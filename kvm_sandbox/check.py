import ipaddress
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET

import sandbox_config as config
from .common import capture, die, log, parse_n, resolve_ip, resolve_password


def private_nets():
    try:
        nets = [ipaddress.ip_network(n) for n in config.check_private_nets]
    except ValueError as e:
        die(f"invalid check_private_nets in sandbox_config.py: {e}")
    if not nets:
        die("check_private_nets in sandbox_config.py must list at least "
            "one network.")
    return nets


def is_probe_target(ip_str, nets):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    is_private = any(addr in net for net in nets)
    return not addr.is_loopback and is_private


def ssh_vm(ip, command, sudo_password=None, stream=False):
    # sudo_password is forwarded on stdin to the remote command
    # (e.g. for a `sudo -S ...` command), not consumed by ssh.
    cmd = ["ssh", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=5",
           f"{config.user}@{ip}", command]
    stdin = None if sudo_password is None else sudo_password + "\n"
    # stream=True: output goes straight to the terminal (for long-running
    # commands like apt-get), so stdout/stderr come back as None.
    if stream:
        r = subprocess.run(cmd, text=True, input=stdin)
    else:
        r = capture(cmd, input=stdin)
    if r.returncode == 255:
        die(f"Cannot SSH to {config.user}@{ip}. The VM may not exist, may not "
            f"be running, may still be finishing cloud-init, or may use a "
            f"different user. Check 'sudo virsh list --all' and wait for SSH "
            f"to come up.\n  ssh error: {(r.stderr or '').strip()}", code=2)
    return r


def die_tool_missing(tool, vm_ip):
    die(f"{tool} is not installed in the VM ({config.user}@{vm_ip}); the check "
        f"runs {tool} from inside the sandbox.\n"
        f"Re-run with --install-tools, or install it there yourself.", code=2)


def sandbox_ips(subnet, gateway):
    r = capture(["sudo", "virsh", "list", "--name"])
    if r.returncode != 0:
        log(f"WARNING: could not list running VMs (virsh exit "
            f"{r.returncode}): {r.stderr.strip()}")
        return []
    return [ip for name in r.stdout.split()
            if (ip := resolve_ip(parse_n(name), subnet, gateway, strict=False))]


def enumerate_targets(vm_ip, subnet, gateway, nets):
    # simply grab all IPs, false positives don't matter
    cmds = [
        ["ip", "-4", "addr"],
        ["ip", "-4", "neigh"],
        ["ip", "-4", "route", "show", "table", "all"],
        ["ss", "-4tn"],
        ["ss", "-4un"],
    ]
    lines = []
    for cmd in cmds:
        try:
            r = capture(cmd)
        except FileNotFoundError as e:
            die(f"'{shlex.join(cmd)}' failed: {e}.", code=2)
        if r.returncode != 0:
            die(f"'{shlex.join(cmd)}' failed (exit {r.returncode}): "
                f"{r.stderr.strip()}.", code=2)
        lines.extend(r.stdout.splitlines())

    lines = [ln for ln in lines if "FAILED" not in ln and "INCOMPLETE" not in ln]
    cands = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "\n".join(lines)))

    # Cloud-metadata service and a common router address, plus a representative
    # IP per private block so ranges the host has no presence in are still probed.
    cands.update(["169.254.169.254", "192.168.1.1"])
    cands.update(str(net[1]) if net.num_addresses > 2 else str(net[0])
                 for net in nets)

    cands.update(sandbox_ips(subnet, gateway))

    unhostable = {str(subnet.network_address), str(subnet.broadcast_address)}

    cands = {c for c in cands
             if c != vm_ip and c not in unhostable and is_probe_target(c, nets)}

    return sorted(cands, key=ipaddress.ip_address)


def _parse_nmap_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    results = []
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        ip = addr.get("addr")
        ports = []
        for port in host.findall("./ports/port"):
            st = port.find("state")
            ports.append((port.get("protocol"), port.get("portid"),
                          st.get("state") if st is not None else None))
        results.append((ip, ports))
    return results


def install_tools(vm_ip, sudo_password):
    log("Installing nmap and curl in the VM...")
    # -p '' suppresses sudo's password prompt, which would otherwise show up
    # in the streamed output.
    r = ssh_vm(vm_ip, "sudo -S -p '' sh -c "
                      "'apt-get update && apt-get install -y nmap curl'",
               sudo_password=sudo_password, stream=True)
    if r.returncode != 0:
        die(f"Failed to install nmap/curl in the VM ({config.user}@{vm_ip}, "
            f"exit {r.returncode}); see output above.", code=2)


def run_remote_nmap(vm_ip, targets, tcp_ports, udp_ports, sudo_password):
    # -Pn skips host discovery, which would just be another redundant connect.
    port_spec = f"T:{tcp_ports},U:{udp_ports}"
    scan = ["sudo", "-S", "nmap", "-n", "-Pn", "-sS", "-sU",
            "-p", port_spec,
            "--max-retries", "1",
            "-T4", "-oX", "-"] + targets
    r = ssh_vm(vm_ip, shlex.join(scan), sudo_password=sudo_password)
    if r.returncode != 0:
        if "not found" in r.stderr.lower():
            die_tool_missing("nmap", vm_ip)
        # includes a wrong sudo password
        die(f"nmap scan failed (exit {r.returncode}): {r.stderr.strip()}",
            code=2)
    scanned = _parse_nmap_xml(r.stdout)
    findings = {}
    scanned_ips = set()
    for ip, ports in scanned:
        scanned_ips.add(ip)
        for proto, port, state in ports:
            if state in ("open", "closed"):
                findings.setdefault(ip, set()).add((proto, port))

    missing = [t for t in targets if t not in scanned_ips]
    missing.sort(key=ipaddress.ip_address)
    if missing:
        log(f"WARNING: nmap reported no result for {len(missing)} "
            f"target(s); their containment is UNVERIFIED: "
            f"{', '.join(missing)}")

    return findings


INTERNET_URL = "https://example.com"


def cmd_check(a):
    name, vm_ip = a.name, a.ip
    nets = private_nets()

    # Connectivity probe before the password prompt
    ssh_vm(vm_ip, "true")

    sudo_password = resolve_password(config, what="VM sudo password", confirm=False)

    # Before the internet check, which needs curl in the guest.
    if a.install_tools:
        install_tools(vm_ip, sudo_password)

    # The check is "internet reachable, private addresses not" — confirm the
    # internet half first, since a dead NIC or no route would make every
    # private target look unreachable too.
    log("Checking that the internet is reachable...")
    r = ssh_vm(vm_ip, f"curl -fsS --max-time 15 -o /dev/null {INTERNET_URL}")
    if r.returncode != 0:
        if "not found" in r.stderr.lower():
            die_tool_missing("curl", vm_ip)
        die(f"Internet unreachable: the VM could not fetch {INTERNET_URL}: "
            f"{r.stderr.strip()}\nThe VM may have no egress, no DNS, or a "
            f"dead network, so a containment result would be meaningless. "
            f"Fix connectivity and re-run.", code=2)
    log("Internet is reachable.")

    targets = enumerate_targets(vm_ip, a.subnet, a.gateway, nets)
    log(f"Enumerated {len(targets)} private target(s) from the host:")
    log(f"  {', '.join(targets)}")

    log("Probing the targets from inside the VM with nmap...")
    findings = run_remote_nmap(vm_ip, targets, config.check_tcp_ports,
                               config.check_udp_ports, sudo_password)

    reachable = [(ip, proto, port)
                 for ip in sorted(findings, key=ipaddress.ip_address)
                 for proto, port in sorted(findings[ip],
                                           key=lambda t: (t[0], int(t[1])))]

    bar = "=" * 60
    label_w = 20
    print(f"\n{bar}")
    print(f"Containment check for '{name}' ({vm_ip})")
    print(bar)
    print(f"  {'Internet reachable:':{label_w}} yes")
    print(f"  {'Targets probed:':{label_w}} {len(targets)}")
    print(f"  {'Reachable services:':{label_w}} {len(reachable)}")
    if reachable:
        ip_w = max(len(ip) for ip, _, _ in reachable)
        print()
        for ip, proto, port in reachable:
            print(f"    {ip:<{ip_w}}  {proto}/{port}")
    print(bar)
    if reachable:
        print(f"{len(reachable)} private service(s) reachable from '{name}'.\n"
              f"NOTE: Expected if allowlisted via private_allow.")
    else:
        print(f"Containment check PASSED for '{name}'.")
    sys.exit(1 if reachable else 0)
