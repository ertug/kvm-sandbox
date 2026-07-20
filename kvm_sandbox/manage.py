import base64
import ipaddress
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

import sandbox_config as config
from .common import capture, die, log, parse_n, resolve_password


def run(cmd, check=True):
    print(f"  $ {shlex.join(cmd)}", flush=True)
    return subprocess.run(cmd, check=check, text=True).returncode


def sudo_file_exists(path):
    # image_dir might not be traversable by the invoking user, use sudo
    return capture(["sudo", "test", "-e", path]).returncode == 0


def sudo_file_nonempty(path):
    return capture(["sudo", "test", "-s", path]).returncode == 0


def run_umask077(cmd):
    # Runs cmd with umask 077, so any file/dir it creates is 0600/0700 from the
    # first write instead of briefly world-readable.
    run(["sudo", "sh", "-c", f"umask 077 && {shlex.join(cmd)}"])


def hash_password(plaintext):
    # openssl because the stdlib crypt module was removed in Python 3.13.
    r = capture(["openssl", "passwd", "-6", "-stdin"], input=plaintext)
    if r.returncode != 0 or not r.stdout.strip():
        die(f"Failed to hash the VM password with openssl: {r.stderr.strip()}")
    return r.stdout.strip()


def removal_hint(name):
    return f"{sys.argv[0]} delete {name}"


def virsh_list():
    r = capture(["sudo", "virsh", "list", "--all", "--name"])
    if r.returncode != 0:
        die(f"Could not list existing VMs: {r.stderr.strip()}")
    return r.stdout.split()


def check_nftables():
    for family in ("inet", "ip", "bridge"):
        r = capture(["sudo", "nft", "list", "table", family, "kvm_sandbox"])
        if r.returncode != 0:
            die(f"nftables table '{family} kvm_sandbox' not found "
                f"(rules not loaded?). See the README.")
    log("nftables sandbox tables verified.")


def check_ip_forward():
    with open("/proc/sys/net/ipv4/ip_forward") as f:
        if f.read().strip() != "1":
            die("IP forwarding ('net.ipv4.ip_forward') is not enabled. See the README.")
    log("IP forwarding ('net.ipv4.ip_forward') is enabled.")


def check_ssh_key():
    ssh_key = config.ssh_key
    if ssh_key:
        ssh_key = os.path.expanduser(ssh_key)
        if not os.path.exists(ssh_key):
            die(f"ssh_key '{ssh_key}' from sandbox_config.py not found.")
    else:
        for cand in ("id_ed25519.pub", "id_rsa.pub", "id_ecdsa.pub"):
            p = os.path.expanduser(f"~/.ssh/{cand}")
            if os.path.exists(p):
                ssh_key = p
                break
        if not ssh_key:
            die("No SSH public key found in ~/.ssh. Generate one "
                "(ssh-keygen -t ed25519) or set ssh_key in sandbox_config.py.")
    log(f"Using SSH key: {ssh_key}")
    # Exactly one key: a multi-line .pub would otherwise break the YAML list
    # in write_cloud_init.
    with open(ssh_key) as f:
        keys = [ln for ln in f.read().splitlines() if ln.strip()]
    if len(keys) != 1:
        die(f"ssh_key '{ssh_key}' must contain exactly one public key "
            f"(found {len(keys)}).")
    return keys[0]


def check_bridge():
    r = capture(["ip", "-4", "-j", "addr", "show", "dev", config.bridge])
    if r.returncode != 0:
        die(f"Bridge '{config.bridge}' not found. See the README.")
    bridge_addrs = [ipaddress.ip_interface(f"{ai['local']}/{ai['prefixlen']}")
                    for link in json.loads(r.stdout)
                    for ai in link.get("addr_info", [])]
    if ipaddress.ip_interface(config.host_address) not in bridge_addrs:
        die(f"Bridge '{config.bridge}' does not carry host_address "
            f"{config.host_address} from sandbox_config.py (found: "
            f"{', '.join(map(str, bridge_addrs)) or 'no IPv4 address'}).")


def check_prereqs(a):
    # Local, free checks first, so they fail before the first sudo prompt.
    for tool in ("openssl", "curl", "sudo", "ip", "ping", "virt-install",
                 "qemu-img", "xorrisofs"):
        if not shutil.which(tool):
            die(f"Required tool '{tool}' not found. See the README.")

    if a.provision:
        a.provision = os.path.abspath(os.path.expanduser(a.provision))
        if not os.path.isfile(a.provision):
            die(f"--provision executable '{a.provision}' not found.")
        a.provision_name = os.path.basename(a.provision)

    a.pubkey = check_ssh_key()
    check_bridge()
    check_ip_forward()
    check_nftables()

    new_n = parse_n(a.name)
    for name in virsh_list():
        if name == a.name:
            die(f"A VM named '{a.name}' already exists. Pick another name, "
                f"or remove it: {removal_hint(name)}")
        if parse_n(name) == new_n:
            die(f"VM '{name}' already uses the same IP {a.ip}; two names "
                f"sharing <n> map to the same IP. Pick another number, or "
                f"remove it: {removal_hint(name)}")

    if capture(["ping", "-c1", "-W1", a.ip]).returncode == 0:
        die(f"{a.ip} already answers ping; another host is using this IP. "
            f"Pick another number.")

    for path, what in ((a.disk_path, "disk"),
                       (a.seed_iso, "cloud-init seed")):
        if sudo_file_exists(path):
            die(f"A {what} for '{a.name}' already exists at {path}. "
                f"Remove it first: {removal_hint(a.name)}")


def prepare_disk(a):
    if not os.path.isdir(config.image_dir):
        run(["sudo", "mkdir", "-p", config.image_dir])
    base = os.path.join(config.image_dir,
                        f"base-{os.path.basename(config.image_url)}")
    part = base + ".part"
    cached = sudo_file_exists(base)
    if cached:
        log("Checking the mirror for a newer cloud image...")
    else:
        log(f"Downloading cloud image (cached for future VMs): {config.image_url}")
    # Download to a .part file and rename only on success, so the cache never
    # holds a partial or error download. -R + -z make the request conditional on
    # the cached copy's Last-Modified (the default URL is a `latest` symlink); a
    # failed check (e.g. offline) falls back to the cached copy.
    # some mirrors just hang instead of answering; bound the connect and
    # stalled-transfer time so a bad mirror fails fast.
    try:
        rc = run(["sudo", "curl", "-fLR",
                  "--connect-timeout", "10", "--speed-limit", "1", "--speed-time", "30",
                  "-o", part, config.image_url]
                 + (["-z", base] if cached else []), check=False)
        if rc != 0:
            if not cached:
                die(f"Downloading the cloud image failed (curl exit {rc}).")
            log("Mirror unreachable; using the cached image as-is.")
        elif sudo_file_nonempty(part):
            run(["sudo", "mv", part, base])
            if cached:
                log("Cached base image refreshed from the mirror.")
        elif cached:
            # 304 Not Modified: -z suppressed the download, keep the cache.
            log("Cached base image is up to date.")
        else:
            die("curl reported success but downloaded no cloud image "
                f"from {config.image_url}.")
    finally:
        # On success the mv consumed the .part; nothing else must leave one.
        if sudo_file_exists(part):
            run(["sudo", "rm", "-f", part], check=False)
    # A plain file copy keeps the image's qcow2 compression; cloud-init's
    # growpart expands the guest filesystem into the resized disk on boot.
    log(f"Copying base image to {a.disk_path} and resizing to {a.disk}...")
    # The per-VM disk holds the guest's filesystem, so it's created 0600
    run_umask077(["cp", "--reflink=auto", base, a.disk_path])
    run(["sudo", "qemu-img", "resize", "-q", a.disk_path, a.disk])


def write_cloud_init(seed_dir, a):
    # json.dumps wraps the key in a quoted YAML scalar; an OpenSSH comment can
    # contain ": ", which an unquoted scalar would parse as a mapping.
    pubkey = json.dumps(a.pubkey)
    # sudo requires the password (no NOPASSWD), and only the hash is stored,
    # so in-guest code can't read the plaintext out of the cloud-init seed.
    pwhash = hash_password(a.password)
    provision_file = ""
    provision_cmd = ""
    if a.provision:
        # The --provision executable is embedded base64 (binary-safe in YAML);
        # write_files places it before runcmd execs it as root, exactly once
        # (per-instance module + stable instance-id). Its output lands in
        # /var/log/cloud-init-output.log in the guest.
        with open(a.provision, "rb") as f:
            content = base64.b64encode(f.read()).decode("ascii")
        guest_path = json.dumps(f"/root/{a.provision_name}")
        provision_file = (f"  - path: {guest_path}\n"
                          f"    encoding: b64\n"
                          f"    permissions: '0700'\n"
                          f"    content: {content}\n")
        provision_cmd = f"  - [{guest_path}]\n"
    user_data = f"""\
#cloud-config
hostname: {a.name}
users:
  - name: {config.user}
    shell: /bin/bash
    sudo: ALL=(ALL) ALL
    lock_passwd: false
    ssh_authorized_keys:
      - {pubkey}
ssh_pwauth: false
chpasswd:
  expire: false
  users:
    - name: {config.user}
      password: {json.dumps(pwhash)}
      type: hash
write_files:
  - path: /etc/sysctl.d/99-disable-ipv6.conf
    content: |
      net.ipv6.conf.all.disable_ipv6 = 1
      net.ipv6.conf.default.disable_ipv6 = 1
      net.ipv6.conf.lo.disable_ipv6 = 1
{provision_file}\
runcmd:
  - sysctl --system
{provision_cmd}\
  - touch /etc/cloud/cloud-init.disabled
"""
    ns_lines = "\n".join(f"        - {ns}" for ns in config.nameservers)
    network_config = f"""\
version: 2
ethernets:
  primary:
    match:
      macaddress: {a.mac}
    dhcp4: false
    addresses:
      - {a.ip}/{a.subnet.prefixlen}
    routes:
      - to: default
        via: {a.gateway}
    nameservers:
      addresses:
{ns_lines}
"""
    # NoCloud requires meta-data; a stable instance-id makes the per-instance
    # modules (user, password, hostname) run exactly once across reboots.
    meta_data = f"instance-id: {a.name}\nlocal-hostname: {a.name}\n"
    # NoCloud requires exactly these filenames at the cidata root.
    for fname, content in (("user-data", user_data),
                           ("meta-data", meta_data),
                           ("network-config", network_config)):
        path = os.path.join(seed_dir, fname)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, 0o600)


def build_seed_iso(a, seed_dir):
    # virt-install's --cloud-init also stamps an SMBIOS serial of "ds=nocloud"
    # on the VM; recent cloud-init (25.x) then seeds "from dmi" with an empty
    # payload and never reads the attached cidata ISO. Building the
    # cidata-labelled seed ourselves and attaching it as a plain read-only
    # virtio disk sidesteps that: cloud-init discovers it by filesystem label.
    log(f"Building cloud-init seed ISO {a.seed_iso}...")
    # The seed ISO holds the sudo password hash, so it's created 0600
    run_umask077(["xorrisofs", "-output", a.seed_iso, "-volid", "cidata",
                  "-joliet", "-rock", seed_dir])


def virt_install(a):
    log("Creating the VM with virt-install...")
    cmd = [
        "sudo", "virt-install",
        "--name", a.name,
        "--virt-type", "kvm",
        "--osinfo", config.osinfo,
        "--memory", str(a.memory),
        "--vcpus", str(a.vcpus),
        # Mask the virtualization flags so the guest can't run its own
        # hypervisor: nested virt exercises KVM's most complex code paths
        # (a disable policy is a no-op for a flag the host CPU lacks, so
        # listing both vmx and svm works on Intel and AMD).
        "--cpu", "host-model,disable=vmx,disable=svm",
        # Strip the emulated devices a headless dev box never uses (QEMU's
        # device emulation is where most VM escapes have lived). The
        # video-less config requires UEFI: only under OVMF does GRUB
        # fall back to serial (a BIOS boot wedges at GRUB). Secure boot
        # stays off so libvirt picks the OVMF build that doesn't need
        # QEMU's SMM emulation.
        "--boot", ("firmware=efi,firmware.feature0.name=secure-boot,"
                   "firmware.feature0.enabled=no"),
        "--graphics", "none",
        "--video", "none",
        "--sound", "none",
        "--controller", "usb,model=none",
        "--memballoon", "none",
        "--channel", "none",
        # Drop the default TPM 2.0 virt-install adds to UEFI guests;
        # nothing here does measured boot or attestation.
        "--tpm", "none",
        # Guests use kvm-clock; HPET is an unused chipset default.
        "--clock", "hpet_present=no",
        "--console", "pty,target.type=serial",
        "--disk", f"path={a.disk_path},bus=virtio,format=qcow2",
        # Read-only virtio disk rather than an emulated cdrom; cloud-init
        # finds it by its "cidata" volume label. format=raw stops
        # virt-install probing the ISO's format.
        "--disk", f"path={a.seed_iso},bus=virtio,readonly=on,format=raw",
        "--import",
        "--network",
        # Anti-spoofing: clean-traffic pinned to the VM's IP. The parameter
        # is injected via xpath (virt-install has no dedicated
        # filterref.parameter option). network-config matches the MAC.
        (f"bridge={config.bridge},model=virtio,mac={a.mac},"
         f"filterref.filter=clean-traffic,"
         f"xpath1.set=./filterref/parameter/@name,xpath1.value=IP,"
         f"xpath2.set=./filterref/parameter/@value,xpath2.value={a.ip}"),
        "--noautoconsole",
    ]
    run(cmd)
    if config.autostart:
        run(["sudo", "virsh", "autostart", a.name])
    else:
        log("Autostart disabled; the VM will not start at host boot.")


def detach_seed(a):
    log("Waiting for the VM to come up on its IP...")
    deadline = time.time() + 60
    while capture(["ping", "-c1", "-W1", a.ip]).returncode != 0:
        if time.time() > deadline:
            log(f"WARNING: {a.ip} not answering; seed ISO left attached "
                f"({a.seed_iso}).")
            return
        time.sleep(2)
    log("Detaching and deleting the cloud-init seed ISO...")
    if run(["sudo", "virsh", "detach-disk", a.name, a.seed_iso,
            "--persistent"], check=False) != 0:
        log(f"WARNING: detach failed; seed ISO left attached ({a.seed_iso}).")
        return
    run(["sudo", "rm", "-f", a.seed_iso])


def cleanup_failed_create(a):
    # check_prereqs verified none of these existed beforehand. Errors are
    # ignored so cleanup never masks the original failure.
    log("Create failed; removing this run's artifacts...")
    capture(["sudo", "virsh", "destroy", a.name])
    capture(["sudo", "virsh", "undefine", "--nvram", a.name])
    capture(["sudo", "rm", "-f", a.disk_path, a.seed_iso])


def summary(a):
    bar = "=" * 60
    print(f"\n{bar}")
    print(f"Sandbox VM '{a.name}' created at {a.ip} (cloud-init runs on first boot).")
    print(bar)
    print(f"  SSH:            ssh {config.user}@{a.ip}")
    print(f"  Console:        sudo virsh console {a.name}  (serial; exit with Ctrl+])")
    print(f"  Login & sudo:   user '{config.user}' & password you set")
    if a.provision:
        print(f"  Provision:      /root/{a.provision_name} runs as root on "
              f"first boot; log: /var/log/cloud-init-output.log")
    print()


def vm_paths(name):
    return (os.path.join(config.image_dir, f"{name}.qcow2"),
            os.path.join(config.image_dir, f"{name}-seed.iso"))


def vm_mac(ip):
    # Deterministic MAC in QEMU's 52:54:00 OUI from the IP's last three
    # octets: unique per VM for any sandbox subnet of /8 or narrower
    octets = ipaddress.ip_address(ip).packed[-3:]
    return "52:54:00:" + ":".join(f"{b:02x}" for b in octets)


def cmd_create(a):
    a.disk_path, a.seed_iso = vm_paths(a.name)
    a.mac = vm_mac(a.ip)
    check_prereqs(a)
    a.password = resolve_password(config)
    try:
        prepare_disk(a)
        # TemporaryDirectory is created 0700, so the seed files (which hold
        # the sudo password hash) are never visible to other users.
        with tempfile.TemporaryDirectory() as seed_dir:
            write_cloud_init(seed_dir, a)
            build_seed_iso(a, seed_dir)
            virt_install(a)
    except BaseException:
        cleanup_failed_create(a)
        raise
    detach_seed(a)
    summary(a)


def cmd_delete(a):
    a.disk_path, a.seed_iso = vm_paths(a.name)
    exists = a.name in virsh_list()
    # Also clean up leftover files from an earlier undefine without rm.
    leftovers = [path for path in (a.disk_path, a.seed_iso)
                 if sudo_file_exists(path)]
    if not exists and not leftovers:
        die(f"No VM named '{a.name}' and no leftover files for it "
            f"in {config.image_dir}.")
    what = ([f"VM '{a.name}'"] if exists else []) + leftovers
    reply = input(f"Delete {', '.join(what)}? [y/N] ")
    if reply.strip().lower() not in ("y", "yes"):
        die("Aborted; nothing deleted.")
    if exists:
        # destroy fails when the VM isn't running; that's fine.
        capture(["sudo", "virsh", "destroy", a.name])
        # --managed-save: undefine otherwise refuses when a managed save exists
        run(["sudo", "virsh", "undefine", "--nvram", "--managed-save", a.name])
    if leftovers:
        run(["sudo", "rm", "-f"] + leftovers)
    log(f"Sandbox '{a.name}' deleted.")
