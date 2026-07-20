import getpass
import ipaddress
import os
import re
import subprocess
import sys
from typing import NoReturn


def log(msg):
    print(f"==> {msg}", flush=True)


def die(msg, code=1) -> NoReturn:
    print(f"ERROR: {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def capture(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


PASSWORD_ENV_VAR = "KVM_SANDBOX_PASSWORD"


def resolve_password(config, what="VM password", confirm=True):
    env_pw = os.environ.get(PASSWORD_ENV_VAR)
    if env_pw is not None:
        if not env_pw.strip():
            die(f"{PASSWORD_ENV_VAR} must be a non-empty string.")
        log(f"Using the {what} from ${PASSWORD_ENV_VAR}.")
        return env_pw

    pw = getattr(config, "password", None)
    if pw is not None:
        if not str(pw).strip():
            die("password in sandbox_config.py must be a non-empty string, or "
                "None to be prompted for it.")
        log(f"Using the {what} from sandbox_config.py.")
        return pw

    return prompt_password(what, confirm=confirm)


def prompt_password(what="VM password", confirm=True):
    while True:
        pw = getpass.getpass(f"{what}: ")
        if not pw.strip():
            print("Password must not be empty.", file=sys.stderr, flush=True)
            continue
        if confirm and pw != getpass.getpass(f"Confirm {what}: "):
            print("Passwords do not match; try again.", file=sys.stderr, flush=True)
            continue
        return pw


# Label is one or more hyphen-separated alphanumeric segments, so no doubled
# or trailing hyphens leak into the hostname (an RFC-invalid hostname).
NAME_RE = re.compile(r"^sandbox([1-9][0-9]*)(?:-[A-Za-z0-9]+)*$")


def parse_n(name):
    m = NAME_RE.match(name)
    return int(m.group(1)) if m else None


def validate_name(name):
    n = parse_n(name)
    if n is None:
        die(f"VM name '{name}' must be 'sandbox<n>' or 'sandbox<n>-<label>', "
            f"e.g. sandbox5 or sandbox5-my-project.")
    return n


def resolve_ip(n, subnet, gateway, strict=True):
    if n is None or n >= subnet.num_addresses - 1:
        if strict:
            die(f"VM number {n} is out of range for {subnet}.")
        return None
    addr = subnet[n]
    if addr == gateway:
        if strict:
            die(f"VM number {n} maps to the gateway address ({addr}).")
        return None
    return str(addr)


def resolve_subnet(config):
    try:
        iface = ipaddress.ip_interface(config.host_address)
    except ValueError as e:
        die(f"Invalid host_address {config.host_address!r} in sandbox_config.py: {e}")
    subnet = iface.network
    gateway = iface.ip
    if gateway in (subnet.network_address, subnet.broadcast_address):
        die(f"host_address {config.host_address!r} in sandbox_config.py must "
            f"be a usable host address in its subnet, not the network or "
            f"broadcast address.")
    return subnet, gateway


def require_not_root():
    if os.geteuid() == 0:
        die("Run as your normal user, not root. The script calls sudo itself.")
