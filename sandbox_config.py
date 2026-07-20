# Config for kvm-sandbox.

# Per-VM option defaults (these take a matching --flag):
memory = 1024  # MiB
vcpus = 1
disk = "10G"

# None: autodetect a *.pub in ~/.ssh
ssh_key = None

# login/sudo account created in the guest
user = "user"

# None: prompt interactively. Set to a plaintext string to skip the prompt
# (stored in this file in the clear).
password = None

image_url = (
    "https://cloud.debian.org/images/cloud/trixie/latest/"
    "debian-13-genericcloud-amd64.qcow2"
)

# must describe image_url (osinfo-query os); if your osinfo-db predates 2025
# and lacks debian13, use "debian12"
osinfo = "debian13"

nameservers = ["1.1.1.1", "1.0.0.1"]  # Cloudflare

# start the VM at host boot
autostart = False

# TCP ports the check probes on each target. Any response (open or closed) fails
# the check, so a single port already catches a missing drop rule. It lists
# services likely to be allowlisted or running on the host/LAN.
check_tcp_ports = ("21-23,53,80,111,139,443,445,631,1433,2049,2375-2376,"
                   "3000,3306,3389,5000-5001,5173,5432,5900,5985,6379,6443,"
                   "8000,8006,8080,8443,8888,9000,9090,9100,9200,10250,"
                   "11211,16509,27017")

# UDP ports the check probes on each target.
check_udp_ports = "53,67-69,111,123,137,161,500,514,623,1900,4500,5353,51820"

# Private ranges the check treats as must-be-unreachable: RFC1918, loopback,
# link-local, and CGNAT (Tailscale). Add any other overlay/VPN range you run.
# A copy of PRIVATE_NET in host-setup/nftables/kvm-sandbox.conf.
check_private_nets = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
)

# Host topology. Change these only if your host deviates from the provided
# configs. The bridge and nftables rules must match. host_address is the host's
# bridge address as configured in host-setup/libvirt-net/kvm-sandbox.xml;
# it is the VMs' gateway, and its prefix defines the sandbox subnet.
host_address = "10.248.0.254/24"
bridge = "br-kvm-sandbox"
image_dir = "/var/lib/libvirt/images"
