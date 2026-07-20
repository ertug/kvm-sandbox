"""Integration tests for kvm-sandbox, run against the real host.

These run the actual script, which calls sudo, downloads the cloud image (cached
after the first run), creates a real VM on the configured bridge, waits for it
to come up over SSH, and deletes it.  They are meant to be run manually on a
host already set up per the README (bridge, nftables rules, libvirt/KVM stack,
SSH key).

Run from the repo root:

    python3 -m unittest discover -s tests -v

Notes:
- Expect sudo prompts, and a VM password prompt unless `password` is set in
  sandbox_config.py (needed to install nmap in the guest and to run the
  containment check).
- The lifecycle test uses the VM name sandbox253-inttest; its IP must be free
  on your subnet.
- The full run can take a few minutes: image download on the first run, then VM
  boot + cloud-init.

"""

import ipaddress
import os
import subprocess
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "kvm-sandbox")
sys.path.insert(0, REPO)
import sandbox_config as config  # noqa: E402

VM_NAME = "sandbox253-inttest"
VM_NUM = 253  # the <n> in VM_NAME
SSH_WAIT_SECONDS = 60
PASSWORD_ENV_VAR = "KVM_SANDBOX_PASSWORD"
TEST_PASSWORD = "inttest-password"

_iface = ipaddress.ip_interface(config.host_address)
SUBNET = _iface.network
GATEWAY = _iface.ip
VM_IP = str(SUBNET[VM_NUM])


def run_script(*args, input=None, capture=False):
    """Run the real script. With capture=False, output (and sudo/password
    prompts) go straight to the terminal."""
    return subprocess.run([sys.executable, SCRIPT, *args], input=input,
                          capture_output=capture, text=True)


def sudo_file_exists(path):
    # image_dir may not be readable by the test user; ask via sudo.
    return subprocess.run(["sudo", "test", "-e", path]).returncode == 0


def virsh_vms():
    r = subprocess.run(["sudo", "virsh", "list", "--all", "--name"],
                       capture_output=True, text=True, check=True)
    return r.stdout.split()


class QuickValidationTest(unittest.TestCase):
    """Fast checks that exit before touching sudo or the system."""

    def test_rejects_invalid_names(self):
        for name in ("foo", "sandbox", "sandbox0", "sandbox5-",
                     "sandbox5--x", "Sandbox5"):
            with self.subTest(name=name):
                r = run_script("create", name, capture=True)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("must be 'sandbox<n>'", r.stderr)

    def test_rejects_gateway_number(self):
        n = int(str(GATEWAY).rsplit(".", 1)[-1])
        r = run_script("create", f"sandbox{n}", capture=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("gateway", r.stderr)

    def test_rejects_out_of_range_number(self):
        n = SUBNET.num_addresses - 1
        r = run_script("create", f"sandbox{n}", capture=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("out of range for", r.stderr)

    def test_rejects_missing_provision_executable(self):
        r = run_script("create", "sandbox250", "--provision",
                       "/nonexistent/provision", capture=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("--provision", r.stderr)

    def test_delete_nonexistent_vm_fails(self):
        # Name chosen to be absent; bail out if it isn't.
        if VM_NAME in virsh_vms():
            self.skipTest(f"{VM_NAME} exists; delete it first")
        r = run_script("delete", VM_NAME, input="y\n", capture=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f"No VM named '{VM_NAME}'", r.stderr)


class VmLifecycleTest(unittest.TestCase):
    """Create a real VM, verify it boots and answers SSH, delete it."""

    def cleanup_vm(self):
        # Best effort; a passing test already deleted the VM.
        subprocess.run([sys.executable, SCRIPT, "delete", VM_NAME],
                       input="y\n", capture_output=True, text=True)

    def set_password_env(self):
        # Export a fixed password via the env var to never hit an interactive
        # prompt. Cleared on exit so this test doesn't leak state into others.
        os.environ[PASSWORD_ENV_VAR] = TEST_PASSWORD
        self.addCleanup(os.environ.pop, PASSWORD_ENV_VAR, None)
        return TEST_PASSWORD

    def test_lifecycle(self):
        disk = os.path.join(config.image_dir, f"{VM_NAME}.qcow2")
        seed = os.path.join(config.image_dir, f"{VM_NAME}-seed.iso")

        if VM_NAME in virsh_vms():
            self.fail(f"{VM_NAME} already exists; delete it first: "
                      f"{SCRIPT} delete {VM_NAME}")

        self.set_password_env()

        # --provision executable that leaves a marker proving it ran, and as whom.
        provision = tempfile.NamedTemporaryFile(
            mode="w", suffix=".sh", delete=False)
        self.addCleanup(os.unlink, provision.name)
        with provision:
            provision.write("#!/bin/sh\n"
                        "echo \"provision-ran-as-$(id -un)\" > /provision-marker\n"
                        "chmod 644 /provision-marker\n")

        # --- create ---
        print(f"[TEST] Creating {VM_NAME}...", flush=True)
        self.addCleanup(self.cleanup_vm)
        r = run_script("create", VM_NAME,
                       "--memory", "1024", "--vcpus", "1", "--disk", "5G",
                       "--provision", provision.name)
        self.assertEqual(r.returncode, 0, "create failed; see output above")

        self.assertTrue(sudo_file_exists(disk), f"missing disk {disk}")
        # create returns only after hot-unplugging and deleting the seed ISO.
        self.assertFalse(sudo_file_exists(seed), f"seed left behind: {seed}")

        state = subprocess.run(["sudo", "virsh", "domstate", VM_NAME],
                               capture_output=True, text=True)
        self.assertEqual(state.stdout.strip(), "running")

        # A second create with the same name must be refused (before the
        # password prompt, so this is safe to run captured).
        r = run_script("create", VM_NAME, capture=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("already exists", r.stderr)

        # A different name with the same host number maps to the same IP
        # and must be refused too.
        r = run_script("create", f"sandbox{VM_NUM}-other", capture=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f"the same IP {VM_IP}", r.stderr)

        # --- wait for cloud-init + SSH, then verify the guest ---
        print(f"[TEST] Waiting up to {SSH_WAIT_SECONDS}s for SSH at "
              f"{config.user}@{VM_IP}...", flush=True)
        hostname = self.wait_for_ssh("hostname")
        self.assertEqual(hostname, VM_NAME)

        # Static network config: the default route must be the gateway.
        route = self.ssh("ip route show default")
        self.assertIn(f"via {GATEWAY}", route)

        # --provision: wait for cloud-init to finish first boot (runcmd may still
        # be running when SSH comes up), then verify the marker it left.
        marker = self.ssh("cloud-init status --wait > /dev/null; "
                          "cat /provision-marker")
        self.assertEqual(marker, "provision-ran-as-root")

        # The seed was hot-unplugged (only the root disk remains) and
        # cloud-init is disabled for later boots.
        self.assertEqual(self.ssh("lsblk -dno NAME"), "vda")
        self.ssh("test -e /etc/cloud/cloud-init.disabled")

        # --- check ---
        print(f"[TEST] Running the containment check against {VM_NAME}...", flush=True)
        r = run_script("check", VM_NAME, "--install-tools", capture=True)
        self.assertEqual(r.returncode, 0,
                         f"containment check failed:\n{r.stdout}\n{r.stderr}")
        self.assertIn(f"Containment check PASSED for '{VM_NAME}'.", r.stdout)
        self.assertIn("Internet reachable:", r.stdout)

        # --- delete ---
        print(f"[TEST] Deleting {VM_NAME}...", flush=True)
        r = run_script("delete", VM_NAME, input="y\n")
        self.assertEqual(r.returncode, 0, "delete failed; see output above")
        self.assertNotIn(VM_NAME, virsh_vms())
        self.assertFalse(sudo_file_exists(disk), f"disk left behind: {disk}")
        self.assertFalse(sudo_file_exists(seed), f"seed left behind: {seed}")

    def ssh(self, command, input=None):
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=5",
             f"{config.user}@{VM_IP}", command],
            input=input, capture_output=True, text=True)
        if r.returncode != 0:
            self.fail(f"ssh '{command}' failed: {r.stderr.strip()}")
        return r.stdout.strip()

    def wait_for_ssh(self, command):
        # Retries cover both the boot window and the gap where sshd is up
        # before cloud-init has created the user.
        deadline = time.monotonic() + SSH_WAIT_SECONDS
        while True:
            r = subprocess.run(
                ["ssh", "-o", "BatchMode=yes",
                 "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "ConnectTimeout=5",
                 f"{config.user}@{VM_IP}", command],
                capture_output=True, text=True)
            if r.returncode == 0:
                return r.stdout.strip()
            if time.monotonic() > deadline:
                self.fail(f"SSH to {VM_IP} not up after {SSH_WAIT_SECONDS}s; "
                          f"last error: {r.stderr.strip()}")
            time.sleep(5)


if __name__ == "__main__":
    unittest.main()
