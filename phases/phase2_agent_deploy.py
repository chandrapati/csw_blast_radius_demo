"""
phases/phase2_agent_deploy.py
=============================
Phase 2 — Deploy CSW enforcement agents to lab VMs over SSH.

Workflow per VM
---------------
1. Verify the VM is reachable over SSH (the agent installer needs sudo).
2. If `tet-sensor` is already installed, skip the VM (idempotent).
3. SCP the tenant-specific installer script to /tmp.
4. SSH and execute the installer with sudo (the script handles dpkg/rpm
   internally and retrieves its certificate from the embedded payload).
5. Once all VMs are processed, poll the CSW Sensors API until each VM's
   IP appears as an active agent — or until `max_wait` seconds elapse.

Operational requirements
------------------------
- `ssh` and `scp` in $PATH (default on macOS / most Linux).
- Private key configured per `config.ssh.key_path`, public half present in
  `~<ssh_user>/.ssh/authorized_keys` on every VM.
- The SSH user must have NOPASSWD sudo on each VM (the installer requires
  sudo and we run it non-interactively).
- An active ssh-agent if the key is encrypted:
    eval "$(ssh-agent -s)" && ssh-add <key_path>
  or, on macOS:
    ssh-add --apple-use-keychain <key_path>

Security note
-------------
We deliberately use:
    StrictHostKeyChecking=no
    UserKnownHostsFile=/dev/null
because lab VMs are commonly destroyed and re-created on the same IP, which
would otherwise pin the operator on host-key warnings. Do NOT reuse this
SSH options profile against production hosts.

API capabilities required
-------------------------
- sensor_management   (read sensor status, agent UUIDs)
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.csw_client import CSWClient


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def _resolve_key(key_path):
    """Expand ~ in the SSH key path."""
    return os.path.expanduser(key_path)


def _ssh_opts(key_path, timeout):
    """Standard SSH option set used by every command in this phase.

    BatchMode=yes -> never prompt for a passphrase or password; fail instead.
    Lab-only host key handling -> see module docstring.
    """
    return [
        "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "BatchMode=yes",
    ]


def _resolve_user(vm, config):
    """Pick the SSH user for a VM: per-VM > config.ssh.user > error."""
    user = vm.get("ssh_user") or config.get("ssh", {}).get("user")
    if not user:
        raise RuntimeError(
            f"No SSH user configured for {vm['hostname']} ({vm['ip']}). "
            "Set ssh.user globally or vms[*].ssh_user per host in config.yaml."
        )
    return user


# ---------------------------------------------------------------------------
# Per-VM checks and installer steps
# ---------------------------------------------------------------------------

def _check_agent_installed(vm, key_path, timeout, config, log):
    """Return True if `tet-sensor` is already installed on the VM.

    Tries dpkg (Debian/Ubuntu) then rpm (RHEL/CentOS/Rocky/Alma). Any
    failure => assume not installed (we'll attempt the install).
    """
    user = _resolve_user(vm, config)
    check_cmd = (
        "if dpkg -l tet-sensor 2>/dev/null | grep -q '^ii'; then echo installed; "
        "elif rpm -q tet-sensor 2>/dev/null | grep -q tet-sensor; then echo installed; "
        "else echo not_installed; fi"
    )
    cmd = ["ssh"] + _ssh_opts(key_path, timeout) + [f"{user}@{vm['ip']}", check_cmd]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        if "installed" in result.stdout:
            return True
    except Exception:
        # Any exception here (network, ssh, sudo) means we can't confirm —
        # safer to attempt an install than skip a misconfigured VM silently.
        pass
    return False


def _check_ssh_reachable(vm, key_path, timeout, config, log):
    """Run `echo reachable` over SSH; return True on success."""
    user = _resolve_user(vm, config)
    cmd  = ["ssh"] + _ssh_opts(key_path, timeout) + [f"{user}@{vm['ip']}", "echo reachable"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        if "reachable" in result.stdout:
            return True
        log(f"    SSH check failed: {result.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        log(f"    SSH connection to {vm['ip']} timed out.")
        return False
    except FileNotFoundError:
        # ssh binary missing — fatal, not a per-VM issue
        raise RuntimeError("ssh binary not found. Please ensure OpenSSH is installed.")


def _copy_installer(vm, installer_path, key_path, timeout, config, log):
    """SCP the tenant installer to /tmp on the VM."""
    user   = _resolve_user(vm, config)
    remote = f"{user}@{vm['ip']}:/tmp/tet_installer.sh"
    cmd    = ["scp"] + _ssh_opts(key_path, timeout) + [installer_path, remote]
    log(f"    Copying installer to {vm['ip']}...")
    # 60s is generous — the installer is ~10-20MB and lab links are usually fast.
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"SCP failed on {vm['ip']}: {result.stderr.strip()}")
    log(f"    Installer copied.")


def _run_installer(vm, key_path, timeout, config, log):
    """Make the installer executable and run it via sudo."""
    user        = _resolve_user(vm, config)
    install_cmd = "chmod +x /tmp/tet_installer.sh && sudo /tmp/tet_installer.sh"
    cmd         = ["ssh"] + _ssh_opts(key_path, timeout) + [f"{user}@{vm['ip']}", install_cmd]
    log(f"    Running installer (this may take 30-60 seconds)...")
    # 180s ceiling — slow VMs (or first-time package installs) can exceed 60s.
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        combined = result.stdout.lower() + result.stderr.lower()
        # The installer exits non-zero when the agent is already there;
        # treat that as a soft success rather than a hard failure.
        if "already installed" in combined or "remove existing" in combined:
            log(f"    Agent already installed on {vm['ip']} -- skipping.")
            return
        raise RuntimeError(
            f"Installer failed on {vm['ip']}:\n"
            f"  stdout: {result.stdout[-500:]}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    log(f"    Installer completed on {vm['ip']}.")


# ---------------------------------------------------------------------------
# Wait for agents to register with the cluster
# ---------------------------------------------------------------------------

def _wait_for_agents(client, vm_ips, log, max_wait=300):
    """Poll the Sensors API until every IP in `vm_ips` is seen as active.

    Args:
        client:   CSWClient
        vm_ips:   list of VM IP strings to wait for
        max_wait: total seconds to wait before giving up

    Returns:
        dict mapping ip -> sensor uuid (only for IPs that registered in time).
    """
    log(f"  Waiting for agents to check in (up to {max_wait}s)...")
    deadline = time.time() + max_wait
    found    = {}

    while time.time() < deadline:
        try:
            sensors = client.get("/openapi/v1/sensors")

            # Normalise CSW's varying response shapes
            if sensors is None:
                sensor_list = []
            elif isinstance(sensors, dict):
                sensor_list = sensors.get("results", sensors.get("data", []))
            elif isinstance(sensors, list):
                sensor_list = sensors
            else:
                sensor_list = []

            for sensor in sensor_list:
                # An agent typically reports multiple interfaces (eth0, lo, ...);
                # match on any interface IP we care about.
                for iface in sensor.get("interfaces", []):
                    ip = iface.get("ip", "")
                    if ip in vm_ips and ip not in found:
                        # "" status occurs briefly during registration —
                        # treat it as success rather than waiting forever.
                        status = sensor.get("status", "")
                        if status in ("active", "registered", ""):
                            found[ip] = sensor.get("uuid", sensor.get("id", "unknown"))
                            log(f"    Agent checked in: {ip} (uuid: {found[ip][:12]}...)")

            if len(found) == len(vm_ips):
                log(f"  All {len(vm_ips)} agents active.")
                return found

        except Exception as e:
            # Transient API errors during polling — keep retrying, don't crash
            log(f"  Poll error (retrying): {e}")

        remaining = int(deadline - time.time())
        log(f"  {len(found)}/{len(vm_ips)} agents seen. Waiting... ({remaining}s remaining)")
        time.sleep(15)

    missing = [ip for ip in vm_ips if ip not in found]
    log(f"  WARNING: Agents not yet visible for: {missing}")
    log(f"  Check Manage > Agents in CSW UI. They may still be registering.")
    return found


# ---------------------------------------------------------------------------
# Per-VM orchestration
# ---------------------------------------------------------------------------

def deploy_vm(vm, config, log):
    """Run the full deploy sequence on a single VM. Skips if already installed."""
    key_path       = _resolve_key(config["ssh"]["key_path"])
    timeout        = config["ssh"].get("connect_timeout", 10)
    installer_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__), "..",
            config.get("agent_installer", "./tetration_installer.sh"),
        )
    )

    # Fail loud and early if the operator forgot to download the installer
    if not os.path.exists(installer_path):
        raise FileNotFoundError(
            f"Installer script not found at: {installer_path}\n"
            f"Download from: Manage > Agents > Installer > Agent Script Installer > Linux"
        )

    log(f"  [{vm['hostname']} / {vm['ip']}]")

    if not _check_ssh_reachable(vm, key_path, timeout, config, log):
        raise RuntimeError(f"Cannot reach {vm['ip']} over SSH. Check key and connectivity.")

    if _check_agent_installed(vm, key_path, timeout, config, log):
        log(f"    Agent already installed on {vm['ip']} -- skipping deployment.")
        return

    _copy_installer(vm, installer_path, key_path, timeout, config, log)
    _run_installer(vm, key_path, timeout, config, log)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(config, log=print, target_vm_ip=None):
    """Public entry point used by the menu orchestrator.

    Args:
        config:        loaded config.yaml
        log:           callable (single string arg) for status messages
        target_vm_ip:  if set, deploy ONLY to this VM IP (used by the
                       interactive menu when the operator picks one host)

    Returns:
        dict with keys: deployed, skipped, failed, agent_uuids
    """
    log("Phase 2: Agent Deployment")
    log("-" * 40)

    vms = config["vms"]
    if target_vm_ip:
        vms = [vm for vm in vms if vm["ip"] == target_vm_ip]
        if not vms:
            raise ValueError(f"No VM with IP {target_vm_ip} found in config.")

    deployed, skipped, failed = [], [], []

    for vm in vms:
        try:
            deploy_vm(vm, config, log)
            deployed.append(vm["ip"])
        except RuntimeError as e:
            # Distinguish "already installed" (soft) from real failures (hard).
            if "already installed" in str(e).lower():
                skipped.append(vm["ip"])
            else:
                log(f"  ERROR on {vm['ip']}: {e}")
                failed.append(vm["ip"])
        except Exception as e:
            log(f"  ERROR on {vm['ip']}: {e}")
            failed.append(vm["ip"])

    # Wait for ALL configured VMs (not just those we deployed this run) so
    # the menu can show an accurate status afterwards.
    all_ips = [vm["ip"] for vm in vms]
    log("")
    client    = CSWClient()
    agent_map = _wait_for_agents(client, all_ips, log)

    log("-" * 40)
    log(f"Phase 2 complete.")
    log(f"  Deployed : {deployed}")
    log(f"  Skipped  : {skipped} (already installed)")
    log(f"  Failed   : {failed}")
    return {
        "deployed"   : deployed,
        "skipped"    : skipped,
        "failed"     : failed,
        "agent_uuids": agent_map,
    }
