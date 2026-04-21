"""
phases/phase2_agent_deploy.py
Phase 2: Deploy CSW enforcement agents to lab VMs over SSH.

Skips VMs where the agent is already installed and running.
Handles None response from sensors API gracefully.

Requirements:
  - ssh and scp in PATH (standard on macOS)
  - SSH key in authorized_keys on each VM
  - beghorra has NOPASSWD sudo on each VM
  - eval "$(ssh-agent -s)" && ssh-add ~/.ssh/csw_lab_key before running
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.csw_client import CSWClient


def _resolve_key(key_path):
    return os.path.expanduser(key_path)


def _ssh_opts(key_path, timeout):
    return [
        "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "BatchMode=yes",
    ]


def _check_agent_installed(vm, key_path, timeout, log):
    """
    Returns True if tet-sensor is already installed and running on the VM.
    Checks both dpkg/rpm and the running process.
    """
    user = vm.get("ssh_user", "root")
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
        pass
    return False


def _check_ssh_reachable(vm, key_path, timeout, log):
    user = vm.get("ssh_user", "root")
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
        raise RuntimeError("ssh binary not found. Please ensure OpenSSH is installed.")


def _copy_installer(vm, installer_path, key_path, timeout, log):
    user   = vm.get("ssh_user", "root")
    remote = f"{user}@{vm['ip']}:/tmp/tet_installer.sh"
    cmd    = ["scp"] + _ssh_opts(key_path, timeout) + [installer_path, remote]
    log(f"    Copying installer to {vm['ip']}...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"SCP failed on {vm['ip']}: {result.stderr.strip()}")
    log(f"    Installer copied.")


def _run_installer(vm, key_path, timeout, log):
    user        = vm.get("ssh_user", "root")
    install_cmd = "chmod +x /tmp/tet_installer.sh && sudo /tmp/tet_installer.sh"
    cmd         = ["ssh"] + _ssh_opts(key_path, timeout) + [f"{user}@{vm['ip']}", install_cmd]
    log(f"    Running installer (this may take 30-60 seconds)...")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if result.returncode != 0:
        combined = result.stdout.lower() + result.stderr.lower()
        if "already installed" in combined or "remove existing" in combined:
            log(f"    Agent already installed on {vm['ip']} -- skipping.")
            return
        raise RuntimeError(
            f"Installer failed on {vm['ip']}:\n"
            f"  stdout: {result.stdout[-500:]}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    log(f"    Installer completed on {vm['ip']}.")


def _wait_for_agents(client, vm_ips, log, max_wait=300):
    """Poll until all VM IPs appear as active agents. Returns ip -> uuid map."""
    log(f"  Waiting for agents to check in (up to {max_wait}s)...")
    deadline = time.time() + max_wait
    found    = {}

    while time.time() < deadline:
        try:
            sensors = client.get("/openapi/v1/sensors")
            if sensors is None:
                sensor_list = []
            elif isinstance(sensors, dict):
                sensor_list = sensors.get("results", sensors.get("data", []))
            elif isinstance(sensors, list):
                sensor_list = sensors
            else:
                sensor_list = []

            for sensor in sensor_list:
                for iface in sensor.get("interfaces", []):
                    ip = iface.get("ip", "")
                    if ip in vm_ips and ip not in found:
                        status = sensor.get("status", "")
                        if status in ("active", "registered", ""):
                            found[ip] = sensor.get("uuid", sensor.get("id", "unknown"))
                            log(f"    Agent checked in: {ip} (uuid: {found[ip][:12]}...)")

            if len(found) == len(vm_ips):
                log(f"  All {len(vm_ips)} agents active.")
                return found

        except Exception as e:
            log(f"  Poll error (retrying): {e}")

        remaining = int(deadline - time.time())
        log(f"  {len(found)}/{len(vm_ips)} agents seen. Waiting... ({remaining}s remaining)")
        time.sleep(15)

    missing = [ip for ip in vm_ips if ip not in found]
    log(f"  WARNING: Agents not yet visible for: {missing}")
    log(f"  Check Manage > Agents in CSW UI. They may still be registering.")
    return found


def deploy_vm(vm, config, log):
    """Deploy agent to a single VM. Skips if already installed."""
    key_path       = _resolve_key(config["ssh"]["key_path"])
    timeout        = config["ssh"].get("connect_timeout", 10)
    installer_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__), "..",
            config.get("agent_installer", "./tetration_installer.sh")
        )
    )

    if not os.path.exists(installer_path):
        raise FileNotFoundError(
            f"Installer script not found at: {installer_path}\n"
            f"Download from: Manage > Agents > Installer > Agent Script Installer > Linux"
        )

    log(f"  [{vm['hostname']} / {vm['ip']}]")

    if not _check_ssh_reachable(vm, key_path, timeout, log):
        raise RuntimeError(f"Cannot reach {vm['ip']} over SSH. Check key and connectivity.")

    # Skip if already installed
    if _check_agent_installed(vm, key_path, timeout, log):
        log(f"    Agent already installed on {vm['ip']} -- skipping deployment.")
        return

    _copy_installer(vm, installer_path, key_path, timeout, log)
    _run_installer(vm, key_path, timeout, log)


def run(config, log=print, target_vm_ip=None):
    """Entry point called by the menu orchestrator."""
    log("Phase 2: Agent Deployment")
    log("-" * 40)

    vms = config["vms"]
    if target_vm_ip:
        vms = [vm for vm in vms if vm["ip"] == target_vm_ip]
        if not vms:
            raise ValueError(f"No VM with IP {target_vm_ip} found in config.")

    deployed = []
    skipped  = []
    failed   = []

    for vm in vms:
        try:
            deploy_vm(vm, config, log)
            deployed.append(vm["ip"])
        except RuntimeError as e:
            if "already installed" in str(e).lower():
                skipped.append(vm["ip"])
            else:
                log(f"  ERROR on {vm['ip']}: {e}")
                failed.append(vm["ip"])
        except Exception as e:
            log(f"  ERROR on {vm['ip']}: {e}")
            failed.append(vm["ip"])

    # Poll for all configured VMs, not just newly deployed ones
    all_ips = [vm["ip"] for vm in vms]
    log("")
    client    = CSWClient()
    agent_map = _wait_for_agents(client, all_ips, log)

    log("-" * 40)
    log(f"Phase 2 complete.")
    log(f"  Deployed : {deployed}")
    log(f"  Skipped  : {skipped} (already installed)")
    log(f"  Failed   : {failed}")
    return {"deployed": deployed, "skipped": skipped, "failed": failed, "agent_uuids": agent_map}
