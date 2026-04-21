"""
traffic/simulator.py
Blast Radius Demo - Traffic Simulator

Modes:
  external  -- Mac probes VM ports directly (perimeter view)
  internal  -- SSH into vm-app, run nc to vm-db (lateral movement view)
  combined  -- both in one terminal (recommended for live demo)
  nftables  -- SSH into each VM and display CSW firewall rules in a
               readable summary (use before and after enforcement to
               show the customer the rules that were actually pushed)

Usage:
  python3 traffic/simulator.py --config config.yaml --mode combined
  python3 traffic/simulator.py --config config.yaml --mode nftables
  python3 traffic/simulator.py --config config.yaml --mode external
  python3 traffic/simulator.py --config config.yaml --mode internal
"""

import argparse
import os
import socket
import subprocess
import sys
import time

TOOL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if TOOL_DIR not in sys.path:
    sys.path.insert(0, TOOL_DIR)


# ── Config loader ─────────────────────────────────────────────────────────────

def _load_config(config_path):
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f)
    except ImportError:
        pass
    return _parse_yaml(config_path)


def _coerce(val):
    val = str(val).strip().strip('"').strip("'")
    if val in ("true", "True"):  return True
    if val in ("false", "False"): return False
    try: return int(val)
    except: return val


def _parse_yaml(path):
    config = {}
    current_section = None
    current_subsection = None
    vm_list = []
    current_vm = None

    with open(path) as f:
        lines = f.readlines()

    for raw in lines:
        line    = raw.rstrip()
        content = line.lstrip()
        if not content or content.startswith("#"):
            continue
        indent = len(line) - len(content)

        if indent == 0:
            if current_vm is not None:
                vm_list.append(current_vm)
                current_vm = None
            if ":" in content:
                key, _, val = content.partition(":")
                key = key.strip(); val = val.strip()
                config[key] = _coerce(val) if val else {}
                current_section = key
                current_subsection = None

        elif indent == 2:
            if content.startswith("- "):
                if current_section == "vms":
                    if current_vm is not None:
                        vm_list.append(current_vm)
                    current_vm = {}
                    rest = content[2:].strip()
                    if ":" in rest:
                        k, _, v = rest.partition(":")
                        current_vm[k.strip()] = _coerce(v.strip())
                elif current_section and current_subsection:
                    val = content[2:].strip()
                    lst = config.get(current_section, {}).get(current_subsection)
                    if isinstance(lst, list):
                        lst.append(_coerce(val))
            elif ":" in content:
                key, _, val = content.partition(":")
                key = key.strip(); val = val.strip()
                if isinstance(config.get(current_section), dict):
                    if val == "":
                        config[current_section][key] = []
                        current_subsection = key
                    else:
                        config[current_section][key] = _coerce(val)
                        current_subsection = None

        elif indent == 4:
            if content.startswith("- "):
                val = content[2:].strip()
                if current_section and current_subsection:
                    lst = config.get(current_section, {}).get(current_subsection)
                    if isinstance(lst, list):
                        lst.append(_coerce(val))
            elif ":" in content and current_vm is not None:
                key, _, val = content.partition(":")
                current_vm[key.strip()] = _coerce(val.strip())

    if current_vm is not None:
        vm_list.append(current_vm)
    if vm_list:
        config["vms"] = vm_list
    return config


# ── SSH helpers ───────────────────────────────────────────────────────────────

def _ssh_opts(key_path, timeout):
    return [
        "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=ERROR",   # suppresses "Permanently added" warnings
    ]


def _get_ssh_user(vm, config):
    """
    Resolve SSH user for a VM.
    Priority: vm-level ssh_user > config.ssh.user > 'beghorra'
    Never falls back to root.
    """
    return (
        vm.get("ssh_user")
        or config.get("ssh", {}).get("user")
        or "beghorra"
    )


# ── Terminal colours ──────────────────────────────────────────────────────────

GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[1;36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def _ok(msg):   return f"{GREEN}[OPEN  ]{RESET}  {msg}"
def _fail(msg): return f"{RED}[BLOCK ]{RESET}  {msg}"
def _info(msg): return f"{YELLOW}{msg}{RESET}"


# ── External mode ─────────────────────────────────────────────────────────────

def _probe_external(ip, port, timeout=1.5):
    """TCP connect from this Mac to the target IP:port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, "CONNECTED"
    except ConnectionRefusedError:
        return False, "REFUSED   (port closed or agent blocking)"
    except socket.timeout:
        return False, "TIMEOUT   (agent dropping packets)"
    except OSError as e:
        return False, f"ERROR     ({e})"


def run_external(config, target_ip=None):
    """Probe VM ports from this Mac. Perimeter / external attacker view.

    Expected labels reflect the actual policy:
      mgmt_port (TCP/22)  -- ALLOWED  (management SSH policy covers this Mac)
      everything else     -- BLOCK    (Mac has no other allow policy)
    Note: allowed_port (TCP/5432) is NOT allowed from Mac -- only from app VM.
    """
    vms          = config["vms"]
    probe_ports  = config["demo"].get("probe_ports", [22, 80, 5432, 3306])
    interval     = config["demo"].get("traffic_interval", 5)
    allowed_port = config["demo"]["allowed_port"]
    mgmt_port    = config["demo"].get("mgmt_port", 22)

    if target_ip:
        vms = [vm for vm in vms if vm["ip"] == target_ip]

    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  MODE: EXTERNAL (probing from your Mac){RESET}")
    print(f"{CYAN}  Story: Outside attacker scanning the network{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  Targets   : {[vm['ip'] for vm in vms]}")
    print(f"  Ports     : {probe_ports}")
    print(f"  Interval  : {interval}s")
    print(f"  Mac policy: TCP/{mgmt_port} ALLOWED (SSH) | all others BLOCK")
    print(f"  Note      : TCP/{allowed_port} is only allowed from the app VM, not from Mac")
    print(f"  Press Ctrl+C to stop.\n")

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"{BOLD}[{time.strftime('%H:%M:%S')}] Round {iteration} -- External{RESET}")
            for vm in vms:
                print(f"  Mac --> {vm['hostname']} ({vm['ip']})")
                for port in probe_ports:
                    expected = "ALLOWED" if port == mgmt_port else "BLOCK"
                    success, msg = _probe_external(vm["ip"], port)
                    result = _ok(msg) if success else _fail(msg)
                    print(f"    TCP/{port:<5}  {result}  [{expected}]")
            print()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nSimulator stopped.")


# ── SSH gate ──────────────────────────────────────────────────────────────────

def _check_ssh(vm, key_path, ssh_timeout, config):
    """
    Verify SSH is reachable before running probes or nftables.
    Returns (ok, message).
    """
    user = _get_ssh_user(vm, config)
    cmd  = ["ssh"] + _ssh_opts(key_path, ssh_timeout) + [
        f"{user}@{vm['ip']}", "echo SSH_OK"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=ssh_timeout + 2)
        if "SSH_OK" in result.stdout:
            return True, f"SSH connected as {user}@{vm['ip']}"
        return False, f"SSH failed: {result.stderr.strip()[:100]}"
    except subprocess.TimeoutExpired:
        return False, f"SSH timed out connecting to {vm['ip']}"
    except Exception as e:
        return False, f"SSH error: {e}"


# ── Internal mode ─────────────────────────────────────────────────────────────

def _probe_internal(source_vm, target_vm, port, key_path, ssh_timeout, config):
    """
    SSH into source_vm and run nc to target_vm:port from there.
    Uses separate stdout/stderr capture so SSH warnings do not
    contaminate the nc output and cause false UNKNOWN results.
    """
    user      = _get_ssh_user(source_vm, config)
    target_ip = target_vm["ip"]

    # nc exit code 0 = connected, non-zero = failed
    # -z: scan only, -w2: 2 second timeout, no -v to avoid verbose output
    # All output redirected to /dev/null -- we only care about the exit code
    # NC_SUCCESS / NC_FAILED printed to stdout cleanly after nc finishes
    nc_cmd = (
        f"if nc -z -w2 {target_ip} {port} >/dev/null 2>&1; "
        f"then echo NC_SUCCESS; "
        f"else echo NC_FAILED; "
        f"fi"
    )

    cmd = ["ssh"] + _ssh_opts(key_path, ssh_timeout) + [
        f"{user}@{source_vm['ip']}", nc_cmd
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=ssh_timeout + 5)
        # Only read stdout now -- stderr has SSH warnings which we ignore
        stdout = result.stdout.strip()
        if "NC_SUCCESS" in stdout:
            return True, f"CONNECTED (from {source_vm['hostname']} as {user})"
        elif "NC_FAILED" in stdout:
            return False, "REFUSED   (port closed or CSW agent blocking)"
        elif result.returncode != 0 and not stdout:
            return False, f"SSH ERROR (rc={result.returncode})"
        else:
            return False, f"UNKNOWN   (stdout={stdout[:40]})"
    except subprocess.TimeoutExpired:
        return False, f"SSH TIMEOUT (cannot reach {source_vm['hostname']})"
    except Exception as e:
        return False, f"SSH ERROR ({e})"


def run_internal(config):
    """
    SSH into vm-app and probe vm-db from there.
    The real blast radius story -- compromised workload trying to pivot.
    """
    vms = config["vms"]

    source_vm = next((vm for vm in vms if vm.get("role") == "app"), None)
    target_vm = next((vm for vm in vms if vm.get("role") == "db"),  None)

    if not source_vm or not target_vm:
        print("ERROR: Need one VM with role=app and one with role=db in config.yaml")
        return

    key_path     = os.path.expanduser(config["ssh"]["key_path"])
    ssh_timeout  = config["ssh"].get("connect_timeout", 10)
    probe_ports  = config["demo"].get("probe_ports", [22, 80, 5432, 3306])
    interval     = config["demo"].get("traffic_interval", 5)
    allowed_port = config["demo"]["allowed_port"]
    user         = _get_ssh_user(source_vm, config)

    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  MODE: INTERNAL (lateral movement simulation){RESET}")
    print(f"{CYAN}  Story: Compromised {source_vm['hostname']} pivoting to {target_vm['hostname']}{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  SSH user: {user}")
    print(f"  Source  : {source_vm['hostname']} ({source_vm['ip']})  <-- attacker foothold")
    print(f"  Target  : {target_vm['hostname']} ({target_vm['ip']})  <-- blast radius target")
    print(f"  Ports   : {probe_ports}")
    print(f"  Interval: {interval}s   |   Allowed after enforcement: TCP/{allowed_port}")
    print(f"  {_info('Before enforcement: all ports open -- blast radius is unlimited')}")
    print(f"  {_info('After enforcement:  CSW blocks at vm-db host firewall -- lateral movement stopped')}")
    print(f"  Press Ctrl+C to stop.\n")

    # Gate: confirm SSH works before starting the loop
    print(f"  Checking SSH connectivity...")
    ok, msg = _check_ssh(source_vm, key_path, ssh_timeout, config)
    if ok:
        print(f"  {GREEN}{msg}{RESET}\n")
    else:
        print(f"  {RED}SSH FAILED: {msg}{RESET}")
        print(f"  Run: eval \"$(ssh-agent -s)\" && ssh-add ~/.ssh/csw_lab_key")
        return

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"{BOLD}[{time.strftime('%H:%M:%S')}] Round {iteration} -- {source_vm['hostname']} -> {target_vm['hostname']}{RESET}")
            for port in probe_ports:
                expected = "ALLOWED" if port == allowed_port else "BLOCK"
                success, msg = _probe_internal(
                    source_vm, target_vm, port, key_path, ssh_timeout, config
                )
                result = _ok(msg) if success else _fail(msg)
                print(f"  TCP/{port:<5}  {result}  [{expected}]")
            print()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nSimulator stopped.")


# ── Combined mode ─────────────────────────────────────────────────────────────

def run_combined(config):
    """Both external and internal in one terminal. Recommended for live demo."""
    vms = config["vms"]

    source_vm = next((vm for vm in vms if vm.get("role") == "app"), None)
    target_vm = next((vm for vm in vms if vm.get("role") == "db"),  None)

    if not source_vm or not target_vm:
        print("ERROR: Need one VM with role=app and one with role=db in config.yaml")
        return

    key_path     = os.path.expanduser(config["ssh"]["key_path"])
    ssh_timeout  = config["ssh"].get("connect_timeout", 10)
    probe_ports  = config["demo"].get("probe_ports", [22, 80, 5432, 3306])
    interval     = config["demo"].get("traffic_interval", 5)
    allowed_port = config["demo"]["allowed_port"]
    mgmt_port    = config["demo"].get("mgmt_port", 22)
    user         = _get_ssh_user(source_vm, config)

    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  MODE: COMBINED (external + internal){RESET}")
    print(f"{CYAN}  Story: Full blast radius picture{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  SSH user  : {user}")
    print(f"  External  : Mac --> {target_vm['hostname']} ({target_vm['ip']})")
    print(f"  Internal  : {source_vm['hostname']} --> {target_vm['hostname']} (lateral movement)")
    print(f"  Ports     : {probe_ports}")
    print(f"  Interval  : {interval}s   |   Allowed after enforcement: TCP/{allowed_port}")
    print(f"  Press Ctrl+C to stop.\n")

    # Gate: confirm SSH works before starting the loop
    print(f"  Checking SSH connectivity to {source_vm['hostname']}...")
    ok, msg = _check_ssh(source_vm, key_path, ssh_timeout, config)
    if ok:
        print(f"  {GREEN}{msg}{RESET}\n")
    else:
        print(f"  {RED}SSH FAILED: {msg}{RESET}")
        print(f"  Run: eval \"$(ssh-agent -s)\" && ssh-add ~/.ssh/csw_lab_key")
        print(f"  External mode will still work. Starting external-only...\n")

    iteration = 0
    try:
        while True:
            iteration += 1
            ts = time.strftime("%H:%M:%S")

            print(f"{BOLD}[{ts}] Round {iteration} -- External (Mac -> {target_vm['hostname']}){RESET}")
            for port in probe_ports:
                expected = "ALLOWED" if port == mgmt_port else "BLOCK"
                success, msg = _probe_external(target_vm["ip"], port)
                result = _ok(msg) if success else _fail(msg)
                print(f"  TCP/{port:<5}  {result}  [{expected}]")
            print()

            print(f"{BOLD}[{ts}] Round {iteration} -- Internal ({source_vm['hostname']} -> {target_vm['hostname']}){RESET}")
            for port in probe_ports:
                expected = "ALLOWED" if port == allowed_port else "BLOCK"
                success, msg = _probe_internal(
                    source_vm, target_vm, port, key_path, ssh_timeout, config
                )
                result = _ok(msg) if success else _fail(msg)
                print(f"  TCP/{port:<5}  {result}  [{expected}]")
            print()

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nSimulator stopped.")


# ── NFTables mode -- show CSW firewall rules on each VM ───────────────────────

def _get_nftables(vm, key_path, ssh_timeout, config):
    """
    SSH into a VM and return current firewall rules.
    CSW on Ubuntu uses iptables, not nftables in older kernel versions.
    We try nft first (CSW tet table), then iptables as fallback.
    Uses sudo -n (non-interactive) since beghorra has NOPASSWD configured.
    """
    user = _get_ssh_user(vm, config)

    # Try nft (CSW table 'tet'), then iptables, then nft full ruleset
    # sudo -n: non-interactive, fails immediately if password needed
    fw_cmd = (
        "if sudo -n nft list table ip tet 2>/dev/null | grep -q chain; then "
        "  echo '=== NFT TABLE: tet ==='; sudo -n nft list table ip tet 2>/dev/null; "
        "elif sudo -n nft list table inet tet 2>/dev/null | grep -q chain; then "
        "  echo '=== NFT TABLE: inet tet ==='; sudo -n nft list table inet tet 2>/dev/null; "
        "elif sudo -n iptables -L -n --line-numbers 2>/dev/null | grep -q Chain; then "
        "  echo '=== IPTABLES ==='; sudo -n iptables -L -n --line-numbers 2>/dev/null; "
        "elif sudo -n nft list ruleset 2>/dev/null | grep -q table; then "
        "  echo '=== NFT FULL RULESET ==='; sudo -n nft list ruleset 2>/dev/null; "
        "else "
        "  echo NO_FW_OUTPUT; "
        "fi"
    )

    cmd = ["ssh"] + _ssh_opts(key_path, ssh_timeout) + [
        f"{user}@{vm['ip']}", fw_cmd
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=ssh_timeout + 10)
        output = result.stdout.strip()
        if not output or "NO_FW_OUTPUT" in output:
            return None, (
                "No firewall rules found.\n"
                "  Either enforcement is not active, or sudo access is needed.\n"
                "  Check: sudo -n nft list ruleset  OR  sudo -n iptables -L -n"
            )
        return output, None
    except subprocess.TimeoutExpired:
        return None, f"SSH timeout reaching {vm['hostname']}"
    except Exception as e:
        return None, f"SSH error: {e}"


def _summarise_nftables(raw_output, vm, allowed_port):
    """
    Parse nftables output and produce a clean, human-readable summary.
    Highlights allow rules, deny rules, and the CSW catch-all.
    """
    lines = raw_output.splitlines()
    allows  = []
    denies  = []
    catchall = None
    rule_count = 0

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("table") or stripped.startswith("chain") or stripped in ("{", "}"):
            continue

        rule_count += 1
        lower = stripped.lower()

        if "accept" in lower or "allow" in lower:
            allows.append(stripped)
        elif "drop" in lower or "reject" in lower:
            if "default" in lower or len(stripped) < 20:
                catchall = stripped
            else:
                denies.append(stripped)

    return {
        "total_rules": rule_count,
        "allows"     : allows,
        "denies"     : denies,
        "catchall"   : catchall,
    }


def run_nftables(config):
    """
    SSH into each VM and display CSW nftables rules in a readable summary.
    Run this before and after enforcement to show the customer what changed.

    Before enforcement: minimal or no rules, catch-all allow
    After enforcement:  explicit rules pushed by CSW, catch-all deny
    """
    vms         = config["vms"]
    key_path    = os.path.expanduser(config["ssh"]["key_path"])
    ssh_timeout = config["ssh"].get("connect_timeout", 10)
    allowed_port = config["demo"]["allowed_port"]

    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  NFTables Firewall Rules -- CSW Enforcement View{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  This shows what CSW has actually written to each VM.")
    print(f"  Run before enforcement: no CSW rules yet.")
    print(f"  Run after enforcement:  see the policy pushed to the host.")
    print()

    for vm in vms:
        user = _get_ssh_user(vm, config)
        print(f"{BOLD}  [{vm['hostname']} / {vm['ip']}]  (SSH user: {user}){RESET}")
        print(f"  {'-' * 54}")

        # Gate: confirm SSH before attempting firewall read
        ok, ssh_msg = _check_ssh(vm, key_path, ssh_timeout, config)
        if not ok:
            print(f"  {RED}SSH FAILED: {ssh_msg}{RESET}")
            print(f"  Run: eval \"$(ssh-agent -s)\" && ssh-add ~/.ssh/csw_lab_key")
            print()
            continue

        print(f"  {GREEN}SSH OK{RESET}")
        raw, err = _get_nftables(vm, key_path, ssh_timeout, config)

        if err:
            print(f"  {RED}{err}{RESET}")
            print()
            continue

        summary = _summarise_nftables(raw, vm, allowed_port)

        print(f"  Total rules : {summary['total_rules']}")
        print()

        if summary["allows"]:
            print(f"  {GREEN}ALLOW rules:{RESET}")
            for rule in summary["allows"]:
                print(f"    {GREEN}+{RESET} {rule}")
        else:
            print(f"  {YELLOW}No explicit ALLOW rules found{RESET}")

        print()

        if summary["denies"]:
            print(f"  {RED}DENY rules:{RESET}")
            for rule in summary["denies"]:
                print(f"    {RED}-{RESET} {rule}")

        if summary["catchall"]:
            print(f"  {RED}Catch-all : {summary['catchall']}{RESET}")
        else:
            print(f"  {YELLOW}No catch-all rule found (enforcement may not be active){RESET}")

        print()
        print(f"  Full ruleset:")
        for line in raw.splitlines():
            print(f"    {line}")
        print()

    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  TIP: Run this before enforcement to show the open state.")
    print(f"       Run again after enforcement to show rules pushed by CSW.")
    print(f"{CYAN}{'=' * 60}{RESET}\n")


# ── Entry points ──────────────────────────────────────────────────────────────

def run_loop(config, target_ip=None, mode="combined"):
    """Called by menu.py."""
    if mode == "internal":
        run_internal(config)
    elif mode == "combined":
        run_combined(config)
    elif mode == "nftables":
        run_nftables(config)
    else:
        run_external(config, target_ip=target_ip)


def main():
    parser = argparse.ArgumentParser(
        description="CSW Blast Radius Demo - Traffic Simulator"
    )
    parser.add_argument(
        "--config",
        default=os.path.join(TOOL_DIR, "config.yaml"),
        help="Path to config.yaml"
    )
    parser.add_argument(
        "--mode",
        choices=["external", "internal", "combined", "nftables"],
        default="combined",
        help=(
            "external : probe from Mac | "
            "internal : SSH into vm-app then nc to vm-db | "
            "combined : both perspectives | "
            "nftables : show CSW firewall rules on each VM"
        )
    )
    parser.add_argument(
        "--target",
        default=None,
        help="External mode only: probe just this VM IP"
    )
    args = parser.parse_args()

    config = _load_config(args.config)
    run_loop(config, target_ip=args.target, mode=args.mode)


if __name__ == "__main__":
    main()
