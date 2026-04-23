"""
traffic/simulator.py
====================
Live traffic simulator for the CSW Blast Radius Demo.

Why this script exists
----------------------
The customer needs to SEE the policy land in real time. Watching CSW UI tiles
flip is one piece of the story; watching connections die in a terminal is
the visceral one. This script provides both:

  external  -- TCP connect from THIS host (operator laptop) to each VM port.
               Tells the perimeter / outside-attacker view.
  internal  -- SSH into the `app` role VM, then `nc -z` from there to the
               `db` role VM. Tells the lateral-movement / pivot view —
               exactly what makes the blast radius shrink dramatic.
  combined  -- both perspectives interleaved in one terminal.
  nftables  -- SSH into each VM and dump the firewall table CSW pushes,
               with a parsed allow / deny / catch-all summary.

Usage
-----
    python3 traffic/simulator.py --mode combined          # the recommended demo mode
    python3 traffic/simulator.py --mode external          # outside view only
    python3 traffic/simulator.py --mode internal          # inside view only
    python3 traffic/simulator.py --mode nftables          # show pushed firewall rules
    python3 traffic/simulator.py --mode external --target 10.0.0.15
    python3 traffic/simulator.py --config /path/to/config.yaml --mode combined

Run before AND after Phase 4 enforcement to highlight the change.
"""

import argparse
import os
import socket
import subprocess
import sys
import time

# Add the project root to sys.path so this script works when run directly
# (e.g. `python3 traffic/simulator.py`) AND when imported by `menu.py`.
TOOL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if TOOL_DIR not in sys.path:
    sys.path.insert(0, TOOL_DIR)


# ---------------------------------------------------------------------------
# Config loading (PyYAML if installed, fallback parser otherwise)
# ---------------------------------------------------------------------------

def _load_config(config_path):
    """Prefer PyYAML when available; fall back to the built-in parser."""
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f)
    except ImportError:
        return _parse_yaml(config_path)


def _coerce(val):
    """Convert a YAML scalar string to bool / int / str (in that order)."""
    val = str(val).strip().strip('"').strip("'")
    if val in ("true", "True"):  return True
    if val in ("false", "False"): return False
    try:
        return int(val)
    except (ValueError, TypeError):
        return val


def _parse_yaml(path):
    """Minimal YAML parser sufficient for this project's config shape.

    Limitations (intentional — keep simple):
      - 2-space indentation only
      - Scalars, lists of scalars, lists of dicts (the `vms` block)
      - No multi-line strings, anchors, or merge keys
    """
    config             = {}
    current_section    = None
    current_subsection = None
    vm_list            = []
    current_vm         = None

    with open(path) as f:
        lines = f.readlines()

    for raw in lines:
        line    = raw.rstrip()
        content = line.lstrip()

        # Skip blanks and comments
        if not content or content.startswith("#"):
            continue
        indent = len(line) - len(content)

        # ---- top-level (indent 0) ----
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

        # ---- second level (indent 2) ----
        elif indent == 2:
            if content.startswith("- "):
                # list item — only used by the `vms` block
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
                        # Empty value -> list begins on next indent level
                        config[current_section][key] = []
                        current_subsection = key
                    else:
                        config[current_section][key] = _coerce(val)
                        current_subsection = None

        # ---- third level (indent 4) ----
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


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def _ssh_opts(key_path, timeout):
    """Same option set as the deploy phase, plus LogLevel=ERROR to suppress
    `Permanently added 'host' (ED25519) to the list of known hosts.` noise
    that would otherwise contaminate parsed nc output."""
    return [
        "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=ERROR",
    ]


def _get_ssh_user(vm, config):
    """Resolve SSH user: per-VM > config.ssh.user > raise.

    Never falls back to a baked-in default — silently using a wrong user
    is much worse than failing loudly with a clear error.
    """
    user = vm.get("ssh_user") or config.get("ssh", {}).get("user")
    if not user:
        raise RuntimeError(
            f"No SSH user configured for {vm.get('hostname', vm.get('ip'))}. "
            "Set ssh.user globally or vms[*].ssh_user per host in config.yaml."
        )
    return user


# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------

GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[1;36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def _ok(msg):   return f"{GREEN}[OPEN  ]{RESET}  {msg}"
def _fail(msg): return f"{RED}[BLOCK ]{RESET}  {msg}"
def _info(msg): return f"{YELLOW}{msg}{RESET}"


# ---------------------------------------------------------------------------
# External mode — TCP connect from THIS host
# ---------------------------------------------------------------------------

def _probe_external(ip, port, timeout=1.5):
    """Plain TCP connect from the operator's laptop to ip:port.

    Three failure modes are distinguished because they tell different stories:
      ConnectionRefusedError -> port closed (or CSW REJECT)
      socket.timeout         -> packets dropped silently (CSW DROP)
      OSError                -> network-level error (route, host down, ...)
    """
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
    """Probe VM ports from the operator's laptop. Perimeter / external view.

    After enforcement, only TCP/<mgmt_port> survives from this host because
    the management policy is the only one that allows our IP. Every other
    port becomes BLOCK — the catch-all DENY does its job.

    Note: TCP/<allowed_port> is BLOCK from this host even though it is
    ALLOWED inside the cluster — the policy specifically ALLOWs role=app
    -> role=db, and we are neither.
    """
    vms          = config["vms"]
    probe_ports  = config["demo"].get("probe_ports", [22, 80, 5432, 3306])
    interval     = config["demo"].get("traffic_interval", 5)
    allowed_port = config["demo"]["allowed_port"]
    mgmt_port    = config["demo"].get("mgmt_port", 22)

    if target_ip:
        vms = [vm for vm in vms if vm["ip"] == target_ip]

    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  MODE: EXTERNAL (probing from your laptop){RESET}")
    print(f"{CYAN}  Story: Perimeter view -- outside actor scanning the segment{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  Targets   : {[vm['ip'] for vm in vms]}")
    print(f"  Ports     : {probe_ports}")
    print(f"  Interval  : {interval}s")
    print(f"  Mac policy: TCP/{mgmt_port} ALLOWED (mgmt SSH) | all others BLOCK")
    print(f"  Note      : TCP/{allowed_port} is only allowed app -> db, "
          f"not from this host")
    print(f"  Press Ctrl+C to stop.\n")

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"{BOLD}[{time.strftime('%H:%M:%S')}] Round {iteration} -- External{RESET}")
            for vm in vms:
                print(f"  laptop --> {vm['hostname']} ({vm['ip']})")
                for port in probe_ports:
                    expected      = "ALLOWED" if port == mgmt_port else "BLOCK"
                    success, msg  = _probe_external(vm["ip"], port)
                    result        = _ok(msg) if success else _fail(msg)
                    print(f"    TCP/{port:<5}  {result}  [{expected}]")
            print()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nSimulator stopped.")


# ---------------------------------------------------------------------------
# SSH gate — verify we can reach a host before starting a probe loop
# ---------------------------------------------------------------------------

def _check_ssh(vm, key_path, ssh_timeout, config):
    """Quick `echo SSH_OK` test; returns (ok, message)."""
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


# ---------------------------------------------------------------------------
# Internal mode — SSH into vm-app and run nc to vm-db from there
# ---------------------------------------------------------------------------

def _probe_internal(source_vm, target_vm, port, key_path, ssh_timeout, config):
    """Run `nc -z -w2` on `source_vm` against `target_vm:port`.

    The nc command suppresses all chatter so we can reliably parse a
    single token from stdout. SSH warnings (when they slip through despite
    LogLevel=ERROR) end up on stderr and are ignored.
    """
    user      = _get_ssh_user(source_vm, config)
    target_ip = target_vm["ip"]

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
    """Internal lateral-movement probe loop."""
    vms       = config["vms"]
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
    print(f"{CYAN}  MODE: INTERNAL (east-west lateral movement){RESET}")
    print(f"{CYAN}  Story: Attacker on {source_vm['hostname']} pivoting to {target_vm['hostname']}{RESET}")
    print(f"{CYAN}         This is the blast radius -- watch it shrink at enforcement{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  SSH user: {user}")
    print(f"  Source  : {source_vm['hostname']} ({source_vm['ip']})  <-- attacker foothold")
    print(f"  Target  : {target_vm['hostname']} ({target_vm['ip']})  <-- blast radius target")
    print(f"  Ports   : {probe_ports}")
    print(f"  Interval: {interval}s   |   Allowed after enforcement: TCP/{allowed_port}")
    print(f"  {_info('Before enforcement: all ports open -- blast radius is unlimited')}")
    print(f"  {_info('After enforcement:  CSW blocks at the db host firewall -- pivot stopped')}")
    print(f"  Press Ctrl+C to stop.\n")

    print(f"  Checking SSH connectivity...")
    ok, msg = _check_ssh(source_vm, key_path, ssh_timeout, config)
    if ok:
        print(f"  {GREEN}{msg}{RESET}\n")
    else:
        print(f"  {RED}SSH FAILED: {msg}{RESET}")
        print(f"  Run: eval \"$(ssh-agent -s)\" && ssh-add {config['ssh']['key_path']}")
        return

    iteration = 0
    try:
        while True:
            iteration += 1
            print(f"{BOLD}[{time.strftime('%H:%M:%S')}] Round {iteration} -- "
                  f"{source_vm['hostname']} -> {target_vm['hostname']}{RESET}")
            for port in probe_ports:
                expected     = "ALLOWED" if port == allowed_port else "BLOCK"
                success, msg = _probe_internal(
                    source_vm, target_vm, port, key_path, ssh_timeout, config
                )
                result = _ok(msg) if success else _fail(msg)
                print(f"  TCP/{port:<5}  {result}  [{expected}]")
            print()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nSimulator stopped.")


# ---------------------------------------------------------------------------
# Combined mode — both perspectives in one terminal
# ---------------------------------------------------------------------------

def run_combined(config):
    """Interleave external and internal probes for the live demo terminal."""
    vms       = config["vms"]
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
    print(f"{CYAN}  MODE: COMBINED (perimeter + east-west){RESET}")
    print(f"{CYAN}  Story: Full blast radius picture -- outside view + lateral pivot{RESET}")
    print(f"{CYAN}         Recommended for live demos -- shows both perspectives at once{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  SSH user  : {user}")
    print(f"  External  : laptop --> {target_vm['hostname']} ({target_vm['ip']})")
    print(f"  Internal  : {source_vm['hostname']} --> {target_vm['hostname']} (lateral movement)")
    print(f"  Ports     : {probe_ports}")
    print(f"  Interval  : {interval}s   |   Allowed after enforcement: TCP/{allowed_port}")
    print(f"  Press Ctrl+C to stop.\n")

    print(f"  Checking SSH connectivity to {source_vm['hostname']}...")
    ok, msg = _check_ssh(source_vm, key_path, ssh_timeout, config)
    if ok:
        print(f"  {GREEN}{msg}{RESET}\n")
    else:
        print(f"  {RED}SSH FAILED: {msg}{RESET}")
        print(f"  Run: eval \"$(ssh-agent -s)\" && ssh-add {config['ssh']['key_path']}")
        print(f"  External mode will still work. Starting external-only...\n")

    iteration = 0
    try:
        while True:
            iteration += 1
            ts = time.strftime("%H:%M:%S")

            # --- External half -----------------------------------------------
            print(f"{BOLD}[{ts}] Round {iteration} -- "
                  f"External (laptop -> {target_vm['hostname']}){RESET}")
            for port in probe_ports:
                expected     = "ALLOWED" if port == mgmt_port else "BLOCK"
                success, msg = _probe_external(target_vm["ip"], port)
                result       = _ok(msg) if success else _fail(msg)
                print(f"  TCP/{port:<5}  {result}  [{expected}]")
            print()

            # --- Internal half -----------------------------------------------
            print(f"{BOLD}[{ts}] Round {iteration} -- "
                  f"Internal ({source_vm['hostname']} -> {target_vm['hostname']}){RESET}")
            for port in probe_ports:
                expected     = "ALLOWED" if port == allowed_port else "BLOCK"
                success, msg = _probe_internal(
                    source_vm, target_vm, port, key_path, ssh_timeout, config
                )
                result = _ok(msg) if success else _fail(msg)
                print(f"  TCP/{port:<5}  {result}  [{expected}]")
            print()

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nSimulator stopped.")


# ---------------------------------------------------------------------------
# NFTables mode — show CSW firewall rules on each VM
# ---------------------------------------------------------------------------

def _get_nftables(vm, key_path, ssh_timeout, config):
    """Fetch the firewall ruleset from a VM.

    CSW pushes rules to either the `nft` table named `tet` (modern kernels)
    or to `iptables` (older kernels). Try them in order; emit the first one
    that has output. Falls back to dumping the entire `nft` ruleset so the
    operator can still see SOMETHING when CSW uses a non-standard table name.
    """
    user = _get_ssh_user(vm, config)

    # `sudo -n` => non-interactive; fails immediately if a password is needed.
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

    cmd = ["ssh"] + _ssh_opts(key_path, ssh_timeout) + [f"{user}@{vm['ip']}", fw_cmd]

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
    """Parse a firewall dump and bucket lines into allows / denies / catch-all.

    The parser is intentionally tolerant — different CSW versions vary in
    syntax and we want a clean summary even when format drifts.
    """
    lines      = raw_output.splitlines()
    allows     = []
    denies     = []
    catchall   = None
    rule_count = 0

    for line in lines:
        stripped = line.strip()
        # Skip headers, braces, and empty lines
        if (not stripped
                or stripped.startswith("table")
                or stripped.startswith("chain")
                or stripped in ("{", "}")):
            continue

        rule_count += 1
        lower = stripped.lower()

        if "accept" in lower or "allow" in lower:
            allows.append(stripped)
        elif "drop" in lower or "reject" in lower:
            # Heuristic: short DROP lines without an explicit match clause
            # tend to be the catch-all; everything else is a targeted DENY.
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
    """SSH into each VM and pretty-print the CSW firewall state."""
    vms          = config["vms"]
    key_path     = os.path.expanduser(config["ssh"]["key_path"])
    ssh_timeout  = config["ssh"].get("connect_timeout", 10)
    allowed_port = config["demo"]["allowed_port"]

    print(f"\n{CYAN}{'=' * 60}{RESET}")
    print(f"{CYAN}  NFTables Firewall Rules -- CSW Enforcement View{RESET}")
    print(f"{CYAN}{'=' * 60}{RESET}")
    print(f"  This shows what CSW has actually written to each VM.")
    print(f"  Run before enforcement: no CSW rules yet.")
    print(f"  Run after enforcement:  see the policy pushed to the host.")
    print()

    for vm in vms:
        try:
            user = _get_ssh_user(vm, config)
        except RuntimeError as e:
            print(f"  {RED}{e}{RESET}\n")
            continue

        print(f"{BOLD}  [{vm['hostname']} / {vm['ip']}]  (SSH user: {user}){RESET}")
        print(f"  {'-' * 54}")

        ok, ssh_msg = _check_ssh(vm, key_path, ssh_timeout, config)
        if not ok:
            print(f"  {RED}SSH FAILED: {ssh_msg}{RESET}")
            print(f"  Run: eval \"$(ssh-agent -s)\" && ssh-add {config['ssh']['key_path']}")
            print()
            continue

        print(f"  {GREEN}SSH OK{RESET}")
        raw, err = _get_nftables(vm, key_path, ssh_timeout, config)

        if err:
            print(f"  {RED}{err}{RESET}\n")
            continue

        summary = _summarise_nftables(raw, vm, allowed_port)
        print(f"  Total rules : {summary['total_rules']}\n")

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
    print(f"  TIP: Run this BEFORE enforcement to show the open state.")
    print(f"       Run again AFTER enforcement to show rules pushed by CSW.")
    print(f"{CYAN}{'=' * 60}{RESET}\n")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run_loop(config, target_ip=None, mode="combined"):
    """Dispatcher used by `menu.py`."""
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
        help="Path to config.yaml (default: ./config.yaml in repo root)",
    )
    parser.add_argument(
        "--mode",
        choices=["external", "internal", "combined", "nftables"],
        default="combined",
        help=(
            "external : probe from operator laptop | "
            "internal : SSH into vm-app then nc to vm-db | "
            "combined : both perspectives | "
            "nftables : show CSW firewall rules on each VM"
        ),
    )
    parser.add_argument(
        "--target",
        default=None,
        help="External mode only: probe just this VM IP",
    )
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"Config not found: {args.config}")
        print("Copy config.yaml.example to config.yaml and edit it.")
        sys.exit(1)

    config = _load_config(args.config)
    run_loop(config, target_ip=args.target, mode=args.mode)


if __name__ == "__main__":
    main()
