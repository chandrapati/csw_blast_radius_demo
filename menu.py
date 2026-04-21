#!/usr/bin/env python3
"""
menu.py
CSW Demo Builder - Interactive Control Menu
csw-security-toolkit / 05_demo_builder

Usage:
  python3 menu.py
  python3 menu.py --config /path/to/config.yaml
  python3 menu.py --phase 4
  python3 menu.py --phase all
"""

import argparse
import os
import sys
import time

# ── Make sure the tool's own directory is always on the path ──────────────────
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOL_DIR not in sys.path:
    sys.path.insert(0, TOOL_DIR)


# ── Self-contained YAML parser (no external dependencies) ─────────────────────

def _coerce(val: str):
    """Convert a YAML scalar string to the right Python type."""
    val = val.strip().strip('"').strip("'")
    if val in ("true", "True"):
        return True
    if val in ("false", "False"):
        return False
    try:
        return int(val)
    except (ValueError, TypeError):
        return val


def _parse_yaml(path: str) -> dict:
    """
    Minimal YAML parser sufficient for config.yaml.
    Handles: top-level dicts, nested dicts (2-space indent),
    lists of scalars and lists of dicts (the vms block).
    """
    config = {}
    current_section = None      # top-level key  e.g. "csw"
    current_subsection = None   # 2nd-level key  e.g. "probe_ports"
    vm_list = []                # accumulates VM dicts
    current_vm = None           # the VM dict being built

    with open(path) as f:
        lines = f.readlines()

    for raw in lines:
        line = raw.rstrip()
        content = line.lstrip()

        # Skip blanks and comments
        if not content or content.startswith("#"):
            continue

        indent = len(line) - len(content)

        # ── Top-level key (indent 0) ──────────────────────────────────────
        if indent == 0:
            # Flush any pending VM
            if current_vm is not None:
                vm_list.append(current_vm)
                current_vm = None

            if ":" in content:
                key, _, val = content.partition(":")
                key = key.strip()
                val = val.strip()
                if val:
                    config[key] = _coerce(val)
                else:
                    config[key] = {}
                current_section = key
                current_subsection = None

        # ── Second-level (indent 2) ───────────────────────────────────────
        elif indent == 2:
            if content.startswith("- "):
                # List item at level 2 -- only used for vms block
                if current_section == "vms":
                    if current_vm is not None:
                        vm_list.append(current_vm)
                    current_vm = {}
                    rest = content[2:].strip()
                    if ":" in rest:
                        k, _, v = rest.partition(":")
                        current_vm[k.strip()] = _coerce(v.strip())
            elif ":" in content:
                key, _, val = content.partition(":")
                key = key.strip()
                val = val.strip()

                if current_section == "vms":
                    # This shouldn't normally happen at indent 2 inside vms
                    pass
                elif isinstance(config.get(current_section), dict):
                    if val == "":
                        # Empty value means a list follows at indent 4
                        config[current_section][key] = []
                        current_subsection = key
                    else:
                        config[current_section][key] = _coerce(val)
                        current_subsection = None

        # ── Third-level (indent 4) ────────────────────────────────────────
        elif indent == 4:
            if content.startswith("- "):
                # List item (e.g. probe_ports)
                val = content[2:].strip()
                if (current_section and current_subsection
                        and isinstance(config.get(current_section), dict)
                        and isinstance(config[current_section].get(current_subsection), list)):
                    config[current_section][current_subsection].append(_coerce(val))
            elif ":" in content and current_vm is not None:
                # Key-value inside a VM dict
                key, _, val = content.partition(":")
                current_vm[key.strip()] = _coerce(val.strip())

    # Flush the last VM if present
    if current_vm is not None:
        vm_list.append(current_vm)

    # Attach vm_list to config if we collected any
    if vm_list:
        config["vms"] = vm_list

    return config


def load_config(config_path: str) -> dict:
    """Load config.yaml using PyYAML if available, else the built-in parser."""
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f)
    except ImportError:
        pass
    return _parse_yaml(config_path)


# ── Logging ───────────────────────────────────────────────────────────────────

class Logger:
    def __init__(self):
        self.lines = []

    def __call__(self, msg: str):
        self.lines.append(msg)
        print(f"  {msg}")


# ── UI helpers ────────────────────────────────────────────────────────────────

def _header(title: str) -> None:
    bar = "=" * 60
    print(f"\n\033[1;36m{bar}\033[0m")
    print(f"\033[1;36m  {title}\033[0m")
    print(f"\033[1;36m{bar}\033[0m")


def _warn(msg: str) -> None:
    print(f"\n\033[1;33m  ! {msg}\033[0m\n")


def _print_menu(config: dict) -> None:
    scope_name = config["demo"]["scope_name"]
    ws_name    = config["demo"]["workspace_name"]
    tenant     = os.environ.get("CSW_TENANT", config["csw"].get("tenant", "not set"))

    print()
    print("\033[1m" + "=" * 60 + "\033[0m")
    print("\033[1m  CSW Demo Builder - Blast Radius Demo\033[0m")
    print("\033[1m" + "=" * 60 + "\033[0m")
    print(f"  Tenant    : {tenant}")
    print(f"  Scope     : {scope_name}")
    print(f"  Workspace : {ws_name}")
    print(f"  VMs       : {len(config['vms'])} configured")
    print()
    print("  \033[1mPhases\033[0m")
    print("  " + "-" * 48)
    print("  1  Create scope + upload labels to CSW")
    print("  2  Deploy agents to lab VMs (SSH)")
    print("  3  Create workspace + policy + start analysis")
    print("  4  \033[1;31mENFORCE\033[0m  (live demo moment -- lock the doors)")
    print("  5  Teardown (clean up after demo)")
    print()
    print("  \033[1mUtilities\033[0m")
    print("  " + "-" * 48)
    print("  TE  Traffic simulator -- External  (Mac -> VMs, perimeter view)")
    print("  TI  Traffic simulator -- Internal  (vm-app -> vm-db, lateral movement)")
    print("  TC  Traffic simulator -- Combined  (both perspectives, recommended)")
    print("  N   Show nftables rules on VMs    (run before + after enforcement)")
    print("  S   Show environment status")
    print("  A   Auto prep -- run phases 1, 2, 3 in sequence")
    print("  Q   Quit")
    print()


# ── Status ────────────────────────────────────────────────────────────────────

def show_status(config: dict) -> None:
    print()
    _header("Environment Status")

    api_key    = os.environ.get("CSW_API_KEY", "")
    api_secret = os.environ.get("CSW_API_SECRET", "")
    tenant     = os.environ.get("CSW_TENANT", config["csw"].get("tenant", ""))

    print(f"  CSW Tenant   : {tenant or 'NOT SET'}")
    print(f"  API Key      : {'SET (' + api_key[:8] + '...)' if api_key else 'NOT SET'}")
    print(f"  API Secret   : {'SET' if api_secret else 'NOT SET'}")
    print()

    key_path = os.path.expanduser(config["ssh"]["key_path"])
    print(f"  SSH Key      : {key_path} {'[OK]' if os.path.exists(key_path) else '[NOT FOUND]'}")

    installer = os.path.normpath(
        os.path.join(TOOL_DIR, config.get("agent_installer", "./tetration_installer.sh"))
    )
    inst_ok = os.path.exists(installer)
    print(f"  Installer    : {installer}")
    print(f"               : {'[OK]' if inst_ok else '[NOT FOUND -- download from CSW UI]'}")
    print()

    print("  VMs configured:")
    for vm in config["vms"]:
        print(f"    {vm['hostname']:12s}  {vm['ip']:15s}  role={vm['role']:6s}  env={vm['env']}")
    print()

    try:
        from auth.csw_client import CSWClient
        client = CSWClient()

        scope_name = config["demo"]["scope_name"]
        scopes     = client.get("/openapi/v1/app_scopes")
        scope      = next((s for s in scopes if s.get("short_name") == scope_name), None)
        print(f"  Demo scope   : {scope_name} {'[EXISTS]' if scope else '[NOT CREATED]'}")

        if scope:
            ws_name    = config["demo"]["workspace_name"]
            workspaces = client.get(f"/openapi/v1/applications?app_scope_id={scope['id']}")
            ws = None
            if isinstance(workspaces, list):
                ws = next((w for w in workspaces if w.get("name") == ws_name), None)
            print(f"  Workspace    : {ws_name} {'[EXISTS]' if ws else '[NOT CREATED]'}")
            if ws:
                print(f"  Analysis     : {'RUNNING' if ws.get('analysis_enabled') else 'STOPPED'}")
                print(f"  Enforcement  : {'ACTIVE' if ws.get('enforcement_enabled') else 'NOT ENFORCED'}")

        sensors     = client.get("/openapi/v1/sensors")
        sensor_list = sensors.get("results", []) if isinstance(sensors, dict) else sensors
        vm_ips      = {vm["ip"] for vm in config["vms"]}
        active      = []
        for sensor in sensor_list:
            for iface in sensor.get("interfaces", []):
                if iface.get("ip") in vm_ips:
                    active.append(iface["ip"])

        print(f"\n  Agents       : {len(active)}/{len(config['vms'])} active")
        for ip in active:
            print(f"    [ACTIVE] {ip}")
        for vm in config["vms"]:
            if vm["ip"] not in active:
                print(f"    [ABSENT] {vm['ip']} ({vm['hostname']})")

    except EnvironmentError as e:
        print(f"  CSW API      : Cannot connect -- {e}")
    except Exception as e:
        print(f"  CSW API      : Error -- {e}")

    print()


# ── Phase runners ─────────────────────────────────────────────────────────────

def run_phase(phase_num: int, config: dict) -> None:
    log = Logger()
    print()

    if phase_num == 1:
        _header("Phase 1 - Scope + Labels")
        from phases.phase1_scope_labels import run
        run(config, log=log)

    elif phase_num == 2:
        _header("Phase 2 - Agent Deployment")
        print("  Deploy to all VMs or a specific one?\n")
        for i, vm in enumerate(config["vms"], 1):
            print(f"    {i}. {vm['hostname']} ({vm['ip']}) -- {vm.get('description', '')}")
        print("    A. All VMs\n")
        choice = input("  Choice [A]: ").strip().upper() or "A"

        from phases.phase2_agent_deploy import run
        if choice == "A":
            run(config, log=log)
        else:
            try:
                vm = config["vms"][int(choice) - 1]
                run(config, log=log, target_vm_ip=vm["ip"])
            except (ValueError, IndexError):
                print("  Invalid choice -- deploying to all VMs.")
                run(config, log=log)

    elif phase_num == 3:
        _header("Phase 3 - Workspace + Policy")
        from phases.phase3_workspace_policy import run
        run(config, log=log)

    elif phase_num == 4:
        _header("Phase 4 - ENFORCE POLICY")
        _warn(
            "This pushes firewall rules to your lab VMs.\n"
            "  Run the traffic simulator in a second terminal first.\n"
            "  Open CSW Policy Analysis in your browser.\n"
            "  Your customer should be watching both screens."
        )
        confirm = input("  Type ENFORCE to proceed (anything else cancels): ").strip()
        if confirm != "ENFORCE":
            print("  Aborted. No changes made.")
            return
        from phases.phase4_enforce import run
        run(config, log=log)

    elif phase_num == 5:
        _header("Phase 5 - Teardown")
        uninstall = input("  Also uninstall agents from VMs? [y/N]: ").strip().lower() == "y"
        from phases.phase5_teardown import run
        run(config, log=log, uninstall_agents_flag=uninstall)

    print()


def run_traffic_simulator(config, mode="combined"):
    """Launch the traffic simulator in the requested mode."""
    mode_labels = {
        "external": "External  -- Mac probes VM ports (perimeter view)",
        "internal": "Internal  -- vm-app runs nc to vm-db (lateral movement)",
        "combined": "Combined  -- both perspectives in one terminal",
    }
    _header(f"Traffic Simulator -- {mode_labels.get(mode, mode)}")

    if mode == "internal" or mode == "combined":
        source = next((vm for vm in config["vms"] if vm.get("role") == "app"), None)
        target = next((vm for vm in config["vms"] if vm.get("role") == "db"),  None)
        if source and target:
            print(f"  Source : {source['hostname']} ({source['ip']})  <-- attacker foothold")
            print(f"  Target : {target['hostname']} ({target['ip']})  <-- blast radius target")
        print(f"  Make sure ssh-agent is running: eval \"$(ssh-agent -s)\" && ssh-add ~/.ssh/csw_lab_key")

    print("  Runs until Ctrl+C.")
    print()
    input("  Press Enter to start...")
    from traffic.simulator import run_loop
    run_loop(config, mode=mode)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CSW Demo Builder")
    parser.add_argument("--config", default=os.path.join(TOOL_DIR, "config.yaml"))
    parser.add_argument("--phase", default=None,
                        help="Run one phase directly: 1-5 or 'all'")
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    if not os.path.exists(config_path):
        print(f"Config not found: {config_path}")
        sys.exit(1)

    config = load_config(config_path)

    # Load .env
    env_path = os.path.join(os.path.dirname(config_path), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key   = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value

    # Sync tenant from config into env if missing
    if not os.environ.get("CSW_TENANT"):
        tenant = config.get("csw", {}).get("tenant", "")
        if tenant:
            os.environ["CSW_TENANT"] = tenant

    # Non-interactive single-phase mode
    if args.phase:
        if args.phase.lower() == "all":
            for p in [1, 2, 3]:
                run_phase(p, config)
        else:
            try:
                run_phase(int(args.phase), config)
            except ValueError:
                print(f"Unknown phase: {args.phase}")
                sys.exit(1)
        return

    # Interactive loop
    while True:
        _print_menu(config)
        choice = input("  Select [1/2/3/4/5/TE/TI/TC/N/S/A/Q]: ").strip().upper()

        if choice == "Q":
            print("\n  Goodbye.\n")
            break
        elif choice in ("1", "2", "3", "4", "5"):
            run_phase(int(choice), config)
        elif choice == "TE":
            run_traffic_simulator(config, mode="external")
        elif choice == "TI":
            run_traffic_simulator(config, mode="internal")
        elif choice in ("TC", "T"):
            run_traffic_simulator(config, mode="combined")
        elif choice == "N":
            _header("NFTables Rules")
            print("  SSHing into each VM to read current firewall state.")
            print("  Run this before enforcement to show the open state.")
            print("  Run again after enforcement to show what CSW pushed.")
            print()
            input("  Press Enter to continue...")
            from traffic.simulator import run_nftables
            run_nftables(config)
        elif choice == "S":
            show_status(config)
        elif choice == "A":
            _header("Auto Prep - Phases 1 to 3")
            _warn(
                "Creates scope, uploads labels, deploys agents,\n"
                "  creates workspace, writes policy, starts analysis.\n"
                "  Enforcement is NOT triggered -- you do that live."
            )
            if input("  Proceed? [y/N]: ").strip().lower() == "y":
                for p in [1, 2, 3]:
                    run_phase(p, config)
                print("\n  Auto prep complete.")
                print("  Open a second terminal and run:")
                print("    python3 traffic/simulator.py --mode combined")
                print("  Then come back here and choose 4 when ready to enforce.")
            else:
                print("  Aborted.")
        else:
            print("  Invalid choice.")

        time.sleep(0.3)


if __name__ == "__main__":
    main()
