#!/usr/bin/env python3
"""
menu.py
=======
CSW Blast Radius Demo Builder — interactive control center.

This is the operator-facing entry point. It loads `config.yaml`, walks
through the five demo phases on demand, and exposes utility actions for
the live demo (traffic simulator + nftables view + status report).

Usage
-----
    # Interactive (most common)
    python3 menu.py

    # With a non-default config file
    python3 menu.py --config /path/to/config.yaml

    # Non-interactive: run a single phase head-less
    python3 menu.py --phase 1
    python3 menu.py --phase 4

    # Non-interactive: run prep phases 1 + 2 + 3 (NEVER auto-enforces)
    python3 menu.py --phase all
"""

import argparse
import os
import sys
import time

# Always make the project root importable, no matter how this is invoked
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
if TOOL_DIR not in sys.path:
    sys.path.insert(0, TOOL_DIR)


# ===========================================================================
# Self-contained YAML parser (no external dependencies)
# ===========================================================================
#
# The full PyYAML library is preferred when available. The fallback parser
# below handles only the YAML subset used by `config.yaml.example`:
#   - top-level dicts
#   - 2-space-indent nested dicts
#   - lists of scalars (e.g. probe_ports)
#   - lists of dicts (the vms block)
#
# Anything more exotic (anchors, multi-line strings, merge keys, comments
# after values that contain `#`) requires PyYAML — install with:
#   pip install -r requirements.txt
# ===========================================================================

def _coerce(val: str):
    """Convert a YAML scalar string to bool / int / str."""
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
    """Minimal YAML parser sufficient for this project's config shape."""
    config             = {}
    current_section    = None        # top-level key e.g. "csw"
    current_subsection = None        # 2nd-level list key e.g. "probe_ports"
    vm_list            = []          # accumulator for the vms block
    current_vm         = None        # the VM dict currently being built

    with open(path) as f:
        lines = f.readlines()

    for raw in lines:
        line    = raw.rstrip()
        content = line.lstrip()

        # Skip blanks and full-line comments
        if not content or content.startswith("#"):
            continue

        indent = len(line) - len(content)

        # ---- Top-level (indent 0) -----------------------------------------
        if indent == 0:
            # Flush any pending VM dict before starting a new top-level block
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
                current_section    = key
                current_subsection = None

        # ---- Second level (indent 2) --------------------------------------
        elif indent == 2:
            if content.startswith("- "):
                # A list item at level 2 — only used by the vms block
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
                    pass  # vm dicts are entered via "- " above
                elif isinstance(config.get(current_section), dict):
                    if val == "":
                        # Empty value -> a list begins on the next indent
                        config[current_section][key] = []
                        current_subsection           = key
                    else:
                        config[current_section][key] = _coerce(val)
                        current_subsection           = None

        # ---- Third level (indent 4) ---------------------------------------
        elif indent == 4:
            if content.startswith("- "):
                # A list item belonging to current_subsection (e.g. probe_ports)
                val = content[2:].strip()
                if (current_section and current_subsection
                        and isinstance(config.get(current_section), dict)
                        and isinstance(config[current_section].get(current_subsection), list)):
                    config[current_section][current_subsection].append(_coerce(val))
            elif ":" in content and current_vm is not None:
                # Continuation of the current vm dict
                key, _, val = content.partition(":")
                current_vm[key.strip()] = _coerce(val.strip())

    # Flush the trailing VM (if the file ends inside the vms block)
    if current_vm is not None:
        vm_list.append(current_vm)
    if vm_list:
        config["vms"] = vm_list

    return config


def load_config(config_path: str) -> dict:
    """Load config.yaml using PyYAML when available, fallback parser otherwise."""
    try:
        import yaml
        with open(config_path) as f:
            return yaml.safe_load(f)
    except ImportError:
        return _parse_yaml(config_path)


# ===========================================================================
# Tiny logging helper used by phase modules
# ===========================================================================

class Logger:
    """Captures every line printed by phase modules.

    Phase modules call `log("message")`; we both print it and remember it
    in `self.lines`. The captured lines are not currently persisted to a
    file, but the structure makes it easy to add file logging later.
    """
    def __init__(self):
        self.lines = []

    def __call__(self, msg: str):
        self.lines.append(msg)
        print(f"  {msg}")


# ===========================================================================
# UI helpers — tiny ANSI colour helpers, no external deps
# ===========================================================================

def _header(title: str) -> None:
    bar = "=" * 60
    print(f"\n\033[1;36m{bar}\033[0m")
    print(f"\033[1;36m  {title}\033[0m")
    print(f"\033[1;36m{bar}\033[0m")


def _warn(msg: str) -> None:
    print(f"\n\033[1;33m  ! {msg}\033[0m\n")


def _print_menu(config: dict) -> None:
    """Render the main interactive menu."""
    scope_name = config["demo"]["scope_name"]
    ws_name    = config["demo"]["workspace_name"]
    tenant     = os.environ.get("CSW_TENANT", config["csw"].get("tenant", "not set"))

    print()
    print("\033[1m" + "=" * 60 + "\033[0m")
    print("\033[1m  CSW Blast Radius Demo Builder\033[0m")
    print("\033[1m  Stop lateral movement. Contain the blast radius.\033[0m")
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
    print("  TE  Traffic simulator -- External  (laptop -> VMs, perimeter view)")
    print("  TI  Traffic simulator -- Internal  (vm-app -> vm-db, lateral movement)")
    print("  TC  Traffic simulator -- Combined  (both perspectives, recommended)")
    print("  N   Show nftables rules on VMs    (run before + after enforcement)")
    print("  S   Show environment status")
    print("  A   Auto prep -- run phases 1, 2, 3 in sequence (no enforce)")
    print("  Q   Quit")
    print()


# ===========================================================================
# Status command
# ===========================================================================

def show_status(config: dict) -> None:
    """Print a concise summary of credentials, SSH key, installer, and CSW state."""
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
        print(f"    {vm['hostname']:20s}  {vm['ip']:15s}  role={vm['role']:6s}  env={vm['env']}")
    print()

    # Try the API last — we don't want auth errors to hide the local config
    # checks above, which are the most common things to get wrong.
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
        for sensor in sensor_list or []:
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


# ===========================================================================
# Phase runners
# ===========================================================================

def run_phase(phase_num: int, config: dict) -> None:
    """Dispatch to the requested phase module with a shared Logger."""
    log = Logger()
    print()

    if phase_num == 1:
        _header("Phase 1 - Scope + Labels")
        from phases.phase1_scope_labels import run
        run(config, log=log)

    elif phase_num == 2:
        _header("Phase 2 - Agent Deployment")
        # Let the operator deploy to one VM at a time when iterating
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
        _header("Phase 4 - ENFORCE  (contain the blast radius)")
        # Two safety nets: a loud warning + the literal-string confirm gate.
        # The string check is intentional — typing 'y' / 'Enter' must not
        # be enough to push firewall rules in front of a customer.
        _warn(
            "This pushes nftables rules to your lab VMs.\n"
            "  East-west traffic that does not match the policy is dropped\n"
            "  at the host kernel of every workload.\n"
            "  Before continuing:\n"
            "    1. Traffic simulator running in another terminal (combined mode)\n"
            "    2. CSW Policy Analysis open in your browser\n"
            "    3. Customer watching the simulator wall of green"
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
    """Wrapper used by the menu utility actions (TE / TI / TC)."""
    mode_labels = {
        "external": "External  -- laptop probes VM ports (perimeter view)",
        "internal": "Internal  -- vm-app runs nc to vm-db (lateral movement)",
        "combined": "Combined  -- both perspectives in one terminal",
    }
    _header(f"Traffic Simulator -- {mode_labels.get(mode, mode)}")

    if mode in ("internal", "combined"):
        # Internal modes need SSH to vm-app; print a quick reminder so the
        # operator doesn't get caught by a missing ssh-agent.
        source = next((vm for vm in config["vms"] if vm.get("role") == "app"), None)
        target = next((vm for vm in config["vms"] if vm.get("role") == "db"),  None)
        if source and target:
            print(f"  Source : {source['hostname']} ({source['ip']})  <-- attacker foothold")
            print(f"  Target : {target['hostname']} ({target['ip']})  <-- blast radius target")
        print(f"  Make sure ssh-agent is running:")
        print(f"    eval \"$(ssh-agent -s)\" && ssh-add {config['ssh']['key_path']}")

    print("  Runs until Ctrl+C.")
    print()
    input("  Press Enter to start...")
    from traffic.simulator import run_loop
    run_loop(config, mode=mode)


# ===========================================================================
# Main entry point
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="CSW Blast Radius Demo Builder")
    parser.add_argument(
        "--config",
        default=os.path.join(TOOL_DIR, "config.yaml"),
        help="Path to config.yaml (default: ./config.yaml)",
    )
    parser.add_argument(
        "--phase", default=None,
        help="Run one phase non-interactively: 1-5 or 'all' (= phases 1,2,3 only)",
    )
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    if not os.path.exists(config_path):
        # Common case: operator forgot to copy the example
        print(f"Config not found: {config_path}")
        example = os.path.join(TOOL_DIR, "config.yaml.example")
        if os.path.exists(example):
            print(f"Hint: copy the template and edit it:")
            print(f"  cp config.yaml.example config.yaml")
        sys.exit(1)

    config = load_config(config_path)

    # Load .env (CSWClient also does this on import; doing it here as well
    # makes show_status() show credentials before any client is created).
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

    # Mirror tenant from config to env if .env did not set it
    if not os.environ.get("CSW_TENANT"):
        tenant = config.get("csw", {}).get("tenant", "")
        if tenant:
            os.environ["CSW_TENANT"] = tenant

    # ------------------ Non-interactive single-phase mode ------------------
    if args.phase:
        if args.phase.lower() == "all":
            # IMPORTANT: 'all' deliberately stops at Phase 3. We never want
            # `--phase all` to push enforcement automatically — the live
            # moment is the entire point of the demo.
            for p in [1, 2, 3]:
                run_phase(p, config)
        else:
            try:
                run_phase(int(args.phase), config)
            except ValueError:
                print(f"Unknown phase: {args.phase}")
                sys.exit(1)
        return

    # ------------------ Interactive loop ----------------------------------
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
            print("  Run this BEFORE enforcement to show the open state.")
            print("  Run again AFTER enforcement to show what CSW pushed.")
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

        # Tiny pause keeps the terminal scroll readable between actions
        time.sleep(0.3)


if __name__ == "__main__":
    main()
