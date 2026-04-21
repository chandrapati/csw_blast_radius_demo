"""
phases/phase5_teardown.py
Phase 5: Clean up the demo environment.

Cleanup order (matters -- CSW enforces dependency chain):
  1. Disable enforcement on workspace
  2. Delete inventory filters (demo-app, demo-db, demo-mgmt-mac)
  3. Delete workspace
  4. Delete scope
  5. Optionally uninstall agents from VMs

Safe to run multiple times (idempotent where possible).

API capabilities required:
  - app_policy_management
"""

import sys
import os
import subprocess
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.csw_client import CSWClient


def _ssh_opts(key_path, timeout):
    return [
        "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "BatchMode=yes",
    ]


def _get_all_scopes(client):
    scopes = client.get("/openapi/v1/app_scopes")
    if isinstance(scopes, list):
        return scopes
    if isinstance(scopes, dict):
        return scopes.get("results", scopes.get("app_scopes", []))
    return []


def _find_scope_id(client, scope_name, log):
    scopes = _get_all_scopes(client)
    for s in scopes:
        if s.get("short_name") == scope_name:
            return s["id"]
    log(f"  Scope '{scope_name}' not found -- already deleted or never created.")
    return None


def _find_workspace_id(client, workspace_name, scope_id, log):
    if not scope_id:
        return None
    workspaces = client.get(f"/openapi/v1/applications?app_scope_id={scope_id}")
    if isinstance(workspaces, list):
        for ws in workspaces:
            if ws.get("name") == workspace_name:
                return ws["id"]
    return None


# ── Step 1: Disable enforcement ───────────────────────────────────────────────

def disable_enforcement(client, workspace_id, log):
    log(f"  Disabling enforcement...")
    try:
        client.post(f"/openapi/v1/applications/{workspace_id}/disable_enforce", {})
        log("  Enforcement disabled.")
        time.sleep(5)
    except RuntimeError as e:
        log(f"  Note: {e} (may already be disabled -- continuing)")


# ── Step 2: Delete inventory filters ─────────────────────────────────────────

def delete_inventory_filters(client, config, log):
    """
    Delete only the three filters Phase 3 creates.
    Uses exact name matching to avoid touching colleagues' filters.

    Phase 3 always creates filters with these exact names:
      demo-app        (role filter for app VMs)
      demo-db         (role filter for db VMs)
      demo-mgmt-mac   (IP filter for management host)
    """
    log("  Looking for demo inventory filters to delete...")

    try:
        filters = client.get("/openapi/v1/filters/inventories")
        if filters is None:
            filters = []
        elif isinstance(filters, dict):
            filters = filters.get("results", filters.get("data", []))
    except RuntimeError as e:
        log(f"  Could not retrieve filters: {e}")
        return

    # Exact names created by Phase 3 -- nothing else will match
    target_names = {
        "demo-app",
        "demo-db",
        "demo-mgmt-mac",
    }

    log(f"  Scanning {len(filters)} filters for: {sorted(target_names)}")

    targets = [f for f in filters if f.get("name", "") in target_names]

    if not targets:
        log("  No demo filters found -- already deleted or Phase 3 not yet run.")
        return

    log(f"  Found {len(targets)} filter(s) to delete:")
    for f in targets:
        log(f"    {f['id']}  {f['name']}")
        try:
            client.delete(f"/openapi/v1/filters/inventories/{f['id']}")
            log(f"    Deleted.")
        except RuntimeError as e:
            log(f"    Could not delete '{f['name']}': {e}")
            log(f"    It may still be referenced by the workspace.")
            log(f"    Delete the workspace first (Step 3) then run Phase 5 again.")


# ── Step 3: Delete workspace ──────────────────────────────────────────────────

def delete_workspace(client, workspace_id, log):
    log(f"  Deleting workspace {workspace_id}...")
    try:
        client.delete(f"/openapi/v1/applications/{workspace_id}")
        log("  Workspace deleted.")
    except RuntimeError as e:
        log(f"  Could not delete workspace: {e}")


# ── Step 4: Delete scope ──────────────────────────────────────────────────────

def delete_scope(client, scope_id, log):
    log(f"  Deleting scope {scope_id}...")
    try:
        client.delete(f"/openapi/v1/app_scopes/{scope_id}")
        log("  Scope deleted.")
    except RuntimeError as e:
        log(f"  Could not delete scope: {e}")
        log("  If CSW reports dependencies, check for remaining filters or workspaces in the UI.")


# ── Step 5: Uninstall agents ──────────────────────────────────────────────────

def uninstall_agents(config, log):
    key_path = os.path.expanduser(config["ssh"]["key_path"])
    timeout  = config["ssh"].get("connect_timeout", 10)

    for vm in config["vms"]:
        user = vm.get("ssh_user", config["ssh"].get("user", "root"))
        log(f"  Uninstalling agent on {vm['hostname']} ({vm['ip']})...")

        uninstall_cmd = (
            "if command -v rpm &>/dev/null; then "
            "  sudo rpm -e tet-sensor 2>/dev/null || true; "
            "elif command -v dpkg &>/dev/null; then "
            "  sudo dpkg --purge tet-sensor 2>/dev/null || true; "
            "fi; "
            "echo uninstall_done"
        )

        cmd = ["ssh"] + _ssh_opts(key_path, timeout) + [f"{user}@{vm['ip']}", uninstall_cmd]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if "uninstall_done" in result.stdout:
                log(f"    Agent uninstalled on {vm['ip']}.")
            else:
                log(f"    Output: {result.stdout.strip()} {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            log(f"    Timeout reaching {vm['ip']} -- skipping.")
        except Exception as e:
            log(f"    Error on {vm['ip']}: {e}")


# ── Entry point ───────────────────────────────────────────────────────────────

def run(config, log=print, uninstall_agents_flag=False):
    """Entry point called by the menu orchestrator."""
    log("Phase 5: Teardown")
    log("-" * 40)

    client         = CSWClient()
    workspace_name = config["demo"]["workspace_name"]
    scope_name     = config["demo"]["scope_name"]

    # Find scope and workspace IDs upfront
    scope_id     = _find_scope_id(client, scope_name, log)
    workspace_id = _find_workspace_id(client, workspace_name, scope_id, log)

    if workspace_id:
        log(f"  Workspace found: {workspace_id}")
    else:
        log("  No workspace found -- may already be deleted.")

    # Step 1: disable enforcement
    if workspace_id:
        disable_enforcement(client, workspace_id, log)

    # Step 2: delete inventory filters (must happen before workspace/scope)
    delete_inventory_filters(client, config, log)

    # Step 3: delete workspace
    if workspace_id:
        delete_workspace(client, workspace_id, log)

    # Step 4: delete scope
    if scope_id:
        delete_scope(client, scope_id, log)

    # Step 5: optionally uninstall agents
    if uninstall_agents_flag:
        log("  Uninstalling agents from VMs...")
        uninstall_agents(config, log)
    else:
        log("  Skipping agent uninstall (choose Y when prompted if needed).")

    log("-" * 40)
    log("Phase 5 complete. Demo environment is clean.")
    return {
        "workspace_deleted": workspace_id is not None,
        "scope_deleted"    : scope_id is not None,
    }
