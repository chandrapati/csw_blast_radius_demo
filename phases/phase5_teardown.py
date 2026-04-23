"""
phases/phase5_teardown.py
=========================
Phase 5 — Tear down everything Phases 1-4 created.

Why the order matters
---------------------
CSW enforces a strict dependency chain on deletion:

    enforcement  ->  workspace  ->  filters  ->  scope

If you try to delete a workspace whose enforcement is still active,
CSW will reject the delete. If you try to delete a scope while filters
or workspaces still reference it, CSW will reject that too.

We therefore work bottom-up:
    1. Disable enforcement on the workspace.
    2. Delete the three inventory filters Phase 3 created (by EXACT name
       — never wildcard — so we cannot accidentally delete other people's
       filters on a shared tenant).
    3. Delete the workspace.
    4. Delete the scope.
    5. (Optional) SSH into each VM and uninstall the CSW agent package.

Idempotent: every step tolerates "not found" and continues.

API capabilities required
-------------------------
- app_policy_management
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.csw_client import CSWClient

# Reuse the SAME filter names Phase 3 creates — single source of truth would
# be nicer, but a defensive duplicate is acceptable for two scripts.
FILTER_NAMES = {"demo-app", "demo-db", "demo-mgmt-host"}


# ---------------------------------------------------------------------------
# SSH helpers (used only when uninstall_agents_flag=True)
# ---------------------------------------------------------------------------

def _ssh_opts(key_path, timeout):
    """Same SSH option set as Phase 2 — see that module's docstring for caveats."""
    return [
        "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={timeout}",
        "-o", "BatchMode=yes",
    ]


def _resolve_user(vm, config):
    """Resolve SSH user with the same precedence as Phase 2."""
    user = vm.get("ssh_user") or config.get("ssh", {}).get("user")
    if not user:
        raise RuntimeError(
            f"No SSH user configured for {vm['hostname']} ({vm['ip']}). "
            "Set ssh.user globally or vms[*].ssh_user per host in config.yaml."
        )
    return user


# ---------------------------------------------------------------------------
# CSW lookup helpers
# ---------------------------------------------------------------------------

def _get_all_scopes(client):
    """Normalise CSW scope listings to a flat list."""
    scopes = client.get("/openapi/v1/app_scopes")
    if isinstance(scopes, list):
        return scopes
    if isinstance(scopes, dict):
        return scopes.get("results", scopes.get("app_scopes", []))
    return []


def _find_scope_id(client, scope_name, log):
    """Return scope id or None (logs and returns None when missing)."""
    for s in _get_all_scopes(client):
        if s.get("short_name") == scope_name:
            return s["id"]
    log(f"  Scope '{scope_name}' not found -- already deleted or never created.")
    return None


def _find_workspace_id(client, workspace_name, scope_id, log):
    """Return workspace id under a scope or None."""
    if not scope_id:
        return None
    workspaces = client.get(f"/openapi/v1/applications?app_scope_id={scope_id}")
    if isinstance(workspaces, list):
        for ws in workspaces:
            if ws.get("name") == workspace_name:
                return ws["id"]
    return None


# ---------------------------------------------------------------------------
# Step 1: disable enforcement
# ---------------------------------------------------------------------------

def disable_enforcement(client, workspace_id, log):
    """Turn off enforcement on the workspace.

    Sleeps briefly afterwards because CSW removes host firewall rules
    asynchronously — giving it a moment helps the next deletion calls succeed.
    """
    log(f"  Disabling enforcement...")
    try:
        client.post(f"/openapi/v1/applications/{workspace_id}/disable_enforce", {})
        log("  Enforcement disabled.")
        time.sleep(5)
    except RuntimeError as e:
        log(f"  Note: {e} (may already be disabled -- continuing)")


# ---------------------------------------------------------------------------
# Step 2: delete inventory filters
# ---------------------------------------------------------------------------

def delete_inventory_filters(client, config, log):
    """Delete only the three filters created by Phase 3, matched by EXACT name.

    On shared tenants this exact-match guard is critical — wildcard or
    contains-style matching could wipe out another team's filters.
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

    log(f"  Scanning {len(filters)} filters for: {sorted(FILTER_NAMES)}")
    targets = [f for f in filters if f.get("name", "") in FILTER_NAMES]

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
            # Most common reason: workspace still references this filter.
            log(f"    Could not delete '{f['name']}': {e}")
            log(f"    It may still be referenced by the workspace.")
            log(f"    Delete the workspace first (Step 3) then run Phase 5 again.")


# ---------------------------------------------------------------------------
# Step 3: delete workspace
# ---------------------------------------------------------------------------

def delete_workspace(client, workspace_id, log):
    """Delete the workspace by id."""
    log(f"  Deleting workspace {workspace_id}...")
    try:
        client.delete(f"/openapi/v1/applications/{workspace_id}")
        log("  Workspace deleted.")
    except RuntimeError as e:
        log(f"  Could not delete workspace: {e}")


# ---------------------------------------------------------------------------
# Step 4: delete scope
# ---------------------------------------------------------------------------

def delete_scope(client, scope_id, log):
    """Delete the scope by id."""
    log(f"  Deleting scope {scope_id}...")
    try:
        client.delete(f"/openapi/v1/app_scopes/{scope_id}")
        log("  Scope deleted.")
    except RuntimeError as e:
        log(f"  Could not delete scope: {e}")
        log("  If CSW reports dependencies, check for remaining filters or workspaces in the UI.")


# ---------------------------------------------------------------------------
# Step 5: optionally uninstall agents from VMs
# ---------------------------------------------------------------------------

def uninstall_agents(config, log):
    """SSH into each VM and remove the CSW agent package.

    Tries rpm first then dpkg — covers RHEL-family and Debian-family alike.
    All commands soft-fail (`|| true`) so an absent agent is not an error.
    """
    key_path = os.path.expanduser(config["ssh"]["key_path"])
    timeout  = config["ssh"].get("connect_timeout", 10)

    for vm in config["vms"]:
        try:
            user = _resolve_user(vm, config)
        except RuntimeError as e:
            log(f"  {e}  -- skipping {vm['hostname']}")
            continue

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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(config, log=print, uninstall_agents_flag=False):
    """Public entry point used by the menu orchestrator.

    Args:
        uninstall_agents_flag: when True, also `rpm -e` / `dpkg --purge`
                               the agent on every VM. Default False because
                               most demos re-use the same VMs and reinstalling
                               the agent every time is wasteful.
    """
    log("Phase 5: Teardown")
    log("-" * 40)

    client         = CSWClient()
    workspace_name = config["demo"]["workspace_name"]
    scope_name     = config["demo"]["scope_name"]

    # Resolve ids upfront — saves multiple list calls and lets us short-circuit
    scope_id     = _find_scope_id(client, scope_name, log)
    workspace_id = _find_workspace_id(client, workspace_name, scope_id, log)

    if workspace_id:
        log(f"  Workspace found: {workspace_id}")
    else:
        log("  No workspace found -- may already be deleted.")

    # Step 1
    if workspace_id:
        disable_enforcement(client, workspace_id, log)

    # Step 2 — must run BEFORE step 3 because workspace deletion does not
    # cascade to filters; if filters are deleted last, you'll see them as
    # orphaned objects in the UI.
    delete_inventory_filters(client, config, log)

    # Step 3
    if workspace_id:
        delete_workspace(client, workspace_id, log)

    # Step 4
    if scope_id:
        delete_scope(client, scope_id, log)

    # Step 5 (optional)
    if uninstall_agents_flag:
        log("  Uninstalling agents from VMs...")
        uninstall_agents(config, log)
    else:
        log("  Skipping agent uninstall (re-run Phase 5 with the flag if needed).")

    log("-" * 40)
    log("Phase 5 complete. Demo environment is clean.")
    return {
        "workspace_deleted": workspace_id is not None,
        "scope_deleted"    : scope_id is not None,
    }
