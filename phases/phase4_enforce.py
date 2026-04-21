"""
phases/phase4_enforce.py
Phase 4: Enforce the policy. The blast radius reduction moment.

Handles gracefully:
  - Workspace already analyzed (skip re-analysis)
  - Workspace already enforced (confirm and continue)
  - No policy version available yet (wait and retry)

API capabilities required:
  - app_policy_management
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.csw_client import CSWClient


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_all_scopes(client):
    scopes = client.get("/openapi/v1/app_scopes")
    if isinstance(scopes, list):
        return scopes
    if isinstance(scopes, dict):
        return scopes.get("results", scopes.get("app_scopes", []))
    return []


def _find_workspace(client, workspace_name, scope_name):
    """Return (workspace_id, workspace_dict)."""
    scopes = _get_all_scopes(client)
    scope_id = None
    for s in scopes:
        if s.get("short_name") == scope_name:
            scope_id = s["id"]
            break
    if not scope_id:
        raise ValueError(f"Scope '{scope_name}' not found. Run Phase 1 first.")

    workspaces = client.get(f"/openapi/v1/applications?app_scope_id={scope_id}")
    if isinstance(workspaces, list):
        for ws in workspaces:
            if ws.get("name") == workspace_name:
                return ws["id"], ws
    raise ValueError(f"Workspace '{workspace_name}' not found. Run Phase 3 first.")


def _get_workspace(client, workspace_id):
    return client.get(f"/openapi/v1/applications/{workspace_id}")


# ── Analysis ──────────────────────────────────────────────────────────────────

def _ensure_analysis(client, workspace_id, log):
    """
    Start policy analysis if not already running.
    Skips silently if policies have not changed or analysis is already running.
    """
    ws = _get_workspace(client, workspace_id)

    if ws.get("analysis_enabled"):
        log("  Policy analysis already running -- skipping.")
        return

    log("  Starting policy analysis...")
    try:
        client.post(
            f"/openapi/v1/applications/{workspace_id}/enable_analysis",
            {}
        )
        log("  Analysis started.")
    except RuntimeError as e:
        err = str(e)
        if "not changed" in err or "no changes" in err or "already" in err.lower():
            log("  Analysis already current -- no changes needed.")
        else:
            log(f"  Analysis note: {err}")
            log("  Continuing to enforcement.")


def _wait_for_policy_version(client, workspace_id, log, max_wait=120):
    """
    Wait until the workspace has at least one analyzed policy version (p*).
    Returns True if confirmed, False if timed out.
    """
    log(f"  Waiting for policy version (up to {max_wait}s)...")
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            ws = _get_workspace(client, workspace_id)
            # analyzed_version > 0 means a p* version exists
            if ws.get("analyzed_version", 0) > 0 or ws.get("analysis_enabled"):
                log("  Policy version confirmed.")
                return True
        except Exception as e:
            log(f"  Poll error (retrying): {e}")
        remaining = int(deadline - time.time())
        log(f"  Still waiting... ({remaining}s remaining)")
        time.sleep(10)
    log("  WARNING: Could not confirm policy version. Attempting enforce anyway.")
    return False


# ── Enforcement ───────────────────────────────────────────────────────────────

def _enforce(client, workspace_id, log):
    """
    Enforce the current analyzed version explicitly.

    Always reads analyzed_version from the workspace and passes it as the
    version parameter. This works whether it is the first enforcement (p1)
    or a subsequent one (p5, p12, etc.) and never fails with 'no changes'
    because we are telling CSW exactly which version to enforce.
    """
    ws       = _get_workspace(client, workspace_id)
    analyzed = ws.get("analyzed_version", 0)
    enforced = ws.get("enforced_version")
    active   = ws.get("enforcement_enabled", False)

    log(f"  Workspace: analyzed=p{analyzed}, enforced={'p' + str(enforced) if enforced else 'none'}, active={active}")

    if not analyzed:
        raise RuntimeError(
            "No analyzed policy version found (analyzed_version=0).\n"
            "Run Phase 3 first to create and analyze the workspace."
        )

    # Already enforced at the latest analyzed version -- nothing to do
    if active and enforced == analyzed:
        log(f"  Already enforced at p{analyzed} -- nothing to do.")
        return True

    # Always pass the version explicitly -- CSW requires this
    version_label = f"p{analyzed}"
    log(f"  Enforcing version {version_label}...")

    try:
        client.post(
            f"/openapi/v1/applications/{workspace_id}/enable_enforce",
            {"version": version_label}
        )
        log(f"  Enforce API accepted for {version_label}.")
        return True
    except RuntimeError as e:
        err = str(e)
        if "already" in err.lower():
            log("  Already enforced.")
            return True
        raise


def _wait_for_enforcement(client, workspace_id, log, max_wait=120):
    """Poll until enforcement_enabled is True."""
    log(f"  Waiting for enforcement to propagate (up to {max_wait}s)...")
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            ws = _get_workspace(client, workspace_id)
            if ws.get("enforcement_enabled"):
                return True
        except Exception as e:
            log(f"  Poll error (retrying): {e}")
        time.sleep(10)
        log(f"  Still waiting... ({int(deadline - time.time())}s remaining)")
    return False


# ── Entry point ───────────────────────────────────────────────────────────────

def run(config, log=print):
    """Entry point called by the menu orchestrator."""
    log("Phase 4: ENFORCE POLICY")
    log("-" * 40)
    log("WARNING: This pushes firewall rules to your lab VMs.")
    log("All traffic not matching your allow policy will be DROPPED.")
    log("Catch-all action: DENY")
    log("")

    client        = CSWClient()
    workspace_name = config["demo"]["workspace_name"]
    scope_name    = config["demo"]["scope_name"]
    allowed_port  = config["demo"]["allowed_port"]

    workspace_id, ws = _find_workspace(client, workspace_name, scope_name)
    log(f"Workspace found: {workspace_id}")

    # Step 1: ensure analysis is running
    _ensure_analysis(client, workspace_id, log)

    # Step 2: wait for a policy version to exist
    _wait_for_policy_version(client, workspace_id, log)

    # Step 3: enforce
    enforce_ok = _enforce(client, workspace_id, log)

    # Step 4: confirm
    if enforce_ok:
        confirmed = _wait_for_enforcement(client, workspace_id, log)
    else:
        confirmed = False

    log("")
    if confirmed:
        log("ENFORCEMENT ACTIVE")
        log("")
        log("Policy summary:")
        log(f"  ALLOW  app -> db  TCP/{allowed_port}")
        log(f"  DENY   everything else (catch-all)")
        log("")
        log("What to show the customer now:")
        log("  1. CSW Global Visualization Canvas -- flows flipping to Rejected")
        log("  2. Policy Analysis page -- Escaped gone, Rejected appearing")
        log("  3. Traffic simulator -- connections failing on blocked ports")
        log(f"  4. Only surviving path: app TCP/{allowed_port} -> db")
        log("     That is your blast radius, reduced to a single line.")
    else:
        log("Enforcement status unclear. Check CSW UI:")
        log("  Defend > Segmentation > your workspace > Enforcement tab")

    log("-" * 40)
    log("Phase 4 complete.")
    return {"workspace_id": workspace_id, "enforcement_confirmed": confirmed}
