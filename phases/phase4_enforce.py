"""
phases/phase4_enforce.py
========================
Phase 4 — Enforce the segmentation policy. The blast-radius reduction moment.

How enforcement works in CSW
----------------------------
- A workspace has TWO version cursors:
    analyzed_version  (`p1`, `p2`, ...) — the policy CSW analyses against
    enforced_version  (`p1`, `p2`, ...) — the policy CSW actively pushes
- Calling `enable_enforce` with `{"version": "pN"}` tells CSW exactly which
  analyzed version to push to host firewalls.
- Always pass the version explicitly. Re-enforcing without a version
  number returns "no changes since last enforce" on a fresh workspace.

This phase
----------
1. Locate the workspace by `(scope, name)`.
2. Make sure analysis is running (it should be — Phase 3 starts it).
3. Wait until `analyzed_version > 0` so we have something to enforce.
4. Call `enable_enforce` passing the latest `analyzed_version`.
5. Poll until `enforcement_enabled == True`.

Idempotent: re-running when already enforced at the latest version is a no-op.

API capabilities required
-------------------------
- app_policy_management
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.csw_client import CSWClient


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def _get_all_scopes(client):
    """Normalise CSW scope listings to a flat list."""
    scopes = client.get("/openapi/v1/app_scopes")
    if isinstance(scopes, list):
        return scopes
    if isinstance(scopes, dict):
        return scopes.get("results", scopes.get("app_scopes", []))
    return []


def _find_workspace(client, workspace_name, scope_name):
    """Return (workspace_id, workspace_dict) for the named workspace.

    Raises ValueError if the scope or workspace is missing.
    """
    scopes   = _get_all_scopes(client)
    scope_id = next((s["id"] for s in scopes if s.get("short_name") == scope_name), None)
    if not scope_id:
        raise ValueError(f"Scope '{scope_name}' not found. Run Phase 1 first.")

    workspaces = client.get(f"/openapi/v1/applications?app_scope_id={scope_id}")
    if isinstance(workspaces, list):
        for ws in workspaces:
            if ws.get("name") == workspace_name:
                return ws["id"], ws
    raise ValueError(f"Workspace '{workspace_name}' not found. Run Phase 3 first.")


def _get_workspace(client, workspace_id):
    """Fetch the latest workspace state (analyzed_version, enforced_version, ...)."""
    return client.get(f"/openapi/v1/applications/{workspace_id}")


# ---------------------------------------------------------------------------
# Analysis enablement
# ---------------------------------------------------------------------------

def _ensure_analysis(client, workspace_id, log):
    """Start policy analysis if not already running.

    Phase 3 normally enables analysis. This is a defensive no-op safety
    net for cases where the operator skipped or aborted Phase 3.
    """
    ws = _get_workspace(client, workspace_id)

    if ws.get("analysis_enabled"):
        log("  Policy analysis already running -- skipping.")
        return

    log("  Starting policy analysis...")
    try:
        client.post(f"/openapi/v1/applications/{workspace_id}/enable_analysis", {})
        log("  Analysis started.")
    except RuntimeError as e:
        err = str(e)
        if "not changed" in err or "no changes" in err or "already" in err.lower():
            log("  Analysis already current -- no changes needed.")
        else:
            log(f"  Analysis note: {err}")
            log("  Continuing to enforcement.")


def _wait_for_policy_version(client, workspace_id, log, max_wait=120):
    """Poll until the workspace exposes at least one analyzed policy version.

    Returns True once `analyzed_version > 0` is observed (or analysis flag
    flipped on), False on timeout. Even on timeout we proceed to enforce —
    sometimes CSW propagates the version asynchronously and the call works
    a moment later.
    """
    log(f"  Waiting for policy version (up to {max_wait}s)...")
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            ws = _get_workspace(client, workspace_id)
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


# ---------------------------------------------------------------------------
# Enforcement
# ---------------------------------------------------------------------------

def _enforce(client, workspace_id, log):
    """Push the workspace's latest analyzed version to host firewalls.

    CSW resolves `enable_enforce` payloads as follows:
      - `{"version": "pN"}` enforces exactly version N  <-- we always do this
      - `{}`                 enforces the next pending change (often errors)

    Returns True if enforcement was accepted (or already active at the
    requested version). Raises on real failures.
    """
    ws       = _get_workspace(client, workspace_id)
    analyzed = ws.get("analyzed_version", 0)
    enforced = ws.get("enforced_version")
    active   = ws.get("enforcement_enabled", False)

    log(f"  Workspace: analyzed=p{analyzed}, "
        f"enforced={'p' + str(enforced) if enforced else 'none'}, "
        f"active={active}")

    if not analyzed:
        raise RuntimeError(
            "No analyzed policy version found (analyzed_version=0).\n"
            "Run Phase 3 first to create and analyze the workspace."
        )

    if active and enforced == analyzed:
        log(f"  Already enforced at p{analyzed} -- nothing to do.")
        return True

    version_label = f"p{analyzed}"
    log(f"  Enforcing version {version_label}...")

    try:
        client.post(
            f"/openapi/v1/applications/{workspace_id}/enable_enforce",
            {"version": version_label},
        )
        log(f"  Enforce API accepted for {version_label}.")
        return True
    except RuntimeError as e:
        # Soft-success path: race conditions where CSW already flipped on
        # enforcement between our pre-check and the call.
        if "already" in str(e).lower():
            log("  Already enforced.")
            return True
        raise


def _wait_for_enforcement(client, workspace_id, log, max_wait=120):
    """Poll until the workspace reports enforcement_enabled=True."""
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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(config, log=print):
    """Public entry point used by the menu orchestrator."""
    log("Phase 4: ENFORCE POLICY")
    log("-" * 40)
    log("WARNING: This pushes firewall rules to your lab VMs.")
    log("All traffic not matching your allow policy will be DROPPED.")
    log("Catch-all action: DENY")
    log("")

    client         = CSWClient()
    workspace_name = config["demo"]["workspace_name"]
    scope_name     = config["demo"]["scope_name"]
    allowed_port   = config["demo"]["allowed_port"]

    workspace_id, _ = _find_workspace(client, workspace_name, scope_name)
    log(f"Workspace found: {workspace_id}")

    # Step 1: ensure analysis is running (defensive)
    _ensure_analysis(client, workspace_id, log)

    # Step 2: wait until there is something to enforce
    _wait_for_policy_version(client, workspace_id, log)

    # Step 3: enforce explicitly at the latest analyzed version
    enforce_ok = _enforce(client, workspace_id, log)

    # Step 4: confirm enforcement activated end-to-end
    confirmed = _wait_for_enforcement(client, workspace_id, log) if enforce_ok else False

    log("")
    if confirmed:
        log("ENFORCEMENT ACTIVE  --  blast radius contained.")
        log("")
        log("Policy summary:")
        log(f"  ALLOW  app -> db  TCP/{allowed_port}   (the business path)")
        log(f"  DENY   everything else (catch-all -- lateral movement stops here)")
        log("")
        log("What to show the customer now (in this order):")
        log("  1. Traffic simulator -- east-west probes flipping to BLOCK,")
        log(f"     only TCP/{allowed_port} survives. That IS the blast radius now.")
        log("  2. Menu -> N -- the actual nftables rules CSW just wrote into")
        log("     the host kernel of each VM. Not a network choke point --")
        log("     the workload's own firewall.")
        log("  3. CSW UI -> Policy Analysis -- every dropped probe shows up")
        log("     here as a Rejected flow with consumer/provider/port/timestamp.")
        log("  4. CSW UI -> Workload identity card -> Concrete Policies tab --")
        log("     prove the abstract policy was computed for this specific VM.")
    else:
        log("Enforcement status unclear. Check CSW UI:")
        log("  Defend > Segmentation > your workspace > Enforcement tab")

    log("-" * 40)
    log("Phase 4 complete.")
    return {"workspace_id": workspace_id, "enforcement_confirmed": confirmed}
