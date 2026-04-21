"""
phases/phase3_workspace_policy.py
Phase 3: Create the CSW workspace and write the demo segmentation policy.

Policies created (all absolute -- no ADM required):
  1. app  -> db   TCP/5432  ALLOW  (the one allowed path)
  2. mgmt -> app  TCP/22    ALLOW  (management SSH to app VM)
  3. mgmt -> db   TCP/22    ALLOW  (management SSH to db VM)
  Catch-all: DENY

Inventory filters created:
  demo-app          matches role=app  (label-based, user_role field)
  demo-db           matches role=db   (label-based, user_role field)
  demo-mgmt-mac      matches IP 10.8.243.16 (IP-based, external host)

The mgmt IP comes from config.yaml demo.mgmt_ip so it never needs
to be changed here directly.

API capabilities required:
  - app_policy_management
"""

import sys
import os

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


def _find_scope_id(client, scope_name):
    scopes = _get_all_scopes(client)
    for s in scopes:
        if s.get("short_name") == scope_name:
            return s["id"]
    raise ValueError(
        f"Scope '{scope_name}' not found. Run Phase 1 first."
    )


def _workspace_exists(client, scope_id, workspace_name):
    workspaces = client.get(f"/openapi/v1/applications?app_scope_id={scope_id}")
    if isinstance(workspaces, list):
        for ws in workspaces:
            if ws.get("name") == workspace_name:
                return ws["id"]
    return None


# ── Inventory filter creation ─────────────────────────────────────────────────

def _get_existing_filters(client):
    """Return list of existing inventory filters."""
    result = client.get("/openapi/v1/filters/inventories")
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        return result.get("results", result.get("data", []))
    return []


def _find_or_create_role_filter(client, scope_id, name, role, log):
    """
    Find or create an inventory filter matching workloads by role label.
    Uses the verified field format: user_role (not user_orchestrator_system/role).
    """
    existing = _get_existing_filters(client)
    for f in existing:
        if f.get("name") == name:
            log(f"    Filter '{name}' already exists ({f['id']})")
            return f["id"]

    payload = {
        "app_scope_id": scope_id,
        "name"        : name,
        "query"       : {
            "type" : "eq",
            "field": "user_role",
            "value": role
        }
    }

    log(f"    Creating role filter '{name}' (user_role={role})...")
    result    = client.post("/openapi/v1/filters/inventories", payload)
    filter_id = result["id"]
    log(f"    Created: {filter_id}")
    return filter_id


def _find_or_create_ip_filter(client, scope_id, name, ip, log):
    """
    Find or create an inventory filter matching a specific IP address.
    Used for external hosts with no CSW agent (e.g. management Mac).
    """
    existing = _get_existing_filters(client)
    for f in existing:
        if f.get("name") == name:
            log(f"    Filter '{name}' already exists ({f['id']})")
            return f["id"]

    payload = {
        "app_scope_id": scope_id,
        "name"        : name,
        "query"       : {
            "type" : "eq",
            "field": "ip",
            "value": ip
        }
    }

    log(f"    Creating IP filter '{name}' for {ip}...")
    result    = client.post("/openapi/v1/filters/inventories", payload)
    filter_id = result["id"]
    log(f"    Created: {filter_id}")
    return filter_id


# ── Workspace + policy creation ───────────────────────────────────────────────

def create_workspace_and_policy(client, config, scope_id, log):
    """
    Create the primary workspace with all demo policies baked in.

    Policies:
      app  -> db   TCP/allowed_port  ALLOW
      mgmt -> app  TCP/22            ALLOW
      mgmt -> db   TCP/22            ALLOW
      catch-all                      DENY
    """
    workspace_name = config["demo"]["workspace_name"]
    allowed_port   = config["demo"]["allowed_port"]
    mgmt_ip        = config["demo"].get("mgmt_ip", "10.8.243.16")

    existing_id = _workspace_exists(client, scope_id, workspace_name)
    if existing_id:
        log(f"  Workspace '{workspace_name}' already exists ({existing_id}) -- skipping.")
        return existing_id

    # ── Step 1: Build all three inventory filters ─────────────────────────────
    log("  Creating inventory filters...")

    app_filter_id = _find_or_create_role_filter(
        client, scope_id, "demo-app", "app", log
    )
    db_filter_id = _find_or_create_role_filter(
        client, scope_id, "demo-db", "db", log
    )
    mgmt_filter_id = _find_or_create_ip_filter(
        client, scope_id, "demo-mgmt-mac", mgmt_ip, log
    )

    log(f"  Filters ready:")
    log(f"    app  filter : {app_filter_id}")
    log(f"    db   filter : {db_filter_id}")
    log(f"    mgmt filter : {mgmt_filter_id}  ({mgmt_ip})")

    # ── Step 2: Build workspace payload with all policies ─────────────────────
    payload = {
        "app_scope_id"      : scope_id,
        "name"              : workspace_name,
        "description"       : "Auto-created by 05_demo_builder. Blast radius demo.",
        "alternate_query_mode": False,
        "absolute_policies" : [
            {
                # Policy 1: app -> db on the demo port (the one allowed path)
                "consumer_filter_id": app_filter_id,
                "provider_filter_id": db_filter_id,
                "action"            : "ALLOW",
                "l4_params"         : [
                    {"proto": 6, "port": [allowed_port, allowed_port]}
                ]
            },
            {
                # Policy 2: management Mac -> app VM on SSH
                "consumer_filter_id": mgmt_filter_id,
                "provider_filter_id": app_filter_id,
                "action"            : "ALLOW",
                "l4_params"         : [
                    {"proto": 6, "port": [22, 22]}
                ]
            },
            {
                # Policy 3: management Mac -> db VM on SSH
                "consumer_filter_id": mgmt_filter_id,
                "provider_filter_id": db_filter_id,
                "action"            : "ALLOW",
                "l4_params"         : [
                    {"proto": 6, "port": [22, 22]}
                ]
            }
        ],
        "catch_all_action": "DENY"
    }

    log(f"  Creating workspace '{workspace_name}'...")
    log(f"    ALLOW  app  -> db   TCP/{allowed_port}")
    log(f"    ALLOW  mgmt -> app  TCP/22  ({mgmt_ip})")
    log(f"    ALLOW  mgmt -> db   TCP/22  ({mgmt_ip})")
    log(f"    DENY   everything else (catch-all)")

    result       = client.post("/openapi/v1/applications", payload)
    workspace_id = result["id"]
    log(f"  Workspace created: {workspace_id}")
    return workspace_id


# ── Policy analysis ───────────────────────────────────────────────────────────

def start_policy_analysis(client, workspace_id, log):
    """
    Start live policy analysis so escaped flows appear before enforcement.
    This is the 'see the footprints before locking the door' moment.
    """
    log("  Starting live policy analysis (NOT enforcing yet)...")
    try:
        client.post(
            f"/openapi/v1/applications/{workspace_id}/enable_analysis",
            {}
        )
        log("  Analysis started.")
    except RuntimeError as e:
        err = str(e)
        if "not changed" in err or "already" in err.lower() or "no changes" in err:
            log("  Analysis already running or policies unchanged -- skipping.")
        else:
            log(f"  Analysis note: {err}")
            log("  Continuing -- you can start analysis manually from the CSW UI.")


# ── Entry point ───────────────────────────────────────────────────────────────

def run(config, log=print):
    """Entry point called by the menu orchestrator."""
    log("Phase 3: Workspace + Policy Creation")
    log("-" * 40)

    client     = CSWClient()
    scope_name = config["demo"]["scope_name"]

    log(f"  Looking up scope: {scope_name}")
    scope_id = _find_scope_id(client, scope_name)
    log(f"  Scope ID: {scope_id}")

    workspace_id = create_workspace_and_policy(client, config, scope_id, log)
    start_policy_analysis(client, workspace_id, log)

    log("-" * 40)
    log("Phase 3 complete.")
    log("TIP: Open CSW > Defend > Segmentation > your workspace > Policy Analysis")
    log("     Let traffic run for a few minutes. Escaped flows will appear.")
    log("     When ready, go back to the menu and choose 4 to enforce.")
    return {"scope_id": scope_id, "workspace_id": workspace_id}
