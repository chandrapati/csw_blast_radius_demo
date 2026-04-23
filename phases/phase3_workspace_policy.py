"""
phases/phase3_workspace_policy.py
=================================
Phase 3 — Create the CSW workspace and write the demo segmentation policy.

Policy model
------------
All policies are ABSOLUTE (highest precedence in CSW). We use absolute
policies — not ADM-discovered — because the demo environment is fresh and
we want to declare intent directly without waiting for traffic discovery.

    +----------------+--------------+----------+---------+
    | Consumer       | Provider     | Port     | Action  |
    +----------------+--------------+----------+---------+
    | role=app VM    | role=db VM   | TCP/<P>  | ALLOW   |
    | mgmt host IP   | role=app VM  | TCP/<M>  | ALLOW   |
    | mgmt host IP   | role=db VM   | TCP/<M>  | ALLOW   |
    | (catch-all)    | (catch-all)  | any      | DENY    |
    +----------------+--------------+----------+---------+

`<P>` is `demo.allowed_port`, `<M>` is `demo.mgmt_port` (typically 22).

Inventory filters created
-------------------------
    demo-app          user_role == app             (label-based)
    demo-db           user_role == db              (label-based)
    demo-mgmt-host    ip       == demo.mgmt_ip     (IP-based, off-cluster host)

The mgmt filter is IP-based because the operator's laptop has no CSW agent —
a label query would never match it.

Idempotency
-----------
Filter and workspace creation both check for existing objects by exact name
and reuse them when present. Phase 5 (teardown) deletes them by the same names.

API capabilities required
-------------------------
- app_policy_management
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.csw_client import CSWClient


# Names of inventory filters created by this phase. Phase 5 references the
# SAME constants when cleaning up — keep them in sync.
FILTER_APP_NAME  = "demo-app"
FILTER_DB_NAME   = "demo-db"
FILTER_MGMT_NAME = "demo-mgmt-host"


# ---------------------------------------------------------------------------
# Scope + workspace helpers
# ---------------------------------------------------------------------------

def _get_all_scopes(client):
    """Normalise CSW scope listings to a flat list (see phase1 for rationale)."""
    scopes = client.get("/openapi/v1/app_scopes")
    if isinstance(scopes, list):
        return scopes
    if isinstance(scopes, dict):
        return scopes.get("results", scopes.get("app_scopes", []))
    return []


def _find_scope_id(client, scope_name):
    """Return the id of the scope with this short_name, or raise."""
    scopes = _get_all_scopes(client)
    for s in scopes:
        if s.get("short_name") == scope_name:
            return s["id"]
    raise ValueError(f"Scope '{scope_name}' not found. Run Phase 1 first.")


def _workspace_exists(client, scope_id, workspace_name):
    """Return workspace id if a workspace with this name exists in scope, else None."""
    workspaces = client.get(f"/openapi/v1/applications?app_scope_id={scope_id}")
    if isinstance(workspaces, list):
        for ws in workspaces:
            if ws.get("name") == workspace_name:
                return ws["id"]
    return None


# ---------------------------------------------------------------------------
# Inventory filter helpers
# ---------------------------------------------------------------------------

def _get_existing_filters(client):
    """Return the cluster's inventory filters (normalised list)."""
    result = client.get("/openapi/v1/filters/inventories")
    if isinstance(result, list):
        return result
    if isinstance(result, dict):
        return result.get("results", result.get("data", []))
    return []


def _find_or_create_role_filter(client, scope_id, name, role, log):
    """Find filter by exact name; create if missing.

    Field name `user_role` is the verified working format — CSW prefixes
    user-uploaded labels with `user_` for filter queries. Other fields like
    `user_orchestrator_system/role` exist but apply only to discovered
    workloads from orchestrators (k8s, vCenter, etc.).
    """
    for f in _get_existing_filters(client):
        if f.get("name") == name:
            log(f"    Filter '{name}' already exists ({f['id']})")
            return f["id"]

    payload = {
        "app_scope_id": scope_id,
        "name"        : name,
        "query"       : {
            "type" : "eq",
            "field": "user_role",
            "value": role,
        },
    }

    log(f"    Creating role filter '{name}' (user_role={role})...")
    result = client.post("/openapi/v1/filters/inventories", payload)
    log(f"    Created: {result['id']}")
    return result["id"]


def _find_or_create_ip_filter(client, scope_id, name, ip, log):
    """Find filter by exact name; create an IP-based filter if missing.

    Used for hosts that have NO CSW agent (e.g. operator's laptop). CSW
    cannot match them by label — they need to be referenced by IP.
    """
    for f in _get_existing_filters(client):
        if f.get("name") == name:
            log(f"    Filter '{name}' already exists ({f['id']})")
            return f["id"]

    payload = {
        "app_scope_id": scope_id,
        "name"        : name,
        "query"       : {
            "type" : "eq",
            "field": "ip",
            "value": ip,
        },
    }

    log(f"    Creating IP filter '{name}' for {ip}...")
    result = client.post("/openapi/v1/filters/inventories", payload)
    log(f"    Created: {result['id']}")
    return result["id"]


# ---------------------------------------------------------------------------
# Workspace + policy creation
# ---------------------------------------------------------------------------

def create_workspace_and_policy(client, config, scope_id, log):
    """Create the demo workspace with all absolute policies and a catch-all DENY."""
    workspace_name = config["demo"]["workspace_name"]
    allowed_port   = config["demo"]["allowed_port"]
    mgmt_port      = config["demo"].get("mgmt_port", 22)

    # mgmt_ip is REQUIRED — refusing to fall back to a baked-in default keeps
    # the demo from accidentally allowing the wrong host.
    mgmt_ip = config["demo"].get("mgmt_ip")
    if not mgmt_ip:
        raise ValueError(
            "demo.mgmt_ip is not set in config.yaml. This is the operator's IP "
            "that retains SSH access after enforcement. Set it explicitly — "
            "there is intentionally no default."
        )

    # Idempotency — bail out cleanly if the workspace is already present
    existing_id = _workspace_exists(client, scope_id, workspace_name)
    if existing_id:
        log(f"  Workspace '{workspace_name}' already exists ({existing_id}) -- skipping.")
        return existing_id

    # ------------------ Step 1: Build the three inventory filters ----------
    log("  Creating inventory filters...")
    app_filter_id  = _find_or_create_role_filter(client, scope_id, FILTER_APP_NAME,  "app", log)
    db_filter_id   = _find_or_create_role_filter(client, scope_id, FILTER_DB_NAME,   "db",  log)
    mgmt_filter_id = _find_or_create_ip_filter  (client, scope_id, FILTER_MGMT_NAME, mgmt_ip, log)

    log(f"  Filters ready:")
    log(f"    app  filter : {app_filter_id}")
    log(f"    db   filter : {db_filter_id}")
    log(f"    mgmt filter : {mgmt_filter_id}  ({mgmt_ip})")

    # ------------------ Step 2: Workspace + absolute policies --------------
    # CSW protocol numbers: 6 == TCP. l4_params port range is inclusive.
    payload = {
        "app_scope_id"        : scope_id,
        "name"                : workspace_name,
        "description"         : "Auto-created by CSW Blast Radius Demo builder.",
        "alternate_query_mode": False,
        "absolute_policies"   : [
            # Policy 1 — the only allowed cross-tier path
            {
                "consumer_filter_id": app_filter_id,
                "provider_filter_id": db_filter_id,
                "action"            : "ALLOW",
                "l4_params"         : [{"proto": 6, "port": [allowed_port, allowed_port]}],
            },
            # Policy 2 — operator SSH to app VM
            {
                "consumer_filter_id": mgmt_filter_id,
                "provider_filter_id": app_filter_id,
                "action"            : "ALLOW",
                "l4_params"         : [{"proto": 6, "port": [mgmt_port, mgmt_port]}],
            },
            # Policy 3 — operator SSH to db VM
            {
                "consumer_filter_id": mgmt_filter_id,
                "provider_filter_id": db_filter_id,
                "action"            : "ALLOW",
                "l4_params"         : [{"proto": 6, "port": [mgmt_port, mgmt_port]}],
            },
        ],
        # Anything not matched by the absolute policies above is dropped —
        # that is the entire point of the blast radius demo.
        "catch_all_action": "DENY",
    }

    log(f"  Creating workspace '{workspace_name}'...")
    log(f"    ALLOW  app  -> db   TCP/{allowed_port}")
    log(f"    ALLOW  mgmt -> app  TCP/{mgmt_port}  ({mgmt_ip})")
    log(f"    ALLOW  mgmt -> db   TCP/{mgmt_port}  ({mgmt_ip})")
    log(f"    DENY   everything else (catch-all)")

    result       = client.post("/openapi/v1/applications", payload)
    workspace_id = result["id"]
    log(f"  Workspace created: {workspace_id}")
    return workspace_id


# ---------------------------------------------------------------------------
# Policy analysis
# ---------------------------------------------------------------------------

def start_policy_analysis(client, workspace_id, log):
    """Enable live policy analysis on the new workspace.

    With analysis ON but enforcement still OFF, CSW classifies every flow
    as 'permitted', 'rejected', or 'escaped' against the policy WITHOUT
    actually blocking anything. That gives the operator a 'see the
    footprints before locking the door' visualization for the customer.
    """
    log("  Starting live policy analysis (NOT enforcing yet)...")
    try:
        client.post(f"/openapi/v1/applications/{workspace_id}/enable_analysis", {})
        log("  Analysis started.")
    except RuntimeError as e:
        err = str(e)
        # CSW returns errors like "policies have not changed" if you call
        # enable_analysis twice with the same payload — those are benign.
        if "not changed" in err or "already" in err.lower() or "no changes" in err:
            log("  Analysis already running or policies unchanged -- skipping.")
        else:
            log(f"  Analysis note: {err}")
            log("  Continuing -- you can start analysis manually from the CSW UI.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(config, log=print):
    """Public entry point used by the menu orchestrator."""
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
    log("     When ready, return to the menu and choose 4 to enforce.")
    return {"scope_id": scope_id, "workspace_id": workspace_id}
