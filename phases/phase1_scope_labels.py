"""
phases/phase1_scope_labels.py
Phase 1: Upload labels to VMs, then create a label-based scope.

Order of operations (intentional):
  1. Upload labels to each VM IP via the inventory tags API
  2. Create BRD-Lab scope under Beatrice using a label query

Label strategy:
  Application = DemoBRD  (application label -- used as the scope query)
  role        = app | db  (used in workspace policy filters)
  hostname    = <name>

Scope query for BRD-Lab:
    Application = DemoBRD

The parent scope (Beatrice) must already exist in CSW.
This phase only creates BRD-Lab as a child under it.

API capabilities required:
  - app_policy_management
  - user_data_upload
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.csw_client import CSWClient


# ── Scope helpers ─────────────────────────────────────────────────────────────

def _get_all_scopes(client):
    scopes = client.get("/openapi/v1/app_scopes")
    if isinstance(scopes, list):
        return scopes
    if isinstance(scopes, dict):
        return scopes.get("results", scopes.get("app_scopes", []))
    return []


def _find_scope_by_name(scopes, name):
    for scope in scopes:
        if scope.get("short_name") == name or scope.get("name") == name:
            return scope
    return None


def _find_root_scope_id(client, root_scope_name, log):
    scopes = _get_all_scopes(client)
    # Exact match first
    for s in scopes:
        if s.get("short_name") == root_scope_name or s.get("name") == root_scope_name:
            log(f"  Root scope '{root_scope_name}': {s['id']}")
            return s["id"]
    # Fallback: name contains root_scope_name and has no parent (is root)
    for s in scopes:
        if root_scope_name.upper() in s.get("name", "").upper() and not s.get("parent_app_scope_id"):
            log(f"  Root scope matched by name: {s.get('name')} ({s['id']})")
            return s["id"]
    raise ValueError(
        f"Root scope '{root_scope_name}' not found.\n"
        f"  Available: {[s.get('short_name') for s in scopes]}"
    )


def _find_parent_scope_id(client, parent_name, log):
    scopes = _get_all_scopes(client)
    scope = _find_scope_by_name(scopes, parent_name)
    if not scope:
        raise ValueError(
            f"Parent scope '{parent_name}' not found in CSW.\n"
            f"  Make sure it exists before running Phase 1.\n"
            f"  Available: {[s.get('short_name') for s in scopes]}"
        )
    log(f"  Parent scope '{parent_name}': {scope['id']}")
    return scope["id"]


def _scope_exists(client, scope_name):
    scopes = _get_all_scopes(client)
    scope = _find_scope_by_name(scopes, scope_name)
    return scope["id"] if scope else None


# ── Label upload ──────────────────────────────────────────────────────────────

def upload_labels(client, config, log):
    """
    Upload labels to each VM IP via the inventory tags API.
    Matches the verified push_label() pattern exactly.

    Labels applied:
      Beatrice    = TRUE
      Application = DemoBRD
      role        = app | db
      hostname    = <vm hostname>
    """
    root_scope_name = config["csw"]["root_scope_name"]
    root_scope_id   = _find_root_scope_id(client, root_scope_name, log)
    path            = f"/openapi/v1/inventory/tags/{root_scope_id}"

    for vm in config["vms"]:
        attributes = {
            "Application": "DemoBRD",
            "role"       : vm["role"],
            "hostname"   : vm["hostname"],
        }

        payload = {
            "ip"        : vm["ip"],
            "attributes": attributes,
        }

        log(f"  [{vm['hostname']} / {vm['ip']}]")
        log(f"    Application=DemoBRD, role={vm['role']}, hostname={vm['hostname']}")

        try:
            client.post(path, payload)
            log(f"    Labels uploaded.")
        except RuntimeError as e:
            log(f"    Warning: {e}")
            log(f"    Ensure your API key has user_data_upload capability.")


# ── Scope creation ────────────────────────────────────────────────────────────

def create_scope(client, config, log):
    """
    Create BRD-Lab as a child of the DusLab scope.
    Scope query: Beatrice=TRUE AND Application=DemoBRD
    Label-based -- no IP addresses in the scope definition.
    """
    scope_name  = config["demo"]["scope_name"]
    parent_name = config["demo"].get("parent_scope_name", "DusLab")

    existing = _scope_exists(client, scope_name)
    if existing:
        log(f"  Scope '{scope_name}' already exists ({existing}) -- skipping.")
        return existing

    parent_scope_id = _find_parent_scope_id(client, parent_name, log)

    short_query = {
        "type": "and",
        "filters": [
            {
                "type" : "eq",
                "field": "user_Application",
                "value": "DemoBRD"
            }
        ]
    }

    payload = {
        "short_name"         : scope_name,
        "description"        : "Auto-created by 05_demo_builder. Blast radius demo.",
        "short_query"        : short_query,
        "parent_app_scope_id": parent_scope_id,
    }

    log(f"  Creating '{scope_name}' under '{parent_name}'...")
    log(f"  Query: Application=DemoBRD")

    result    = client.post("/openapi/v1/app_scopes", payload)
    scope_id  = result["id"]
    log(f"  Scope created: {scope_id}")
    return scope_id


# ── Entry point ───────────────────────────────────────────────────────────────

def run(config, log=print):
    """Entry point called by the menu orchestrator."""
    log("Phase 1: Labels + Scope")
    log("-" * 40)

    client = CSWClient()

    log("Step 1: Uploading labels to VMs...")
    upload_labels(client, config, log)
    log("")

    log("Step 2: Creating label-based scope in CSW...")
    scope_id = create_scope(client, config, log)

    log("-" * 40)
    log("Phase 1 complete.")
    log("TIP: Open CSW > Organize > Scopes and Inventory.")
    log("     BRD-Lab should appear under DusLab.")
    log("     Allow 1-2 minutes for workloads to appear inside the scope.")
    return {"scope_id": scope_id}