"""
phases/phase1_scope_labels.py
=============================
Phase 1 — Upload labels to lab VMs and create a label-based CSW scope.

What this phase does
--------------------
1. Uploads inventory labels to every VM IP via the User Data Upload API:

       user_Application = <demo.application_label>   (drives the scope query)
       user_role        = app | db                   (drives policy filters)
       user_hostname    = <vm hostname>              (cosmetic)

2. Creates a child scope under `demo.parent_scope_name` whose query is:

       user_Application == <demo.application_label>

   The scope intentionally contains NO IP addresses. Workloads are admitted
   to the scope by what they ARE (their labels), not where they sit.

Order matters: labels are uploaded BEFORE the scope is created so that as
soon as the scope appears in the UI, the workloads are already inside it.

API capabilities required
-------------------------
- app_policy_management   (read scopes, create scope)
- user_data_upload        (POST inventory tags)
"""

import os
import sys

# Make the parent directory importable so `auth.csw_client` resolves whether
# this file is invoked directly or via the menu orchestrator.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from auth.csw_client import CSWClient


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------

def _get_all_scopes(client):
    """Return a flat list of scope dicts, regardless of API response shape.

    CSW returns scopes either as a bare list or wrapped in a dict with a
    `results` / `app_scopes` key depending on cluster version. Normalise
    here so callers can iterate without worrying.
    """
    scopes = client.get("/openapi/v1/app_scopes")
    if isinstance(scopes, list):
        return scopes
    if isinstance(scopes, dict):
        return scopes.get("results", scopes.get("app_scopes", []))
    return []


def _find_scope_by_name(scopes, name):
    """Return the first scope whose short_name OR name matches `name`."""
    for scope in scopes:
        if scope.get("short_name") == name or scope.get("name") == name:
            return scope
    return None


def _find_root_scope_id(client, root_scope_name, log):
    """Locate the cluster's root scope by exact match, then loose match.

    Inventory tags MUST be uploaded under a root scope id. We try an exact
    short_name/name match first; if that fails, we look for a top-level
    scope (no parent) whose name contains `root_scope_name` case-insensitively.
    """
    scopes = _get_all_scopes(client)

    # Exact match — preferred path
    for s in scopes:
        if s.get("short_name") == root_scope_name or s.get("name") == root_scope_name:
            log(f"  Root scope '{root_scope_name}': {s['id']}")
            return s["id"]

    # Fallback: top-level (no parent) scope whose name contains the value
    for s in scopes:
        if root_scope_name.upper() in s.get("name", "").upper() and not s.get("parent_app_scope_id"):
            log(f"  Root scope matched by name: {s.get('name')} ({s['id']})")
            return s["id"]

    raise ValueError(
        f"Root scope '{root_scope_name}' not found.\n"
        f"  Available: {[s.get('short_name') for s in scopes]}"
    )


def _find_parent_scope_id(client, parent_name, log):
    """Locate the parent scope under which the demo scope will be created.

    Unlike root, the parent must already exist. We do NOT auto-create it
    because parent scopes carry permissions and ownership that are unsafe
    to assume.
    """
    scopes = _get_all_scopes(client)
    scope = _find_scope_by_name(scopes, parent_name)
    if not scope:
        raise ValueError(
            f"Parent scope '{parent_name}' not found in CSW.\n"
            f"  Create it manually before running Phase 1.\n"
            f"  Available: {[s.get('short_name') for s in scopes]}"
        )
    log(f"  Parent scope '{parent_name}': {scope['id']}")
    return scope["id"]


def _scope_exists(client, scope_name):
    """Return scope id if a scope with this short_name/name exists, else None."""
    scopes = _get_all_scopes(client)
    scope = _find_scope_by_name(scopes, scope_name)
    return scope["id"] if scope else None


# ---------------------------------------------------------------------------
# Step 1: upload labels
# ---------------------------------------------------------------------------

def upload_labels(client, config, log):
    """Push inventory labels to every VM in `config["vms"]`.

    Per VM, the following labels are uploaded:
        Application = <demo.application_label>   (used by scope query)
        role        = <vm.role>                  (used by policy filters)
        hostname    = <vm.hostname>              (cosmetic)

    The CSW UI shows uploaded labels prefixed with `user_` — for example
    `user_Application`. That prefix is added by CSW automatically; we
    upload them as plain key names.
    """
    root_scope_name   = config["csw"]["root_scope_name"]
    application_label = config["demo"]["application_label"]
    root_scope_id     = _find_root_scope_id(client, root_scope_name, log)

    # The /inventory/tags/<scope_id> endpoint scopes label visibility to
    # the given root scope. Workloads outside it would not see the tag.
    path = f"/openapi/v1/inventory/tags/{root_scope_id}"

    for vm in config["vms"]:
        attributes = {
            "Application": application_label,
            "role"       : vm["role"],
            "hostname"   : vm["hostname"],
        }
        payload = {
            "ip"        : vm["ip"],
            "attributes": attributes,
        }

        log(f"  [{vm['hostname']} / {vm['ip']}]")
        log(f"    Application={application_label}, role={vm['role']}, hostname={vm['hostname']}")

        try:
            client.post(path, payload)
            log(f"    Labels uploaded.")
        except RuntimeError as e:
            # Most common cause: API key lacks the user_data_upload capability
            log(f"    Warning: {e}")
            log(f"    Ensure your API key has user_data_upload capability.")


# ---------------------------------------------------------------------------
# Step 2: create the scope
# ---------------------------------------------------------------------------

def create_scope(client, config, log):
    """Create the demo scope as a child of `parent_scope_name`.

    The scope query is purely label-based:
        type   = "and"
        filter = user_Application == <demo.application_label>

    Idempotent: if the scope already exists, returns its id and no-op.
    """
    scope_name        = config["demo"]["scope_name"]
    parent_name       = config["demo"]["parent_scope_name"]
    application_label = config["demo"]["application_label"]

    # Idempotency: if the scope is already there from a previous run,
    # don't try to create it again (CSW would 409).
    existing = _scope_exists(client, scope_name)
    if existing:
        log(f"  Scope '{scope_name}' already exists ({existing}) -- skipping.")
        return existing

    parent_scope_id = _find_parent_scope_id(client, parent_name, log)

    # Scope query — single equality filter on user_Application. Wrapped in
    # an `and` so it can easily be extended to multi-condition queries later.
    short_query = {
        "type": "and",
        "filters": [
            {
                "type" : "eq",
                "field": "user_Application",
                "value": application_label,
            }
        ]
    }

    payload = {
        "short_name"         : scope_name,
        "description"        : "Auto-created by CSW Blast Radius Demo builder.",
        "short_query"        : short_query,
        "parent_app_scope_id": parent_scope_id,
    }

    log(f"  Creating '{scope_name}' under '{parent_name}'...")
    log(f"  Query: user_Application == {application_label}")

    result   = client.post("/openapi/v1/app_scopes", payload)
    scope_id = result["id"]
    log(f"  Scope created: {scope_id}")
    return scope_id


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(config, log=print):
    """Public entry point used by the menu orchestrator.

    Returns:
        dict with at least {"scope_id": <newly_created_or_existing_scope>}
    """
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
    log(f"TIP: Open CSW > Organize > Scopes and Inventory.")
    log(f"     '{config['demo']['scope_name']}' should appear under "
        f"'{config['demo']['parent_scope_name']}'.")
    log( "     Allow 1-2 minutes for workloads to appear inside the scope.")
    return {"scope_id": scope_id}
