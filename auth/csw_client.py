"""
auth/csw_client.py
==================
Shared HMAC-SHA256 signing client for the Cisco Secure Workload (CSW / Tetration)
OpenAPI.

Why this exists
---------------
Every script in this toolkit needs to talk to the CSW REST API. CSW requires every
request to be signed with HMAC-SHA256 over a canonical request line. Centralising
that signing logic here means:

  - every phase calls the same battle-tested code path
  - credentials live in exactly one place (env vars, loaded from .env)
  - new endpoints are one-line GET/POST/PUT/DELETE calls

Signing contract (do not modify without re-testing against a live cluster):

    timestamp       = YYYY-MM-DDTHH:MM:SS+0000   (UTC, explicit +0000 offset)
    checksum        = sha256_hex(body_bytes)     (empty string for GET/DELETE)
    string_to_sign  = METHOD\\nPATH\\nCHECKSUM\\napplication/json\\nTIMESTAMP\\n
    signature       = base64( HMAC-SHA256(secret, string_to_sign) )

Required headers:

    Id                 - API key identifier
    Authorization      - signature (no scheme prefix)
    Timestamp          - same value used in the signature
    Content-Type       - application/json
    X-Tetration-Cksum  - body checksum (sent for all requests; empty when no body)

Environment variables (loaded from .env at the project root):

    CSW_API_KEY     [required] API key identifier (hex string from CSW UI)
    CSW_API_SECRET  [required] Paired API secret  (hex string from CSW UI)
    CSW_TENANT      [required] Cluster hostname e.g. customer.tetrationcloud.com
                               (no scheme, no path)

    CSW_VERIFY_SSL  [optional] "false" disables TLS verification. Use only for
                               self-signed lab clusters or behind a corporate
                               TLS-inspection proxy. Default: "true".
"""

import base64
import hashlib
import hmac as _hmac
import json
import os
import ssl
import urllib.request
import urllib.error
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# .env loading
# ---------------------------------------------------------------------------

def _load_env():
    """Load `KEY=value` pairs from .env at the project root.

    Lines beginning with `#` and blank lines are ignored. Quotes around values
    are stripped. Existing environment variables take precedence (so the user
    can always override via `export VAR=...` before invoking).
    """
    env_path = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    )
    if not os.path.exists(env_path):
        return

    with open(env_path) as f:
        for line in f:
            line = line.strip()
            # Skip comments, blanks, and malformed lines
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key   = key.strip()
            # Allow either single- or double-quoted values
            value = value.strip().strip('"').strip("'")
            # Don't override values already in the environment
            if key and key not in os.environ:
                os.environ[key] = value


# Load .env immediately on import so any module that imports CSWClient gets
# credentials transparently — no need to call load_dotenv() in every script.
_load_env()


# ---------------------------------------------------------------------------
# CSW API client
# ---------------------------------------------------------------------------

class CSWClient:
    """Cisco Secure Workload REST client with HMAC-SHA256 request signing.

    Usage:
        client = CSWClient()
        scopes  = client.get("/openapi/v1/app_scopes")
        new_ws  = client.post("/openapi/v1/applications", payload)
        client.delete(f"/openapi/v1/app_scopes/{scope_id}")

    All paths must include the `/openapi/v1/...` prefix. The base URL
    (`https://<tenant>`) is prepended automatically.

    Errors are raised as RuntimeError with the HTTP status, request line, and
    response body so callers can present meaningful messages or log them
    verbatim.
    """

    def __init__(self):
        self.api_key    = os.environ.get("CSW_API_KEY",    "")
        self.api_secret = os.environ.get("CSW_API_SECRET", "")
        self.tenant     = os.environ.get("CSW_TENANT",     "")

        # Fail fast with actionable messages — easier to diagnose than a 401
        if not self.api_key:
            raise EnvironmentError(
                "CSW_API_KEY is not set. Copy .env.example to .env and fill in "
                "the API key from CSW > Platform > API Keys."
            )
        if not self.api_secret:
            raise EnvironmentError(
                "CSW_API_SECRET is not set. Copy .env.example to .env and fill in "
                "the API secret paired with CSW_API_KEY."
            )
        if not self.tenant:
            raise EnvironmentError(
                "CSW_TENANT is not set. Set it in .env to your cluster hostname "
                "(e.g. customer.tetrationcloud.com — no scheme, no path)."
            )

        self.base_url = f"https://{self.tenant}"

        # TLS verification — default ON. Disable only for self-signed clusters
        # or when a corporate TLS-inspection proxy breaks chain validation.
        self.verify_ssl = os.environ.get("CSW_VERIFY_SSL", "true").lower() != "false"

        # Pre-build the SSL context once so every request reuses it
        if self.verify_ssl:
            self._ssl_ctx = ssl.create_default_context()
        else:
            # Insecure: disables hostname + certificate-chain validation.
            # Mitigation: only use for ephemeral lab clusters; rotate API keys
            # when finished; never use against production tenants.
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode    = ssl.CERT_NONE

    # ------------------------------------------------------------------ signing

    def _sign_request(self, method: str, path: str, body: str = ""):
        """Build the HMAC-SHA256 signature for one request.

        Args:
            method: Upper-case HTTP method (GET/POST/PUT/DELETE).
            path:   Full request path including /openapi/v1 prefix and any
                    query string. The path used to sign MUST be byte-identical
                    to the path in the URL line.
            body:   Serialised request body (JSON string) or "" for none.

        Returns:
            (timestamp, base64_signature, body_checksum_hex)
        """
        # CSW expects ISO 8601 timestamp in UTC with explicit +0000 offset.
        # Building it manually keeps the format predictable across Python
        # versions and locales.
        now = datetime.now(timezone.utc)
        timestamp = (
            f"{now.year}-"
            f"{str(now.month).zfill(2)}-"
            f"{str(now.day).zfill(2)}T"
            f"{str(now.hour).zfill(2)}:"
            f"{str(now.minute).zfill(2)}:"
            f"{str(now.second).zfill(2)}+0000"
        )

        # Body checksum is the sha256 hex of the raw bytes; empty string when
        # there is no body (CSW treats GET/DELETE this way).
        checksum = hashlib.sha256(body.encode()).hexdigest() if body else ""

        # Canonical request — newline-separated, trailing newline required
        string_to_sign = (
            f"{method}\n"
            f"{path}\n"
            f"{checksum}\n"
            f"application/json\n"
            f"{timestamp}\n"
        )

        signature = base64.b64encode(
            _hmac.new(
                self.api_secret.encode(),
                string_to_sign.encode(),
                hashlib.sha256,
            ).digest()
        ).decode()

        return timestamp, signature, checksum

    # ----------------------------------------------------------------- request

    def _request(self, method: str, path: str, payload: dict = None) -> dict:
        """Execute a signed request and return the decoded JSON response.

        Raises:
            RuntimeError on non-2xx HTTP status or connection failure. The
            exception message includes the method, path, and CSW's response
            body when available — enough to diagnose 99% of API issues.
        """
        # Serialise payload so the same byte string is used for both the
        # checksum and the body sent on the wire. Mismatches here cause
        # 401 "signature mismatch" errors that are notoriously hard to debug.
        body = json.dumps(payload) if payload else ""
        timestamp, signature, checksum = self._sign_request(method, path, body)

        url  = f"{self.base_url}{path}"
        data = body.encode("utf-8") if body else None

        req = urllib.request.Request(url, data=data, method=method.upper())
        req.add_header("Id",                self.api_key)
        req.add_header("Authorization",     signature)
        req.add_header("Timestamp",         timestamp)
        req.add_header("Content-Type",      "application/json")
        req.add_header("X-Tetration-Cksum", checksum)

        try:
            # Reuse the pre-built SSL context (verifying or not, depending
            # on CSW_VERIFY_SSL).
            with urllib.request.urlopen(req, context=self._ssl_ctx) as resp:
                raw = resp.read().decode("utf-8")
                # Empty body is a valid 2xx response for some endpoints
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            # 4xx / 5xx — surface CSW's error body so callers can show it
            raw = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"HTTP {e.code} on {method.upper()} {path}\n"
                f"Response: {raw}"
            )
        except urllib.error.URLError as e:
            # DNS / connection refused / TLS handshake failure
            raise RuntimeError(
                f"Connection error on {method.upper()} {path}: {e.reason}"
            )

    # ---------------------------------------------------------------- public

    # Thin convenience wrappers — keep callers readable.
    # All paths must be the full `/openapi/v1/...` form.

    def get(self, path: str) -> dict:
        return self._request("GET", path)

    def post(self, path: str, payload: dict) -> dict:
        return self._request("POST", path, payload)

    def put(self, path: str, payload: dict) -> dict:
        return self._request("PUT", path, payload)

    def delete(self, path: str) -> dict:
        return self._request("DELETE", path)
