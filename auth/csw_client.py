"""
auth/csw_client.py
Shared HMAC-SHA256 signing client for Cisco Secure Workload API.
csw-security-toolkit / Beatrice Nnaji

Signing pattern verified working against kubuspov.tetrationcloud.com.
Do not modify the signing logic without re-testing against the API.
"""

import base64
import hashlib
import hmac as _hmac
import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone


def _load_env():
    """Load .env from the tool root directory."""
    env_path = os.path.normpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    )
    if not os.path.exists(env_path):
        return
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

_load_env()


class CSWClient:
    """
    Cisco Secure Workload REST client.
    Signing is a direct copy of the verified working implementation.
    All paths passed to get/post/put/delete must start with /openapi/v1/...
    """

    def __init__(self):
        self.api_key    = os.environ.get("CSW_API_KEY",    "")
        self.api_secret = os.environ.get("CSW_API_SECRET", "")
        self.tenant     = os.environ.get("CSW_TENANT",     "")

        if not self.api_key:
            raise EnvironmentError("CSW_API_KEY is not set.")
        if not self.api_secret:
            raise EnvironmentError("CSW_API_SECRET is not set.")
        if not self.tenant:
            raise EnvironmentError("CSW_TENANT is not set.")

        self.base_url = f"https://{self.tenant}"

    def _sign_request(self, method: str, path: str, body: str = ""):
        """
        Verified working signing logic.
        Returns (timestamp, base64_signature, checksum).
        path must be the full path e.g. /openapi/v1/app_scopes
        """
        now = datetime.now(timezone.utc)
        timestamp = (
            f"{now.year}-"
            f"{str(now.month).zfill(2)}-"
            f"{str(now.day).zfill(2)}T"
            f"{str(now.hour).zfill(2)}:"
            f"{str(now.minute).zfill(2)}:"
            f"{str(now.second).zfill(2)}+0000"
        )

        checksum = hashlib.sha256(body.encode()).hexdigest() if body else ""

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
                hashlib.sha256
            ).digest()
        ).decode()

        return timestamp, signature, checksum

    def _request(self, method: str, path: str, payload: dict = None) -> dict:
        """
        Execute a signed request.
        path must include /openapi/v1 prefix e.g. /openapi/v1/app_scopes
        """
        body = json.dumps(payload) if payload else ""
        timestamp, signature, checksum = self._sign_request(method, path, body)

        url = f"{self.base_url}{path}"
        data = body.encode("utf-8") if body else None

        req = urllib.request.Request(url, data=data, method=method.upper())
        req.add_header("Id",            self.api_key)
        req.add_header("Authorization", signature)
        req.add_header("Timestamp",     timestamp)
        req.add_header("Content-Type",  "application/json")
        req.add_header("X-Tetration-Cksum", checksum)

        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8")
            raise RuntimeError(
                f"HTTP {e.code} on {method.upper()} {path}\n"
                f"Response: {raw}"
            )
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"Connection error on {method.upper()} {path}: {e.reason}"
            )

    # ── Public methods ────────────────────────────────────────────────────────
    # All paths must be full e.g. /openapi/v1/app_scopes

    def get(self, path: str) -> dict:
        return self._request("GET", path)

    def post(self, path: str, payload: dict) -> dict:
        return self._request("POST", path, payload)

    def put(self, path: str, payload: dict) -> dict:
        return self._request("PUT", path, payload)

    def delete(self, path: str) -> dict:
        return self._request("DELETE", path)
