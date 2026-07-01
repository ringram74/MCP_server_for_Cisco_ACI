import httpx
import asyncio
import os
import time
import json
import base64
from dotenv import load_dotenv
import logging

# load .env file for configuration (base URL, username, chosen auth method)
load_dotenv()

# set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("APICmcp")

# Service name used when looking up secrets in the OS credential manager.
KEYRING_SERVICE = "APICmcp"


class AuthConfigError(RuntimeError):
    """Raised when the selected auth method is missing required configuration."""


class ApicCertAuth(httpx.Auth):
    """
    Signature-based (X.509) authentication for the APIC REST API.

    No password is ever stored or sent. Each request is signed with the user's
    private key; APIC verifies the signature against the certificate attached to
    the local user (``aaaUserCert``). See Cisco's "Signature-Based Transactions".
    """

    def __init__(self, cert_dn: str, private_key):
        self._cert_dn = cert_dn
        self._private_key = private_key

    def auth_flow(self, request):
        # Sign: HTTP method + request path (with query) + body.
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        body = request.content.decode() if request.content else ""
        payload = request.method + request.url.raw_path.decode() + body
        signature = base64.b64encode(
            self._private_key.sign(
                payload.encode(), padding.PKCS1v15(), hashes.SHA256()
            )
        ).decode()

        cookies = {
            "APIC-Certificate-Algorithm": "v1.0",
            "APIC-Certificate-Fingerprint": "fingerprint",
            "APIC-Certificate-DN": self._cert_dn,
            "APIC-Request-Signature": signature,
        }
        request.headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        yield request


class ApicAuthManager:
    _instance = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ApicAuthManager, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    async def initialize(self):
        if self._initialized:
            logger.info("ApicAuthManager already initialized.")
            return

        async with self._lock:
            if self._initialized:
                return

            logger.info("ApicAuthManager initializing...")
            self.apic_base_url = os.getenv("APIC_BASE_URL")
            self.token_endpoint = f"{self.apic_base_url}/api/aaaLogin.json"
            self.username = os.getenv("APIC_USERNAME")

            # Which credential backend to use: cert | keyring | dotenv
            self.auth_method = os.getenv("APIC_AUTH_METHOD", "dotenv").strip().lower()

            self._access_token = None
            self._token_expiry_time = 0
            self._cert_auth = None

            # SSL verification is off by default to preserve prior behaviour.
            # Set APIC_VERIFY_SSL=true (and configure trusted certs) in production.
            verify = os.getenv("APIC_VERIFY_SSL", "false").strip().lower() in (
                "1",
                "true",
                "yes",
            )

            if self.auth_method == "cert":
                self._cert_auth = self._build_cert_auth()
                self._client = httpx.AsyncClient(verify=verify, auth=self._cert_auth)
                logger.info("Auth method: certificate (signature-based, no password).")
            elif self.auth_method in ("keyring", "dotenv"):
                self._password = self._load_password()
                if not self.username or not self._password:
                    logger.error(
                        "APIC_USERNAME or password not available for method "
                        f"'{self.auth_method}'. Authentication will fail. "
                        "Run 'uv run python app/setup.py' to configure credentials."
                    )
                self._client = httpx.AsyncClient(verify=verify)
                logger.info(f"Auth method: {self.auth_method} (session login).")
            else:
                raise AuthConfigError(
                    f"Unknown APIC_AUTH_METHOD '{self.auth_method}'. "
                    "Expected one of: cert, keyring, dotenv."
                )

            self._initialized = True
            logger.info(
                f"ApicAuthManager initialized. Login Endpoint: {self.token_endpoint}"
            )

    def _load_password(self) -> str:
        """Resolve the APIC password from the configured backend."""
        if self.auth_method == "dotenv":
            return os.getenv("APIC_PASSWORD")
        if self.auth_method == "keyring":
            try:
                import keyring
            except ImportError as e:
                raise AuthConfigError(
                    "The 'keyring' package is required for APIC_AUTH_METHOD=keyring. "
                    "Install it with 'pip install keyring'."
                ) from e
            if not self.username:
                raise AuthConfigError(
                    "APIC_USERNAME must be set to look up the keyring secret."
                )
            return keyring.get_password(KEYRING_SERVICE, self.username)
        return None

    def _build_cert_auth(self) -> ApicCertAuth:
        """Load the private key and build the per-request signer for cert auth."""
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
        except ImportError as e:
            raise AuthConfigError(
                "The 'cryptography' package is required for APIC_AUTH_METHOD=cert. "
                "Install it with 'pip install cryptography'."
            ) from e

        key_file = os.getenv("APIC_CERT_KEY_FILE")
        cert_name = os.getenv("APIC_CERT_NAME")
        if not (key_file and cert_name and self.username):
            raise AuthConfigError(
                "Certificate auth requires APIC_USERNAME, APIC_CERT_NAME and "
                "APIC_CERT_KEY_FILE. Run 'uv run python app/setup.py --auth-method cert'."
            )
        if not os.path.isfile(key_file):
            raise AuthConfigError(f"Private key file not found: {key_file}")

        # Optional passphrase for an encrypted key (read from keyring, never disk).
        passphrase = None
        if os.getenv("APIC_CERT_KEY_PASSPHRASE_IN_KEYRING", "").strip().lower() in (
            "1",
            "true",
            "yes",
        ):
            import keyring

            pw = keyring.get_password(KEYRING_SERVICE, f"{self.username}:cert-key")
            passphrase = pw.encode() if pw else None

        with open(key_file, "rb") as f:
            private_key = load_pem_private_key(f.read(), password=passphrase)

        cert_dn = f"uni/userext/user-{self.username}/usercert-{cert_name}"
        return ApicCertAuth(cert_dn, private_key)

    async def get_access_token(self) -> str:
        await self.initialize()

        # Certificate auth signs every request individually; there is no session token.
        if self.auth_method == "cert":
            return None

        logger.info("Checking APIC session token...")
        # Check if the token is still valid. APIC token expiry is in 'sessionTimeoutSeconds'.
        # We add a buffer (e.g., 60 seconds) to re-authenticate before it truly expires.
        if self._access_token and self._token_expiry_time > time.time() + 60:
            logger.info("Using existing APIC session token (still valid).")
            return self._access_token

        logger.info("APIC token expired or not present. Attempting to login...")
        try:
            login_payload = {
                "aaaUser": {
                    "attributes": {"name": self.username, "pwd": self._password}
                }
            }

            response = await self._client.post(
                self.token_endpoint, json=login_payload, timeout=15.0
            )
            response.raise_for_status()
            data = response.json()

            token = (
                data.get("imdata", [{}])[0]
                .get("aaaLogin", {})
                .get("attributes", {})
                .get("token")
            )
            session_timeout = int(
                data.get("imdata", [{}])[0]
                .get("aaaLogin", {})
                .get("attributes", {})
                .get("sessionTimeoutSeconds", 600)
            )  # 600s -> 10m

            if not token:
                raise ValueError("APIC session token not found in login response.")

            self._access_token = token
            self._token_expiry_time = time.time() + session_timeout

            logger.info(
                f"Successfully obtained new APIC session token. Expires in {session_timeout} seconds."
            )
            # httpx manage the 'APIC-Cookie' header from the 'Set-Cookie' response when reusing the client instance
            return self._access_token

        except httpx.HTTPStatusError as e:
            error_details = e.response.text
            try:
                error_details = json.dumps(e.response.json(), indent=2)
            except json.JSONDecodeError:
                pass
            logger.error(
                f"APIC Authentication Error (HTTP Status {e.response.status_code}): {error_details}"
            )
            raise RuntimeError(f"APIC authentication failed: {e.response.text}") from e
        except httpx.RequestError as e:
            logger.error(f"Network Error during APIC authentication: {e}")
            raise RuntimeError(
                f"APIC authentication failed due to network error: {e}"
            ) from e
        except Exception as e:
            logger.error(
                f"An unexpected error occurred during APIC authentication: {e}"
            )
            raise RuntimeError(f"APIC authentication failed: {e}") from e

    async def get_authenticated_client(self) -> httpx.AsyncClient:
        """
        Returns an httpx.AsyncClient ready to talk to APIC.

        For session-based methods (keyring/dotenv) the APIC session cookie is
        managed by httpx after login. For certificate auth the client signs each
        request automatically and no login is performed.
        """
        await self.initialize()
        await self.get_access_token()
        return self._client


apic_auth_manager = ApicAuthManager()
