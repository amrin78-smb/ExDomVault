import os

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import app.geoip

KEY_ID = "0b7c6a52-3f1e-4c55-9d1a-2f6f2b7e9a10"


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def key_file(tmp_path, private_key) -> str:
    path = tmp_path / "worker.key"
    path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)
    return str(path)


@pytest.fixture
def valid_env(key_file, tmp_path) -> dict[str, str]:
    return {
        "EXDV_API_BASE_URL": "https://exdomainvault.example.com/",
        "EXDV_WORKER_ID": "home-worker-01",
        "EXDV_KEY_ID": KEY_ID,
        "EXDV_PRIVATE_KEY_FILE": key_file,
        "EXDV_HEALTH_FILE": str(tmp_path / "health.json"),
    }


@pytest.fixture(autouse=True)
def _no_live_geoip_download(monkeypatch):
    """Tests never reach db-ip.com: GeoIp without an injected transport gets one that fails."""

    def refuse(request):
        raise httpx.ConnectError("network disabled in tests", request=request)

    monkeypatch.setattr(app.geoip, "_default_transport", lambda: httpx.MockTransport(refuse))
