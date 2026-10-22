import base64
import hashlib
import json

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import __version__
from app.client import (
    AuthError,
    LeaseLost,
    RequestRejected,
    Signer,
    TransientError,
    WorkerApiClient,
    body_bytes,
    signing_string,
)

from .conftest import KEY_ID

# docs/worker-protocol.md test vector (RFC 8032 test 1 key).
VECTOR = {
    "seedHex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "publicKeyB64": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
    "body": '{"profiles":["passive"]}',
    "bodySha256": "def6b531b6f37f9c565098a3ac8c254408e4ed44786231270b37aa796805b174",
    "signingString": "EDV1\nPOST\n/api/v1/internal/worker/claim\n1792656000\n"
    "vector-nonce-0123456789abcdef\n"
    "def6b531b6f37f9c565098a3ac8c254408e4ed44786231270b37aa796805b174",
    "signatureB64": "ZezimbXKZPd6JLSnkaX3KsoP2/w/b/UCe2jDS3DGdsbswJ3XZ5nzjH//t/NgiZ2N15xQyUS/"
    "JW0704Lw+gTMBw==",
}
BASE = "https://exdomainvault.example.com"
JOB_ID = "6f1f8f7e-1d1b-4d55-8a0e-0d3f6a1b2c3d"


def vector_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VECTOR["seedHex"]))


def test_signing_vector_matches_the_protocol_document():
    key = vector_key()
    from app.identity import public_key_b64

    assert public_key_b64(key) == VECTOR["publicKeyB64"]
    body = body_bytes({"profiles": ["passive"]})
    assert body.decode() == VECTOR["body"]
    assert hashlib.sha256(body).hexdigest() == VECTOR["bodySha256"]
    signer = Signer(
        key, KEY_ID, clock=lambda: 1792656000, nonce_factory=lambda: "vector-nonce-0123456789abcdef"
    )
    path = "/api/v1/internal/worker/claim"
    assert (
        signing_string("POST", path, "1792656000", "vector-nonce-0123456789abcdef", body)
        == (VECTOR["signingString"])
    )
    headers = signer.sign("POST", path, body)
    assert headers["X-EDV-Signature"] == VECTOR["signatureB64"]
    assert headers["X-EDV-Timestamp"] == "1792656000"
    assert headers["X-EDV-Nonce"] == "vector-nonce-0123456789abcdef"
    assert headers["X-EDV-Key-Id"] == KEY_ID
    assert headers["X-EDV-Worker-Version"] == __version__


def verify(request: httpx.Request, key: Ed25519PrivateKey) -> None:
    """Server-side verification, as the API does it."""
    message = "\n".join(
        [
            "EDV1",
            request.method,
            request.url.raw_path.decode(),
            request.headers["X-EDV-Timestamp"],
            request.headers["X-EDV-Nonce"],
            hashlib.sha256(request.content).hexdigest(),
        ]
    )
    key.public_key().verify(base64.b64decode(request.headers["X-EDV-Signature"]), message.encode())


def make_client(handler, key=None, **kwargs) -> tuple[WorkerApiClient, list[float]]:
    sleeps: list[float] = []
    client = WorkerApiClient(
        kwargs.pop("base_url", BASE),
        Signer(key or vector_key(), KEY_ID),
        transport=httpx.MockTransport(handler),
        sleep=sleeps.append,
        **kwargs,
    )
    return client, sleeps


def test_requests_are_signed_compact_and_carry_headers():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"job": None})

    client, _ = make_client(
        handler, access_client_id="id.access", access_client_secret="access-secret"
    )
    assert client.claim(["passive"]) is None
    request = seen[0]
    verify(request, vector_key())
    assert request.method == "POST"
    assert request.url.path == "/api/v1/internal/worker/claim"
    assert request.content == b'{"profiles":["passive"]}'
    assert request.headers["Content-Type"] == "application/json"
    assert request.headers["User-Agent"] == f"exdomainvault-worker/{__version__}"
    assert request.headers["CF-Access-Client-Id"] == "id.access"
    assert request.headers["CF-Access-Client-Secret"] == "access-secret"


def test_no_access_headers_when_not_configured():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"job": None})

    client, _ = make_client(handler)
    client.claim(["passive"])
    assert "CF-Access-Client-Id" not in seen[0].headers
    assert "CF-Access-Client-Secret" not in seen[0].headers


def test_base_path_prefix_is_part_of_the_signed_path():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"job": None})

    client, _ = make_client(handler, base_url=BASE + "/app")
    client.claim(["passive"])
    assert seen[0].url.path == "/app/api/v1/internal/worker/claim"
    verify(seen[0], vector_key())


def test_retries_resign_with_new_nonce_and_reuse_result_id():
    seen: list[httpx.Request] = []
    responses = [
        httpx.Response(503, json={"error": {"code": "unavailable"}}),
        httpx.Response(429, headers={"Retry-After": "2"}),
        httpx.Response(200, json={"accepted": True, "status": "running"}),
    ]

    def handler(request):
        seen.append(request)
        return responses[len(seen) - 1]

    client, sleeps = make_client(handler)
    result = client.results(JOB_ID, 1, f"{JOB_ID}-1-0000", [], [], False)
    assert result == {"accepted": True, "status": "running"}
    assert len(seen) == 3
    nonces = {r.headers["X-EDV-Nonce"] for r in seen}
    assert len(nonces) == 3
    for request in seen:
        verify(request, vector_key())
        assert json.loads(request.content)["resultId"] == f"{JOB_ID}-1-0000"
    assert len({r.content for r in seen}) == 1
    assert len(sleeps) == 2
    assert 0.5 <= sleeps[0] <= 1.0
    assert sleeps[1] >= 2  # Retry-After honoured


def test_network_errors_are_retried_then_raise_transient():
    attempts = []

    def handler(request):
        attempts.append(request)
        raise httpx.ConnectError("refused", request=request)

    client, sleeps = make_client(handler, max_retries=5)
    with pytest.raises(TransientError):
        client.heartbeat(JOB_ID, 1)
    assert len(attempts) == 6
    assert len(sleeps) == 5
    for i, delay in enumerate(sleeps):  # exponential with jitter, capped
        assert min(30, 2**i) * 0.5 <= delay <= min(30, 2**i)


def test_409_raises_lease_lost_without_retry():
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(409, json={"error": {"code": "conflict", "message": "x"}})

    client, sleeps = make_client(handler)
    with pytest.raises(LeaseLost):
        client.heartbeat(JOB_ID, 2)
    assert len(attempts) == 1
    assert sleeps == []


@pytest.mark.parametrize("status", [401, 403])
def test_auth_failures_are_fatal_and_not_retried(status):
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(status, json={"error": {"code": "unauthenticated"}})

    client, _ = make_client(handler)
    with pytest.raises(AuthError):
        client.claim(["passive"])
    assert len(attempts) == 1


@pytest.mark.parametrize("status", [301, 302, 400, 404])
def test_redirects_and_client_errors_are_rejected(status):
    def handler(request):
        return httpx.Response(status, headers={"Location": "https://evil.example/"})

    client, sleeps = make_client(handler)
    with pytest.raises(RequestRejected):
        client.claim(["passive"])
    assert sleeps == []


def test_oversized_request_is_refused_before_sending():
    def handler(request):  # pragma: no cover - never called
        raise AssertionError("sent")

    client, _ = make_client(handler)
    huge = [{"kind": "dns", "values": ["x" * 4000]}] * 300
    with pytest.raises(RequestRejected):
        client.results(JOB_ID, 1, f"{JOB_ID}-1-0000", [], huge, False)


def test_failures_payload_shape():
    seen = []

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"status": "queued", "retryAt": None})

    client, _ = make_client(handler)
    client.failures(JOB_ID, 3, "worker_error", "x" * 600, True)
    assert seen[0] == {
        "jobId": JOB_ID,
        "attempt": 3,
        "errorCode": "worker_error",
        "errorSummary": "x" * 500,
        "retryable": True,
    }
