# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from datetime import timedelta

import jwt
import pytest

from agent_governance.core import FixedClock
from agent_governance.crypto import ec_public_jwk, generate_ec_key, jwk_thumbprint
from agent_governance.identity.dpop import DpopError, DpopVerifier, make_proof, normalize_htu

URL = "https://gw.acme.test/mcp/s4"


def test_valid_proof_returns_thumbprint(clock: FixedClock) -> None:
    key = generate_ec_key()
    proof = make_proof(key, "POST", URL, clock=clock, access_token="tok")
    jkt = DpopVerifier(clock).verify(proof, htm="POST", htu=URL, access_token="tok")
    assert jkt == jwk_thumbprint(ec_public_jwk(key))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"htm": "GET"}, "method"),
        ({"htu": "https://gw.acme.test/mcp/iag"}, "URI"),
        ({"access_token": "other"}, "not bound"),
        ({"expected_jkt": "nope"}, r"cnf\.jkt"),
    ],
)
def test_binding_mismatches(clock: FixedClock, kwargs: dict[str, str], message: str) -> None:
    proof = make_proof(generate_ec_key(), "POST", URL, clock=clock, access_token="tok")
    args = {"htm": "POST", "htu": URL, "access_token": "tok", **kwargs}
    with pytest.raises(DpopError, match=message):
        DpopVerifier(clock).verify(proof, **args)


def test_htu_ignores_query_and_case() -> None:
    assert normalize_htu("HTTPS://GW.acme.test/mcp/s4?x=1#f") == "https://gw.acme.test/mcp/s4"


def test_replay_is_rejected(clock: FixedClock) -> None:
    verifier = DpopVerifier(clock)
    proof = make_proof(generate_ec_key(), "POST", URL, clock=clock)
    verifier.verify(proof, htm="POST", htu=URL)
    with pytest.raises(DpopError, match="replayed"):
        verifier.verify(proof, htm="POST", htu=URL)


def test_stale_and_future_proofs(clock: FixedClock) -> None:
    proof = make_proof(generate_ec_key(), "POST", URL, clock=clock)
    clock.advance(timedelta(seconds=61))
    with pytest.raises(DpopError, match="time window"):
        DpopVerifier(clock).verify(proof, htm="POST", htu=URL)
    future = FixedClock(clock.now() + timedelta(minutes=5))
    with pytest.raises(DpopError, match="time window"):
        DpopVerifier(clock).verify(
            make_proof(generate_ec_key(), "POST", URL, clock=future), htm="POST", htu=URL
        )


def test_missing_malformed_and_wrong_type(clock: FixedClock) -> None:
    verifier = DpopVerifier(clock)
    with pytest.raises(DpopError, match="missing"):
        verifier.verify(None, htm="POST", htu=URL)
    with pytest.raises(DpopError, match="malformed"):
        verifier.verify("not-a-jwt", htm="POST", htu=URL)
    key = generate_ec_key()
    bad_typ = jwt.encode(
        {"jti": "1", "htm": "POST", "htu": URL, "iat": 0},
        key,
        algorithm="ES256",
        headers={"typ": "JWT", "jwk": ec_public_jwk(key)},
    )
    with pytest.raises(DpopError, match="typ"):
        verifier.verify(bad_typ, htm="POST", htu=URL)


def test_signature_must_match_embedded_key(clock: FixedClock) -> None:
    signer, other = generate_ec_key(), generate_ec_key()
    token = jwt.encode(
        {"jti": "1", "htm": "POST", "htu": URL, "iat": int(clock.now().timestamp())},
        signer,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": ec_public_jwk(other)},
    )
    with pytest.raises(DpopError, match="invalid"):
        DpopVerifier(clock).verify(token, htm="POST", htu=URL)


def test_private_key_in_header_is_rejected(clock: FixedClock) -> None:
    key = generate_ec_key()
    jwk = {**ec_public_jwk(key), "d": "secret"}
    token = jwt.encode(
        {"jti": "1", "htm": "POST", "htu": URL, "iat": int(clock.now().timestamp())},
        key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )
    with pytest.raises(DpopError, match="invalid"):
        DpopVerifier(clock).verify(token, htm="POST", htu=URL)
