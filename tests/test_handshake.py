"""
Adversarial tests for the authenticated Diffie-Hellman handshake (Task 2).

Covers Task 4 item (1) valid handshake, and item (6) incorrect RSA public key,
invalid RSA-PSS transcript signature, and reflected handshake message -- plus
the related tamper cases (changed nonce / public value, malformed transcript,
unexpected identity). Each adversarial test asserts a SPECIFIC safe failure:
the right exception type AND a message identifying the cause.
"""

import pytest

import handshake as hs


# --- item 1: valid handshake ------------------------------------------------
def test_valid_handshake_agrees_on_keys(make_parties):
    gw, nd = make_parties()
    kg, kn = hs.run_handshake(gw, nd, verbose=False)

    # both sides derive identical material
    assert kg == kn
    assert len(kg["session_id"]) == 8
    for name in ("K_g2n_enc", "K_g2n_mac", "K_n2g_enc", "K_n2g_mac"):
        assert len(kg[name]) == 32
    # the four directional keys are all distinct (key separation)
    assert len({kg["K_g2n_enc"], kg["K_g2n_mac"],
                kg["K_n2g_enc"], kg["K_n2g_mac"]}) == 4


# --- item 6a: incorrect RSA public key --------------------------------------
def test_incorrect_rsa_public_key_rejected(make_parties, material):
    gw, nd = make_parties()
    # Gateway is tricked into trusting the wrong long-term key for the node.
    gw.peer_rsa_public = material["wrong_rsa"].public_key()
    with pytest.raises(hs.HandshakeError) as e:
        hs.run_handshake(gw, nd, verbose=False)
    assert "signature" in str(e.value).lower()


# --- item 6b: invalid RSA-PSS transcript signature --------------------------
def test_invalid_pss_signature_rejected(make_parties):
    gw, nd = make_parties()

    def tamper(f2):
        s = bytearray(f2["sig"]); s[0] ^= 0x01; f2["sig"] = bytes(s)
        return f2

    with pytest.raises(hs.HandshakeError) as e:
        hs.run_handshake(gw, nd, tamper=tamper, verbose=False)
    assert "signature" in str(e.value).lower()


# --- item 6c: reflected handshake message -----------------------------------
def test_reflected_handshake_rejected(make_parties):
    gw, nd = make_parties()

    def reflect(_f2):
        # Attacker bounces the gateway's own identity/nonce/public back at it.
        return {"id": gw.identity, "dh_pub": gw.dh_pub_bytes(),
                "nonce": gw.nonce, "sig": b"\x00" * 384}

    with pytest.raises(hs.HandshakeError) as e:
        hs.run_handshake(gw, nd, tamper=reflect, verbose=False)
    assert "reflection" in str(e.value).lower()


# --- related binding checks (reinforce "specific safe failure") -------------
def test_changed_nonce_breaks_binding(make_parties):
    gw, nd = make_parties()

    def tamper(f2):
        n = bytearray(f2["nonce"]); n[0] ^= 0xFF; f2["nonce"] = bytes(n)
        return f2

    with pytest.raises(hs.HandshakeError) as e:
        hs.run_handshake(gw, nd, tamper=tamper, verbose=False)
    assert "signature" in str(e.value).lower()   # altered transcript -> sig fails


def test_changed_public_value_breaks_binding(make_parties):
    gw, nd = make_parties()

    def tamper(f2):
        p = bytearray(f2["dh_pub"]); p[-1] ^= 0x01; f2["dh_pub"] = bytes(p)
        return f2

    with pytest.raises(hs.HandshakeError) as e:
        hs.run_handshake(gw, nd, tamper=tamper, verbose=False)
    assert "signature" in str(e.value).lower()


def test_unexpected_peer_identity_rejected(make_parties):
    gw, nd = make_parties()
    nd.peer_identity = "evil.attacker.example"
    with pytest.raises(hs.HandshakeError) as e:
        hs.run_handshake(gw, nd, verbose=False)
    assert "identity" in str(e.value).lower()


def test_malformed_transcript_rejected_before_hashing():
    bad = (10 ** 9).to_bytes(4, "big") + b"short"   # declares 1e9 bytes, has 5
    with pytest.raises(hs.HandshakeError) as e:
        hs.parse_transcript(bad)
    assert "malformed" in str(e.value).lower()
