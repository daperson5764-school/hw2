import os
import hmac
import hashlib

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.exceptions import InvalidSignature


# ----------------------------------------------------------------------------
# Protocol constants
# ----------------------------------------------------------------------------
LABEL         = b"CSCE465-HS-v2"
GROUP_ID      = b"ffdhe3072"
ROLE_GATEWAY  = b"gateway"
ROLE_NODE     = b"node"
MODULUS_BYTES = 384          # 3072-bit ffdhe3072 modulus -> 384 bytes
NONCE_LEN     = 16
GROUP_FILE    = "ffdhe3072.pem"


class HandshakeError(Exception):
    """Raised whenever a session must be rejected."""


# ----------------------------------------------------------------------------
# Canonical, length-prefixed (TLV) transcript encoding
#
# Each field is preceded by its length as a 4-byte big-endian integer.  Plain
# concatenation is ambiguous; the length prefix makes the field boundaries
# unambiguous, so the transcript is canonical.  A declared length that runs
# past the end of the buffer (or leaves trailing bytes) is malformed and is
# rejected BEFORE anything is hashed.
# ----------------------------------------------------------------------------
def tlv(field: bytes) -> bytes:
    return len(field).to_bytes(4, "big") + field


def encode_transcript(fields) -> bytes:
    return b"".join(tlv(f) for f in fields)


def parse_transcript(data: bytes):
    """Strictly parse a TLV buffer, rejecting any bad length declaration."""
    fields, i, n = [], 0, len(data)
    while i < n:
        if i + 4 > n:
            raise HandshakeError("malformed transcript: truncated length prefix")
        length = int.from_bytes(data[i:i + 4], "big")
        i += 4
        if i + length > n:
            raise HandshakeError("malformed transcript: declared length exceeds buffer")
        fields.append(data[i:i + length])
        i += length
    return fields


# Fields always appear GATEWAY-before-NODE so both parties build the same bytes.
def transcript_fields(g_id, n_id, g_pub, n_pub, g_nonce, n_nonce):
    return [
        LABEL,
        GROUP_ID,
        g_id.encode("utf-8"),
        n_id.encode("utf-8"),
        g_pub,            # 384-byte big-endian gateway DH public
        n_pub,            # 384-byte big-endian node DH public
        g_nonce,          # 16-byte gateway nonce
        n_nonce,          # 16-byte node nonce
    ]


def build_transcript(g_id, n_id, g_pub, n_pub, g_nonce, n_nonce) -> bytes:
    fields = transcript_fields(g_id, n_id, g_pub, n_pub, g_nonce, n_nonce)
    data = encode_transcript(fields)
    # Round-trip check: validate TLV structure before it is ever hashed.
    if parse_transcript(data) != fields:
        raise HandshakeError("malformed transcript: non-canonical encoding")
    return data


# ----------------------------------------------------------------------------
# Supplied, assignment-specific key derivation
# ----------------------------------------------------------------------------
def derive_keys(Z: bytes, TH: bytes) -> dict:
    assert len(Z) == MODULUS_BYTES and len(TH) == 32
    K_master = hashlib.sha256(b"CSCE465-KDF-v1" + Z + TH).digest()

    def kdf(label: bytes) -> bytes:
        return hmac.new(K_master, label + TH, hashlib.sha256).digest()

    return {
        "K_master":   K_master,
        "K_g2n_enc":  kdf(b"gateway-to-node encryption"),
        "K_g2n_mac":  kdf(b"gateway-to-node MAC"),
        "K_n2g_enc":  kdf(b"node-to-gateway encryption"),
        "K_n2g_mac":  kdf(b"node-to-gateway MAC"),
        "session_id": kdf(b"session identifier")[:8],
    }


# ----------------------------------------------------------------------------
# RSA-PSS signing helpers (SHA-256, probabilistic salt)
# ----------------------------------------------------------------------------
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                   salt_length=padding.PSS.MAX_LENGTH)


def sign_role_th(rsa_private, role: bytes, TH: bytes) -> bytes:
    # Signs  role || SHA-256(transcript).
    return rsa_private.sign(role + TH, _PSS, hashes.SHA256())


def verify_role_th(rsa_public, role: bytes, TH: bytes, signature: bytes) -> None:
    rsa_public.verify(signature, role + TH, _PSS, hashes.SHA256())  # raises on failure


# ----------------------------------------------------------------------------
# Party
# ----------------------------------------------------------------------------
class Party:
    def __init__(self, identity, role, rsa_private, dh_params):
        self.identity     = identity
        self.role         = role
        self.rsa_private  = rsa_private
        self.rsa_public   = rsa_private.public_key()
        self.dh_params    = dh_params
        self.param_nums   = dh_params.parameter_numbers()
        # trust: expected peer identity + peer long-term public key
        self.peer_identity   = None
        self.peer_rsa_public = None

    def trust(self, peer_identity, peer_rsa_public):
        self.peer_identity   = peer_identity
        self.peer_rsa_public = peer_rsa_public

    def new_session(self):
        self.nonce       = os.urandom(NONCE_LEN)
        self.dh_private  = self.dh_params.generate_private_key()
        self.dh_pub_int  = self.dh_private.public_key().public_numbers().y

    def dh_pub_bytes(self) -> bytes:
        return self.dh_pub_int.to_bytes(MODULUS_BYTES, "big")

    def shared_Z(self, peer_pub_int: int) -> bytes:
        peer_pub = dh.DHPublicNumbers(peer_pub_int, self.param_nums).public_key()
        raw = self.dh_private.exchange(peer_pub)          # library does the DH math
        return int.from_bytes(raw, "big").to_bytes(MODULUS_BYTES, "big")  # canonical 384B


# ----------------------------------------------------------------------------
# Handshake orchestration
#
# Flight 1  gateway -> node : {id, dh_pub, nonce}
# Flight 2  node    -> gateway : {id, dh_pub, nonce, sig_node}
# Flight 3  gateway -> node : {sig_gateway}
#
# `tamper` lets the tests mutate flight 2 in transit to model an active attacker.
# ----------------------------------------------------------------------------
def run_handshake(gateway: Party, node: Party, tamper=None, verbose=True):
    gateway.new_session()
    node.new_session()

    def log(msg):
        if verbose:
            print(msg)

    # ---- Flight 1: gateway -> node ----
    f1 = {"id": gateway.identity,
          "dh_pub": gateway.dh_pub_bytes(),
          "nonce": gateway.nonce}

    # ---- Node processes flight 1 and builds its signed flight 2 ----
    # Node rejects a reflected message (one that claims to be from node itself).
    if f1["id"] == node.identity:
        raise HandshakeError("reflection: flight-1 identity equals my own")
    if f1["id"] != node.peer_identity:
        raise HandshakeError(f"unexpected peer identity: {f1['id']!r}")

    g_pub_int = int.from_bytes(f1["dh_pub"], "big")
    th_node_bytes = build_transcript(
        g_id=f1["id"], n_id=node.identity,
        g_pub=f1["dh_pub"], n_pub=node.dh_pub_bytes(),
        g_nonce=f1["nonce"], n_nonce=node.nonce)
    TH_node = hashlib.sha256(th_node_bytes).digest()
    sig_node = sign_role_th(node.rsa_private, node.role, TH_node)

    f2 = {"id": node.identity,
          "dh_pub": node.dh_pub_bytes(),
          "nonce": node.nonce,
          "sig": sig_node}

    # ---- Active attacker may mutate flight 2 while it is "on the wire" ----
    if tamper is not None:
        f2 = tamper(dict(f2))
        log(f"   [attacker tampered with flight 2]")

    # ---- Flight 2 arrives at gateway: authenticate the node ----
    # Reflection check: a bounced-back copy of our own flight would carry the
    # gateway identity / gateway role; reject it.
    if f2["id"] == gateway.identity:
        raise HandshakeError("reflection: flight-2 identity equals my own")
    if f2["id"] != gateway.peer_identity:
        raise HandshakeError(f"unexpected peer identity: {f2['id']!r}")

    n_pub_int = int.from_bytes(f2["dh_pub"], "big")
    th_gw_bytes = build_transcript(
        g_id=gateway.identity, n_id=f2["id"],
        g_pub=gateway.dh_pub_bytes(), n_pub=f2["dh_pub"],
        g_nonce=gateway.nonce, n_nonce=f2["nonce"])
    TH_gw = hashlib.sha256(th_gw_bytes).digest()

    try:
        # Peer must have signed the NODE role over the transcript gateway sees.
        verify_role_th(gateway.peer_rsa_public, ROLE_NODE, TH_gw, f2["sig"])
    except InvalidSignature:
        raise HandshakeError("invalid node signature "
                             "(forged sig, or a nonce/public value was changed)")

    # Gateway is now satisfied -> it signs the gateway role and replies.
    sig_gw = sign_role_th(gateway.rsa_private, gateway.role, TH_gw)
    f3 = {"sig": sig_gw}

    # ---- Flight 3 arrives at node: authenticate the gateway ----
    try:
        verify_role_th(node.peer_rsa_public, ROLE_GATEWAY, TH_node, f3["sig"])
    except InvalidSignature:
        raise HandshakeError("invalid gateway signature")

    # ---- Both sides agree: derive keys from the SAME (Z, TH) ----
    Z_gw   = gateway.shared_Z(n_pub_int)
    Z_node = node.shared_Z(g_pub_int)

    keys_gw   = derive_keys(Z_gw,   TH_gw)
    keys_node = derive_keys(Z_node, TH_node)

    if keys_gw["session_id"] != keys_node["session_id"]:
        raise HandshakeError("key confirmation failed: session ids differ")

    log(f"   gateway TH = {TH_gw.hex()}")
    log(f"   node    TH = {TH_node.hex()}")
    log(f"   session_id = {keys_gw['session_id'].hex()}")
    return keys_gw, keys_node


# ----------------------------------------------------------------------------
# Demo + the required rejection tests
# ----------------------------------------------------------------------------
def load_params():
    with open(GROUP_FILE, "rb") as f:
        return serialization.load_pem_parameters(f.read())


def fresh_parties():
    params = load_params()
    gw_rsa   = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    node_rsa = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    gateway = Party("gateway.csce465.local", ROLE_GATEWAY, gw_rsa, params)
    node    = Party("node.csce465.local",    ROLE_NODE,    node_rsa, params)
    gateway.trust(node.identity, node.rsa_public)
    node.trust(gateway.identity, gateway.rsa_public)
    return gateway, node


def expect_reject(name, fn):
    try:
        fn()
        print(f"  [FAIL] {name}: session was ACCEPTED (should have been rejected)")
    except HandshakeError as e:
        print(f"  [OK]   {name}: rejected -> {e}")


def main():
    print("=" * 72)
    print("HONEST HANDSHAKE")
    print("=" * 72)
    gateway, node = fresh_parties()
    kg, kn = run_handshake(gateway, node)
    all_match = all(kg[k] == kn[k] for k in kg)
    print(f"   all directional/MAC keys match on both sides: {all_match}")
    for k in ("K_g2n_enc", "K_g2n_mac", "K_n2g_enc", "K_n2g_mac"):
        print(f"     {k:<10} = {kg[k].hex()[:32]}...")
    print()

    print("=" * 72)
    print("REJECTION TESTS (each MUST be rejected)")
    print("=" * 72)

    # 1. Invalid signature: corrupt the node's signature bytes.
    def t_bad_sig():
        gw, nd = fresh_parties()
        def tamper(f2):
            s = bytearray(f2["sig"]); s[0] ^= 0x01; f2["sig"] = bytes(s)
            return f2
        run_handshake(gw, nd, tamper=tamper, verbose=False)
    expect_reject("invalid signature", t_bad_sig)

    # 2. Changed nonce after signing.
    def t_changed_nonce():
        gw, nd = fresh_parties()
        def tamper(f2):
            n = bytearray(f2["nonce"]); n[0] ^= 0xFF; f2["nonce"] = bytes(n)
            return f2
        run_handshake(gw, nd, tamper=tamper, verbose=False)
    expect_reject("changed nonce", t_changed_nonce)

    # 3. Changed DH public value after signing.
    def t_changed_pub():
        gw, nd = fresh_parties()
        def tamper(f2):
            p = bytearray(f2["dh_pub"]); p[-1] ^= 0x01; f2["dh_pub"] = bytes(p)
            return f2
        run_handshake(gw, nd, tamper=tamper, verbose=False)
    expect_reject("changed public value", t_changed_pub)

    # 4. Malformed transcript: a declared length that overruns the buffer.
    def t_malformed():
        bad = (10**9).to_bytes(4, "big") + b"short"   # says 1e9 bytes, has 5
        parse_transcript(bad)
    expect_reject("malformed transcript", t_malformed)

    # 5. Unexpected peer identity: node is told to expect a different gateway.
    def t_bad_identity():
        gw, nd = fresh_parties()
        nd.peer_identity = "evil.attacker.example"   # not who flight 1 claims
        run_handshake(gw, nd, verbose=False)
    expect_reject("unexpected peer identity", t_bad_identity)

    # 6. Reflection: bounce the gateway's own flight-1 back to it as flight 2.
    def t_reflection():
        gw, nd = fresh_parties()
        def tamper(_f2):
            # Attacker discards node's reply and reflects the gateway's own
            # identity/nonce/public back. There is no valid node signature,
            # and the identity equals the gateway's own -> rejected.
            return {"id": gw.identity,
                    "dh_pub": gw.dh_pub_bytes(),
                    "nonce": gw.nonce,
                    "sig": b"\x00" * 384}
        run_handshake(gw, nd, tamper=tamper, verbose=False)
    expect_reject("reflected handshake message", t_reflection)

    print()
    print("Replay note: because both nonces and both ephemeral DH publics are")
    print("fresh per session and are bound into TH, a recorded transcript")
    print("replayed later yields a different expected TH and fails verification.")


if __name__ == "__main__":
    main()