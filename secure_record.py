import os
import hmac
import struct
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ----------------------------------------------------------------------------
# Constants / wire layout
# ----------------------------------------------------------------------------
VERSION        = 0x01
DIR_G2N        = 0x00          # gateway -> node
DIR_N2G        = 0x01          # node -> gateway

HEADER_FMT     = ">BBQBI"      # version, direction, sequence, msg_type, ct_len
HEADER_LEN     = 15
IV_LEN         = 16
TAG_LEN        = 32
SESSION_ID_LEN = 8
MAX_SEQ        = (1 << 64) - 1
MAX_CT_LEN     = (1 << 32) - 1

# example message types (any 1-byte value works)
MSG_APPLICATION = 0x17
MSG_ALERT       = 0x15


class RecordError(Exception):
    """Any condition that forces a record to be rejected."""


# ----------------------------------------------------------------------------
# Primitive wrappers
# ----------------------------------------------------------------------------
def _aes256_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) != 32:
        raise RecordError("K_enc must be 32 bytes (AES-256)")
    if len(iv) != IV_LEN:
        raise RecordError("iv must be 16 bytes")
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


# ----------------------------------------------------------------------------
# One endpoint's view of the session
# ----------------------------------------------------------------------------
class SecureSession:
    def __init__(self, name, session_id,
                 send_direction, send_K_enc, send_K_mac,
                 recv_direction, recv_K_enc, recv_K_mac):
        if len(session_id) != SESSION_ID_LEN:
            raise RecordError("session_id must be 8 bytes")
        self.name           = name
        self.session_id     = session_id
        self.send_direction = send_direction
        self.send_K_enc     = send_K_enc
        self.send_K_mac     = send_K_mac
        self.recv_direction = recv_direction
        self.recv_K_enc     = recv_K_enc
        self.recv_K_mac     = recv_K_mac
        self.send_seq       = 0        # start at zero (this direction)
        self.recv_seq       = 0        # start at zero (peer's direction)

    # -- SENDER ----------------------------------------------------------
    def seal(self, message_type: int, plaintext: bytes) -> bytes:
        if self.send_seq > MAX_SEQ:
            raise RecordError("sequence exhausted; rekey required")
        if len(plaintext) > MAX_CT_LEN:
            raise RecordError("plaintext too long for ciphertext_length field")

        seq = self.send_seq
        iv  = self.session_id + struct.pack(">Q", seq)          # unique per seq
        ciphertext = _aes256_ctr(self.send_K_enc, iv, plaintext)

        header = struct.pack(HEADER_FMT, VERSION, self.send_direction,
                             seq, message_type & 0xFF, len(ciphertext))
        tag = _hmac_sha256(self.send_K_mac, header + iv + ciphertext)  # Enc-then-MAC

        self.send_seq += 1
        return header + iv + ciphertext + tag

    # -- RECEIVER --------------------------------------------------------
    def open_record(self, record: bytes):
        # (1) structural parse -- reject anything malformed before touching crypto
        if len(record) < HEADER_LEN + IV_LEN + TAG_LEN:
            raise RecordError("malformed record: too short")
        header = record[:HEADER_LEN]
        version, direction, seq, msg_type, ct_len = struct.unpack(HEADER_FMT, header)

        expected_total = HEADER_LEN + IV_LEN + ct_len + TAG_LEN
        if len(record) != expected_total:
            raise RecordError("malformed record: length does not match header")

        iv         = record[HEADER_LEN:HEADER_LEN + IV_LEN]
        ciphertext = record[HEADER_LEN + IV_LEN:HEADER_LEN + IV_LEN + ct_len]
        tag        = record[HEADER_LEN + IV_LEN + ct_len:]

        # (2) version + direction (direction is also enforced cryptographically
        #     because each direction has its own K_mac; this gives a clear error)
        if version != VERSION:
            raise RecordError(f"unsupported version {version}")
        if direction != self.recv_direction:
            raise RecordError("wrong direction (possible reflection)")

        # (3) VERIFY HMAC BEFORE DECRYPTING, constant time.
        #     Covers header+iv+ciphertext, so any modified header byte, modified
        #     iv, or modified ciphertext fails here. A record MAC'd for the other
        #     direction also fails, since recv_K_mac is the wrong key for it.
        expected_tag = _hmac_sha256(self.recv_K_mac, header + iv + ciphertext)
        if not hmac.compare_digest(expected_tag, tag):
            raise RecordError("MAC verification failed (modified header/iv/ciphertext"
                              " or wrong-direction key)")

        # --- everything below is on AUTHENTICATED data only ---

        # (4) IV must be exactly session_id || seq (no attacker-chosen IVs).
        if iv != self.session_id + struct.pack(">Q", seq):
            raise RecordError("iv does not match session_id || sequence")

        # (5) exact next sequence number -> catches replays and out-of-order.
        if seq != self.recv_seq:
            raise RecordError(f"unexpected sequence {seq} (expected {self.recv_seq}: "
                              "replay or out-of-order)")

        # (6) only now decrypt and commit state.
        plaintext = _aes256_ctr(self.recv_K_enc, iv, ciphertext)
        self.recv_seq += 1
        return msg_type, plaintext


# ----------------------------------------------------------------------------
# Build the two endpoints from the Task 2 handshake outputs
# ----------------------------------------------------------------------------
def build_endpoints(session_id, k_g2n_enc, k_g2n_mac, k_n2g_enc, k_n2g_mac):
    gateway = SecureSession(
        "gateway", session_id,
        send_direction=DIR_G2N, send_K_enc=k_g2n_enc, send_K_mac=k_g2n_mac,
        recv_direction=DIR_N2G, recv_K_enc=k_n2g_enc, recv_K_mac=k_n2g_mac)
    node = SecureSession(
        "node", session_id,
        send_direction=DIR_N2G, send_K_enc=k_n2g_enc, send_K_mac=k_n2g_mac,
        recv_direction=DIR_G2N, recv_K_enc=k_g2n_enc, recv_K_mac=k_g2n_mac)
    return gateway, node


def keys_from_handshake():
    """Pull real keys from Task 2 if available; else random demo keys."""
    try:
        import handshake as hs
        gw, nd = hs.fresh_parties()
        kg, _ = hs.run_handshake(gw, nd, verbose=False)
        print("   (keys obtained from the Task 2 authenticated handshake)")
        return (kg["session_id"], kg["K_g2n_enc"], kg["K_g2n_mac"],
                kg["K_n2g_enc"], kg["K_n2g_mac"])
    except Exception:
        print("   (Task 2 module not found; using random stand-in keys)")
        return (os.urandom(8), os.urandom(32), os.urandom(32),
                os.urandom(32), os.urandom(32))


# ----------------------------------------------------------------------------
# Demo + required rejection tests
# ----------------------------------------------------------------------------
def expect_reject(name, fn):
    try:
        fn()
        print(f"  [FAIL] {name}: accepted (should have been rejected)")
    except RecordError as e:
        print(f"  [OK]   {name}: rejected -> {e}")


def main():
    print("=" * 72)
    print("SETUP")
    print("=" * 72)
    sid, kge, kgm, kne, knm = keys_from_handshake()
    gateway, node = build_endpoints(sid, kge, kgm, kne, knm)
    print(f"   session_id = {sid.hex()}")
    print()

    print("=" * 72)
    print("HONEST BIDIRECTIONAL TRAFFIC")
    print("=" * 72)
    r0 = gateway.seal(MSG_APPLICATION, b'{"action":"READ","path":"notes.txt"}')
    r1 = gateway.seal(MSG_APPLICATION, b'{"action":"READ","path":"keys.db"}')
    mt, pt = node.open_record(r0); print(f"   node   got (seq0): {pt.decode()}")
    mt, pt = node.open_record(r1); print(f"   node   got (seq1): {pt.decode()}")

    rr = node.seal(MSG_APPLICATION, b'{"status":"OK","bytes":128}')
    mt, pt = gateway.open_record(rr); print(f"   gateway got (seq0): {pt.decode()}")

    # IV uniqueness under one key (gateway's send direction)
    iv0 = r0[HEADER_LEN:HEADER_LEN + IV_LEN]
    iv1 = r1[HEADER_LEN:HEADER_LEN + IV_LEN]
    print(f"   gateway IV seq0 = {iv0.hex()}")
    print(f"   gateway IV seq1 = {iv1.hex()}   (distinct: {iv0 != iv1})")
    print()

    print("=" * 72)
    print("REJECTION TESTS (each MUST be rejected)")
    print("=" * 72)

    # fresh pair + one valid gateway->node record for tampering tests
    def fresh():
        g, n = build_endpoints(sid, kge, kgm, kne, knm)
        rec = g.seal(MSG_APPLICATION, b"the quick brown fox")
        return g, n, bytearray(rec)

    # 1. modified header (flip a byte of the message_type field)
    def t_hdr():
        _, n, rec = fresh(); rec[10] ^= 0x01; n.open_record(bytes(rec))
    expect_reject("modified header", t_hdr)

    # 2. modified ciphertext
    def t_ct():
        _, n, rec = fresh(); rec[HEADER_LEN + IV_LEN] ^= 0x01; n.open_record(bytes(rec))
    expect_reject("modified ciphertext", t_ct)

    # 3. modified tag
    def t_tag():
        _, n, rec = fresh(); rec[-1] ^= 0x01; n.open_record(bytes(rec))
    expect_reject("modified tag", t_tag)

    # 4. replay (deliver the same valid record twice)
    def t_replay():
        g, n = build_endpoints(sid, kge, kgm, kne, knm)
        rec = g.seal(MSG_APPLICATION, b"hello")
        n.open_record(rec)          # first delivery: fine
        n.open_record(rec)          # replay: seq 0 but recv_seq now 1
    expect_reject("replay", t_replay)

    # 5. out-of-order (skip a sequence number)
    def t_ooo():
        g, n = build_endpoints(sid, kge, kgm, kne, knm)
        g.seal(MSG_APPLICATION, b"first")        # seq 0 (not delivered)
        rec1 = g.seal(MSG_APPLICATION, b"second") # seq 1
        n.open_record(rec1)                       # expects seq 0
    expect_reject("out-of-order sequence", t_ooo)

    # 6. wrong direction / reflection: bounce a gateway-sent record back to gateway
    def t_dir():
        g, n = build_endpoints(sid, kge, kgm, kne, knm)
        rec = g.seal(MSG_APPLICATION, b"reflect me")
        g.open_record(rec)          # gateway receiving its own send direction
    expect_reject("wrong-direction / reflection", t_dir)

    # 7. truncated / malformed record
    def t_trunc():
        _, n, rec = fresh(); n.open_record(bytes(rec[:HEADER_LEN + 4]))
    expect_reject("truncated record", t_trunc)

    print()
    print("No branch returns plaintext on any of the above: every failure raises")
    print("RecordError before AES-CTR decryption runs, so plaintext is never released.")


if __name__ == "__main__":
    main()