"""
Adversarial tests for the Encrypt-then-MAC record layer (Task 3).

Covers Task 4 items:
  (1) bidirectional messages,
  (2) modified ciphertext,
  (3) modified authenticated header,
  (4) replayed record,
  (5) record reflected into the opposite direction,
plus out-of-order and truncated records.

Each adversarial test asserts a SPECIFIC safe failure: the right exception,
a message identifying the cause, AND that no plaintext was released / the
receiver's sequence state was not advanced by the rejected record.
"""

import pytest

import secure_record as sr

HDR, IV = sr.HEADER_LEN, sr.IV_LEN


def endpoints(session_keys):
    return sr.build_endpoints(
        session_keys["session_id"],
        session_keys["k_g2n_enc"], session_keys["k_g2n_mac"],
        session_keys["k_n2g_enc"], session_keys["k_n2g_mac"])


# --- item 1: valid bidirectional traffic ------------------------------------
def test_valid_bidirectional(session_keys):
    gw, nd = endpoints(session_keys)

    m0 = b'{"action":"READ","path":"notes.txt"}'
    m1 = b'{"action":"LIST","path":"/etc"}'
    assert nd.open_record(gw.seal(sr.MSG_APPLICATION, m0)) == (sr.MSG_APPLICATION, m0)
    assert nd.open_record(gw.seal(sr.MSG_APPLICATION, m1)) == (sr.MSG_APPLICATION, m1)

    reply = b'{"status":"OK"}'
    assert gw.open_record(nd.seal(sr.MSG_APPLICATION, reply)) == (sr.MSG_APPLICATION, reply)

    assert nd.recv_seq == 2 and gw.recv_seq == 1


# --- item 2: modified ciphertext --------------------------------------------
def test_modified_ciphertext(session_keys):
    gw, nd = endpoints(session_keys)
    rec = bytearray(gw.seal(sr.MSG_APPLICATION, b"the quick brown fox"))
    rec[HDR + IV] ^= 0x01                       # flip first ciphertext byte
    with pytest.raises(sr.RecordError) as e:
        nd.open_record(bytes(rec))
    assert "mac" in str(e.value).lower()
    assert nd.recv_seq == 0                      # no state advance, no plaintext


# --- item 3: modified authenticated header ----------------------------------
def test_modified_header(session_keys):
    gw, nd = endpoints(session_keys)
    rec = bytearray(gw.seal(sr.MSG_APPLICATION, b"payload"))
    rec[10] ^= 0x01                              # flip a byte of message_type
    with pytest.raises(sr.RecordError) as e:
        nd.open_record(bytes(rec))
    assert "mac" in str(e.value).lower()
    assert nd.recv_seq == 0


# --- item 4: replayed record ------------------------------------------------
def test_replayed_record(session_keys):
    gw, nd = endpoints(session_keys)
    rec = gw.seal(sr.MSG_APPLICATION, b"hello once")
    assert nd.open_record(rec)[1] == b"hello once"   # first delivery OK
    with pytest.raises(sr.RecordError) as e:
        nd.open_record(rec)                           # replay
    assert "sequence" in str(e.value).lower()
    assert nd.recv_seq == 1                           # stayed put after replay


# --- item 5: record reflected into the opposite direction -------------------
def test_reflected_opposite_direction(session_keys):
    gw, nd = endpoints(session_keys)
    rec = gw.seal(sr.MSG_APPLICATION, b"reflect me")
    # Feed the gateway's own outbound record back into the gateway.
    with pytest.raises(sr.RecordError) as e:
        gw.open_record(rec)
    assert "direction" in str(e.value).lower()
    assert gw.recv_seq == 0


# --- extra: out-of-order ----------------------------------------------------
def test_out_of_order_rejected(session_keys):
    gw, nd = endpoints(session_keys)
    gw.seal(sr.MSG_APPLICATION, b"seq0")             # produced but dropped
    rec1 = gw.seal(sr.MSG_APPLICATION, b"seq1")
    with pytest.raises(sr.RecordError) as e:
        nd.open_record(rec1)                          # receiver still expects seq0
    assert "sequence" in str(e.value).lower()
    assert nd.recv_seq == 0


# --- extra: truncated / malformed ------------------------------------------
def test_truncated_record_rejected(session_keys):
    gw, nd = endpoints(session_keys)
    rec = gw.seal(sr.MSG_APPLICATION, b"payload")
    with pytest.raises(sr.RecordError) as e:
        nd.open_record(rec[:HDR + 4])
    assert "malformed" in str(e.value).lower()
    assert nd.recv_seq == 0
