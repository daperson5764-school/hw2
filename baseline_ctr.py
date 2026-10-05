import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


KEY   = os.urandom(32)   # AES-256 key
NONCE = os.urandom(16)   # 128-bit CTR initial counter block


def ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(plaintext) + enc.finalize()


def ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CTR(nonce)).decryptor()
    return dec.update(ciphertext) + dec.finalize()


def hexdump(label: str, data: bytes) -> None:
    print(f"  {label:<22}: {data.hex()}")


def sender() -> bytes:
    command = b'{"action":"READ","path":"notes.txt"}'
    ciphertext = ctr_encrypt(KEY, NONCE, command)

    print("=" * 70)
    print("SENDER")
    print("=" * 70)
    print(f"  plaintext command     : {command.decode()}")
    hexdump("ciphertext (on wire)", ciphertext)
    print()
    return ciphertext


def relay(ciphertext: bytes) -> bytes:
    original = b"READ"
    desired  = b"EDIT"          # any EQUAL-LENGTH value works
    assert len(original) == len(desired)

    # Where "READ" sits inside the known command template.
    offset = b'{"action":"READ","path":"notes.txt"}'.index(original)

    print("=" * 70)
    print("RELAY (attacker: has NO key, NO keystream)")
    print("=" * 70)
    print(f"  target offset         : {offset}")
    print(f"  original bytes  P      : {original}  {original.hex()}")
    print(f"  desired  bytes  P'     : {desired}  {desired.hex()}")

    tampered = bytearray(ciphertext)
    print("\n  Per-byte XOR relation  C'[i] = C[i] XOR (P[i] XOR P'[i]):")
    print("  idx  P   P'  delta=P^P'   C[i]  C'[i]=C[i]^delta")
    for i in range(len(original)):
        delta = original[i] ^ desired[i]          # P[i] XOR P'[i]
        c_old = tampered[offset + i]
        c_new = c_old ^ delta                     # flip exactly those bits
        tampered[offset + i] = c_new
        print(f"   {offset+i:<3} {original[i]:02x}  {desired[i]:02x}   "
              f"   {delta:02x}        {c_old:02x}    {c_new:02x}")

    tampered = bytes(tampered)
    print()
    hexdump("ciphertext in ", ciphertext)
    hexdump("ciphertext out", tampered)
    print()
    return tampered


def receiver(ciphertext: bytes, note: str) -> None:
    plaintext = ctr_decrypt(KEY, NONCE, ciphertext)
    print("=" * 70)
    print(f"RECEIVER  ({note})")
    print("=" * 70)
    try:
        cmd = json.loads(plaintext)
        print(f"  decrypted             : {plaintext.decode()}")
        print(f"  >>> EXECUTING action '{cmd['action']}' on '{cmd['path']}'")
    except Exception as e:
        print(f"  decrypt/parse failed  : {e}")
    print()


if __name__ == "__main__":
    # --- Normal flow ---
    original_ct = sender()

    # --- Attack 1: tamper READ -> EDIT without the key ---
    tampered_ct = relay(original_ct)
    receiver(tampered_ct, "receives TAMPERED message")

    # --- Attack 2: replay the ORIGINAL ciphertext a second time ---
    print("### REPLAY: attacker resends the original ciphertext unchanged ###\n")
    receiver(original_ct, "1st delivery of original")
    receiver(original_ct, "2nd delivery of original  <-- processed AGAIN")