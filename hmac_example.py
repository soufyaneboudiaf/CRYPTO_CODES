import hashlib
import secrets


# Shared secret key
k = "crypto2026"
# Message
m = "Transaction : 100DA"


##Hmac function : ##HMAC(K,m)=H((K′⊕opad)∥H((K ′⊕ipad)∥m))

BLOCK_SIZE = 64  # SHA-256 block size in bytes


def hmac_sha256(key: bytes, message: bytes) -> str:
    """Manual HMAC-SHA256 implementation (without using the hmac module)."""
    # If key is longer than block size, shorten it with SHA-256.
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()

    # If key is shorter than block size, pad with zero bytes.
    if len(key) < BLOCK_SIZE:
        key = key + (b"\x00" * (BLOCK_SIZE - len(key)))

    k_ipad = bytes((b ^ 0x36) for b in key)
    k_opad = bytes((b ^ 0x5C) for b in key)

    inner_hash = hashlib.sha256(k_ipad + message).digest()
    outer_hash = hashlib.sha256(k_opad + inner_hash).hexdigest()
    return outer_hash

# === ALICE : Generate HMAC ===
def alice_send(key: str, message: str) -> str:
    """Alice generates HMAC-SHA256 for the message"""
    return hmac_sha256(key.encode('utf-8'), message.encode('utf-8'))

# === BOB : Verify HMAC ===
def bob_verify(key: str, message: str, received_hmac: str) -> bool:
    """Bob recomputes and verifies the HMAC"""
    computed_hmac = hmac_sha256(key.encode('utf-8'), message.encode('utf-8'))
    return secrets.compare_digest(computed_hmac, received_hmac)

# ─── Simulation ───────────────────────────────────────────
print("=" * 60)
print("        HMAC-SHA256 : Alice → Bob")
print("=" * 60)

print(f"\n🔑  Shared Secret Key  : {k}")
print(f"📨  Message            : {m}")

# Alice sends
tag = alice_send(k, m)
print(f"\n[Alice] HMAC-SHA256 generated :")
print(f"  ➜  {tag}")

# Bob verifies
print(f"\n[Bob] Verifying HMAC...")
is_valid = bob_verify(k, m, tag)

if is_valid:
    print("  ✅  HMAC valid — Message is authentic and untampered!")
else:
    print("  ❌  HMAC invalid — Message may have been altered!")

# ─── Tampered message test ────────────────────────────────
def brute_force_hmac(target_hmac: str, message: str, wordlist: list[str]) -> str | None:
    """Brute force attack on HMAC by trying keys from a wordlist."""
    print("\n" + "=" * 60)
    print("  Brute Force Attack")
    print("=" * 60)
    print(f"\n🎯 Target HMAC : {target_hmac}")
    print(f"📨 Message    : {message}")
    print(f"📄 Trying {len(wordlist)} possible keys...")

    for i, key in enumerate(wordlist):
        computed = hmac_sha256(key.encode('utf-8'), message.encode('utf-8'))
        if computed == target_hmac:
            print(f"\n✅  KEY FOUND! : '{key}'")
            print(f"   Attempts   : {i + 1}")
            return key
        if (i + 1) % 1000 == 0:
            print(f"   Tried {i + 1} keys... (still searching)")

    print(f"\n❌  Key not found in wordlist")
    return None

wordlist = [f"crypto{i}" for i in range(10000)]
brute_force_hmac(tag, m, wordlist)

print("\n" + "=" * 60)
print("  Tampered Message Test")
print("=" * 60)

tampered_message = "Transaction : 200DA"
print(f"\n⚠️   Tampered Message   : {tampered_message}")

is_valid_tampered = bob_verify(k, tampered_message, tag)
if is_valid_tampered:
    print("  ✅  HMAC valid")
else:
    print("  ❌  HMAC invalid — Tampering detected! Message rejected.")

print("\n" + "=" * 60)