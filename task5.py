import hmac
from Cryptodome.Cipher import AES #cool Cryptography for Linux I found
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Random import get_random_bytes

def seal(key_enc: bytes, key_mac: bytes, plaintext: bytes, aad: bytes = b"") -> tuple:
    # Use a fresh, random 8-byte nonce for CTR mode block limits
    nonce = get_random_bytes(8)
    
    # Encrypt using CTR mode
    cipher = AES.new(key_enc, AES.MODE_CTR, nonce=nonce)
    ciphertext = cipher.encrypt(plaintext)
    
    # Authenticates everything
    hmac_engine = HMAC.new(key_mac, digestmod=SHA256)
    hmac_engine.update(nonce + ciphertext + aad)
    tag = hmac_engine.digest()
    
    return nonce, ciphertext, tag

def open_sealed(key_enc: bytes, key_mac: bytes, nonce: bytes,
                ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    
    # Recompute the tag over the exact same components
    hmac_engine = HMAC.new(key_mac, digestmod=SHA256)
    hmac_engine.update(nonce + ciphertext + aad)
    expected_tag = hmac_engine.digest()
    
    # Use constant-time comparison to prevent timing side channels
    # (Forces an authentication error if tampered with)
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Authentication failed")
        
    # Decrypts ONLY after validation succeeds
    cipher = AES.new(key_enc, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)

# The main test:
if __name__ == "__main__":
    print("--- RUNNING AUTHENTICATED ENCRYPTION TEST ---")
    k1 = get_random_bytes(16) # Encryption key
    k2 = get_random_bytes(32) # MAC key
    
    msg = b"Bob and Alice's Design"
    associated_data = b"version_1.0"
    
    # packs it togehr
    nonce, ctx, tag = seal(k1, k2, msg, associated_data)
    
    # Test 1: Should execute properly
    try:
        decrypted = open_sealed(k1, k2, nonce, ctx, tag, associated_data)
        print("Success! Decrypted Text matches:", decrypted.decode())
    except ValueError:
        print("Test 1 Failed unexpectedly")
        
    # Test 2: Tamper with ciphertext BEFORE decryption to prove validation
    print("\n--- ATTACK TEST: Tampering with ciphertext bits ---")
    bad_ctx = bytearray(ctx)
    bad_ctx[0] ^= 0xFF # Flip a bit in the first byte position safely
    bad_ctx = bytes(bad_ctx)
    
    try:
        # This must raise an error BEFORE hitting any decryption logic
        open_sealed(k1, k2, nonce, bad_ctx, tag, associated_data)
        print("VULNERABLE: Decryption occurred on modified input!")
    except ValueError as e:
        print(f"Error -> {e}")

