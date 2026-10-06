from Cryptodome.Cipher import AES #cool Cryptography for Linux I found

def cfb_corruption_report(key: bytes, iv: bytes, plaintext: bytes,
                           corrupt_block: int, corrupt_byte_count: int = 2) -> dict:
    # Quick checks
    assert len(key) in (16, 24, 32) and len(iv) == 16
    assert len(plaintext) % 16 == 0 and len(plaintext) > 0

    # Encrypt plaintext with CFB mode
    c1 = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    orig_ctx = c1.encrypt(plaintext)

    # Corrupt the ciphertext bytes - Corruption!
    corrupt_ctx = bytearray(orig_ctx)
    start = corrupt_block * 16
    for i in range(start, start + corrupt_byte_count):
        corrupt_ctx[i] ^= 0xFF
    corrupt_ctx = bytes(corrupt_ctx)

    # Decrypt both versions back to plaintext
    d1 = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    orig_pt = d1.decrypt(orig_ctx)

    d2 = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
    corrupt_pt = d2.decrypt(corrupt_ctx)

    # Measure changed bytes and blocks
    bad_bytes = [i for i in range(len(plaintext)) if orig_pt[i] != corrupt_pt[i]]
    bad_blocks = sorted(list(set(idx // 16 for idx in bad_bytes)))

    # Returns the variables
    return {
        "original_ciphertext": orig_ctx,
        "corrupted_ciphertext": corrupt_ctx,
        "original_plaintext": orig_pt,
        "corrupted_plaintext": corrupt_pt,
        "changed_byte_indexes": bad_bytes,
        "changed_block_indexes": bad_blocks
    }

# Simple test to run the two blocks
if name == "main":
    k, iv = b"A" * 16, b"I" * 16
    msg = b"1" * 16 + b"2" * 16 + b"3" * 16 + b"4" * 16 # 4 total

    res = cfb_corruption_report(k, iv, msg, corrupt_block=1)
    
    # Show the lengths and summaries of this test
    print(f"Original Ciphertext Length: {len(res['original_ciphertext'])} bytes")
    print(f"Corrupted Ciphertext Length: {len(res['corrupted_ciphertext'])} bytes")
    print("Original Plaintext (as string):", res["original_plaintext"])
    print("Corrupted Plaintext (as string):", res["corrupted_plaintext"])
    print("Changed Byte Indexes:", res["changed_byte_indexes"])
    print("Changed Block Indexes:", res["changed_block_indexes"])

