from Cryptodome.Cipher import AES #cool Cryptography for Linux I found

def decrypt_cbc_missing_iv(key: bytes, ciphertext: bytes) -> dict:
    # Quick checks on lengths (important to have checks regardless)
    assert len(key) in (16, 24, 32), "Invalid key size"
    assert len(ciphertext) >= 16 and len(ciphertext) % 16 == 0, "Invalid cipher size"

    # Use standard CBC mode with a placeholder IV of 16 zero-bytes
    dummy_iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, dummy_iv)
    
    # Decrypt everything at once
    raw_decrypted = cipher.decrypt(ciphertext)
    
    # Split the raw data into 16-byte blocks
    blocks = [raw_decrypted[i : i+16] for i in range(0, len(raw_decrypted), 16)]
    
    # Dynamically builds the list
    lost_list = list(range(1)) 

    return {
        "recoverable_blocks": blocks[1:] if len(blocks) > 1 else [],
        "unrecoverable_blocks": lost_list,
        "explanation": "In CBC mode, P[i] = Decrypt(C[i]) ^ C[i-1]. Since the root IV is missing, it passes a dummy zero IV to use standard CBC mode. This breaks block/index 0, but because the remaining blocks rely on the actual ciphertext blocks versus the root IV, blocks 1 onward are recovered and go up by one. It works!"
    }

# The 3 block test
my_key = b"A" * 16
real_iv = b"I" * 16

# Block script test
three_block = AES.new(my_key, AES.MODE_CBC, real_iv)

# Each block is exactly 16 bytes
p0 = b"1" * 16
p1 = b"2" * 16
p2 = b"3" * 16

ctx = three_block.encrypt(p0 + p1 + p2)

# Runs the function
res = decrypt_cbc_missing_iv(my_key, ctx)

# Unpack the blocks sequentially using pop
blocks_list = list(res["recoverable_blocks"])
first_block = blocks_list.pop(0)
second_block = blocks_list.pop(0)

print("Lost Block:", res["unrecoverable_blocks"])
print("Block 1:", list(first_block))
print("Block 2:", list(second_block))

