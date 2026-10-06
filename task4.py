#cool Cryptography for Linux I found - PKCS7 edition

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    # Rejects anything bad, here and below
    if not (1 <= block_size <= 255) or not data or len(data) % block_size != 0:
        raise ValueError("Invalid padding")
    
    pad_len = data[-1]
    if not (1 <= pad_len <= block_size):
        raise ValueError("Invalid padding")

    # Verify every padding byte matches pad_len
    if any(b != pad_len for b in data[-pad_len:]):
        raise ValueError("Invalid padding")

    return data[:-pad_len]

# 5 tests - I used some of the examples I was given
if __name__ == "__main__":
    bs = 16
    # 1. Valid 1-byte padding (15 text chars + 1 padding byte = 16 bytes total)
    print("Test 1:", pkcs7_unpad(b"hello_world_123\x01", bs))
    # 2. Valid multi-byte padding (12 text chars + 4 padding bytes = 16 bytes total)
    print("Test 2:", pkcs7_unpad(b"hello_world_\x04\x04\x04\x04", bs))
    
    # 3, 4, 5: Should catch the bad padding here!
    for i, bad_data in enumerate([b"hello_world_\x04\x04\x04\x03", b"hello_world_123\x00", b"short"], 3):
        try:
            pkcs7_unpad(bad_data, bs)
        except ValueError:
            print(f"Test {i}: Success -> Rejected bad padding!")

