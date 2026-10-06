from Cryptodome.Cipher import AES #cool Cryptography for Linux I found

def cbc_bitflip(previous_ciphertext_block: bytes,
                current_ciphertext_block: bytes,
                known_plaintext_block: bytes,
                byte_index: int,
                target_byte: int) -> bytes:
    
    # Cast to a mutable bytearray to swap out values easily
    modified_prev = bytearray(previous_ciphertext_block)
    
    # Grab the specific old values at our target position
    old_cipher_byte = previous_ciphertext_block[byte_index]
    old_plain_byte = known_plaintext_block[byte_index]
    
    # Core CBC bitflip formula: New_C = Old_C ^ Old_P ^ Target_P
    # This completely wipes out the old character and injects the new one
    modified_prev[byte_index] = old_cipher_byte ^ old_plain_byte ^ target_byte
    
    return bytes(modified_prev)

# Simple test!
if __name__ == "__main__":
    my_key = b"A" * 16
    my_iv = b"I" * 16
    
    # Plaintext blocks 
    p0 = b"Odin_Allfather__" # Exactly 16 bytes (this should corrupt)
    p1 = b"Fenrir_the_wolf_" # Exactly 16 bytes (This should be fine)
    
    # Normal CBC encryption to get our baseline ciphertext blocks to attack
    cipher = AES.new(my_key, AES.MODE_CBC, my_iv)
    ctx = cipher.encrypt(p0 + p1)
    
    c0 = ctx[0:16]
    c1 = ctx[16:32]
    
    # ASCII value for a hyphen '-' is 45. Targets index 6.
    modified_c0 = cbc_bitflip(c0, c1, p1, byte_index=6, target_byte=45)
    
    # Decrypt with the modified previous block
    dec_cipher = AES.new(my_key, AES.MODE_CBC, my_iv)
    corrupted_pt = dec_cipher.decrypt(modified_c0 + c1)
    
    # Print the results
    print("Results:")
    print("Original Block 1: ", p1)
    print("Decrypted Block 0 (Preceding Block):", corrupted_pt[0:16])
    print("Decrypted Block 1 (Targeted Block): ", corrupted_pt[16:32])

