import binascii
from Crypto.Random import get_random_bytes
from simon import SimonCipher
from Crypto.Hash import Poly1305
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

'''
def pad(input, block_size):
    padding_length = block_size - (len(input) % block_size)
    final = input + bytes([padding_length]*padding_length)
    return final

def unpad(input):
    return input[:input[-1]]
'''
def eam_encrypt(plaintext, k1, k2, iv):
    iv_int = int.from_bytes(iv, byteorder='big')
    k1_int = int.from_bytes(k1, byteorder='big')
    cipher = SimonCipher(k1_int, block_size=128, key_size=128, init=iv_int, mode='CTR', counter=1)
    ctxt = b''
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        if len(block) < 16:
            block = pad(block, 16)
        block_int = int.from_bytes(block, byteorder='big')
        ctxt_block = cipher.encrypt(block_int)
        ctxt += ctxt_block.to_bytes(16, byteorder='big')
    ciphertext_int = int.from_bytes(ctxt, byteorder='big')
    
    #k2 = bytes.fromhex(hex(k2).lstrip("0x"))
    poly_cipher = Poly1305.new(key=k2, cipher=AES)
    poly_cipher.update(plaintext)
    mac = poly_cipher.hexdigest()
    mac_nonce = poly_cipher.nonce.hex()
    print(mac)

    return ciphertext_int, mac, mac_nonce
    '''
    plaintext = pad(plaintext, 16)
    print("Padded Plaintext:", plaintext)
    k1_int = bytes_to_int(k1)
    plaintext_int = bytes_to_int(plaintext)
    nonce_int = bytes_to_int(nonce)

    cipher = SimonCipher(k1_int, mode='CTR', init=nonce_int, block_size=128, key_size=128)
    #ciphertext = cipher.encrypt(plaintext)
    ciphertext_int = cipher.encrypt(plaintext_int)
    ciphertext = int_to_bytes(ciphertext_int, len(plaintext))
    print("Encrypted Ciphertext:", ciphertext)

    mac = Poly1305.new(key=k2, cipher=AES, nonce=nonce, data=ciphertext).digest()

    return ciphertext, mac
    '''
def eam_decrypt_and_verify(ctxt, mac, k1, k2, iv, mac_nonce):
    iv_int = int.from_bytes(iv, byteorder='big')
    k1_int = int.from_bytes(k1, byteorder='big')
    cipher = SimonCipher(k1_int, block_size=128, key_size=128, init=iv_int, mode='CTR', counter=1)
    ctxt_bytes = ctxt.to_bytes((ctxt.bit_length() + 7) // 8, byteorder='big')
    ptxt = b''
    for i in range(0, len(ctxt_bytes), 16):
        block = ctxt_bytes[i:i+16]
        block_int = int.from_bytes(block, byteorder='big')
        ptxt_block = cipher.decrypt(block_int)
        ptxt += ptxt_block.to_bytes(16, byteorder='big')
    ptxt = unpad(ptxt, 16).decode()

    #k2_bytes = bytes.fromhex(hex(k2).lstrip("0x"))
    mac_nonce_bytes = bytes.fromhex(mac_nonce)
    poly_cipher = Poly1305.new(key=k2, nonce=mac_nonce_bytes, cipher=AES)
    poly_cipher.update(str.encode(ptxt))
    print(str.encode(ptxt))
    vmac = poly_cipher.hexdigest()
    print(vmac)

    if mac != vmac:
        raise ValueError("MAC verification failed")
    
    return ptxt
    '''
    try:
        Poly1305.new(key=k2, cipher=AES, nonce=nonce, data=ctxt).verify(mac)
    except ValueError:
        raise ValueError("MAC check failed")
    
    k1_int = bytes_to_int(k1)
    ctxt_int = bytes_to_int(ctxt)
    
    cipher = SimonCipher(k1_int, mode='CTR', init=bytes_to_int(nonce), block_size=128, key_size=128)
    plaintext_int = cipher.decrypt(ctxt_int)
    plaintext = int_to_bytes(plaintext_int, len(ctxt))
    #plaintext = cipher.decrypt(ctxt)
    print("Decrypted Plaintext (before unpad):", plaintext)
    plaintext = unpad(plaintext)

    return plaintext
    '''


iv = get_random_bytes(16)
k1 = get_random_bytes(16)
k2 = get_random_bytes(32)
plaintext = b"Hello, world!" * 8

print("Original Plaintext:", plaintext)
ctxt, mac, mac_nonce = eam_encrypt(plaintext, k1, k2, iv)
decrypted = eam_decrypt_and_verify(ctxt, mac, k1, k2, iv, mac_nonce)
print("Decrypted Text:", decrypted)

#assert plaintext == decrypted



