from binascii import unhexlify
from Crypto.Random import get_random_bytes
from simon import SimonCipher
from Crypto.Hash import Poly1305
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash.HMAC import HMAC
from Crypto.Hash import SHA256
from speck import SpeckCipher


def eam_encrypt(ptxt, k1, k2, iv):
    ptxt_bytes = ptxt.encode()
    iv_int = int.from_bytes(iv, byteorder='big')
    k1_int = int.from_bytes(k1, byteorder='big')
    cipher = SimonCipher(k1_int, block_size=128, key_size=128, init=iv_int, mode='CTR', counter=1)
    ctxt = b''
    for i in range(0, len(ptxt_bytes), 16):
        block = ptxt_bytes[i:i+16]
        if len(block) < 16:
            block = pad(block, 16)
        block_int = int.from_bytes(block, byteorder='big')
        ctxt_block = cipher.encrypt(block_int)
        ctxt += ctxt_block.to_bytes(16, byteorder='big')
    ctxt_int = int.from_bytes(ctxt, byteorder='big')
    
    mac, mac_nonce = poly(k2, ptxt_bytes)

    return ctxt_int, mac, mac_nonce

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
    try:
        ptxt = unpad(ptxt, 16).decode()  
    except ValueError as e:
        raise ValueError("Incorrect padding or corrupted data") from e

    mac_nonce = unhexlify(mac_nonce)
    poly = Poly1305.new(key=k2, nonce=mac_nonce, cipher=AES)
    poly.update(str.encode(ptxt))
    vmac = poly.hexdigest()

    if mac == vmac:
        print("MAC verification successful.")
    else:
        print("MAC verification failed.")
        ptxt = None

    return ptxt

def poly(k2, ptxt):
    #k2_bytes = bytes.fromhex(hex(k2).lstrip('0x'))
    poly = Poly1305.new(key=k2, cipher=AES)
    poly.update(ptxt)
    poly_mac = poly.hexdigest()
    mac_nonce = poly.nonce.hex()
    
    return poly_mac, mac_nonce


#Testing 1a

iv = get_random_bytes(16)
k1 = get_random_bytes(16)
k2 = get_random_bytes(32)
plaintext = "Hello, world!"

print("Original Plaintext:", plaintext)
ctxt, mac, mac_nonce = eam_encrypt(plaintext, k1, k2, iv)
decrypted = eam_decrypt_and_verify(ctxt, mac, k1, k2, iv, mac_nonce)
decrypted = decrypted
print("Decrypted Text:", decrypted)

assert plaintext == decrypted



