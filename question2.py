from Crypto.Random import get_random_bytes
from simon import SimonCipher
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def simon_ctr_encrypt(ptxt, key, nonce):
    ptxt_bytes = ptxt.encode()
    nonce_int = int.from_bytes(nonce, byteorder='big')
    key_int = int.from_bytes(key, byteorder='big')
    cipher = SimonCipher(key_int, block_size=64, key_size=128, init=nonce_int, mode='CTR', counter=1)
    ctxt = b''
    for i in range(0, len(ptxt_bytes), 8):
        block = ptxt_bytes[i:i+8]
        if len(block) < 8:
            block = pad(block, 8)
        block_int = int.from_bytes(block, byteorder='big')
        ctxt_block = cipher.encrypt(block_int)
        ctxt += ctxt_block.to_bytes(8, byteorder='big')
    ctxt_int = int.from_bytes(ctxt, byteorder='big')

    return ctxt_int

def simon_ctr_decrypt(ctxt, key, nonce):
    nonce_int = int.from_bytes(nonce, byteorder='big')
    key_int = int.from_bytes(key, byteorder='big')
    cipher = SimonCipher(key_int, block_size=64, key_size=128, init=nonce_int, mode='CTR', counter=1)
    ctxt_bytes = ctxt.to_bytes((ctxt.bit_length() + 7) // 8, byteorder='big')
    ptxt = b''
    for i in range(0, len(ctxt_bytes), 8):
        block = ctxt_bytes[i:i+8]
        block_int = int.from_bytes(block, byteorder='big')
        ptxt_block = cipher.decrypt(block_int)
        ptxt += ptxt_block.to_bytes(8, byteorder='big')
    try:
        ptxt = unpad(ptxt, 16).decode()
        return ptxt  
    except ValueError as e:
        raise ValueError("Incorrect padding or corrupted data") from e


    