import binascii
from simon import SimonCipher
from Crypto.Hash import Poly1305
from Crypto.Cipher import AES

def bytes_to_int(input):
    return int(binascii.hexlify(input), 16)

def int_to_bytes(input, length):
    return binascii.unhexlify(f'{input:0{2*length}x}')

def eam_encrypt(plaintext, k1, k2, nonce):
    k1_int = bytes_to_int(k1)
    plaintext_int = bytes_to_int(plaintext)

    cipher = SimonCipher(k1_int, mode='CTR', init=bytes_to_int(nonce))
    ciphertext_int = cipher.encrypt(plaintext_int)
    ciphertext = int_to_bytes(ciphertext_int, len(plaintext))

    cipher_aes = AES.new(k2, AES.MODE_ECB)
    mac = Poly1305.new(mac_data=ciphertext, cipher=cipher_aes).digest()

    return ciphertext+mac

def eam_decrypt_and_verify(ctxt_mac, k1, k2, nonce):
    mac = ctxt_mac[-16:]
    ctxt = ctxt_mac[:-16]

    cipher_aes = AES.new(k2, AES.MODE_ECB)
    try:
        Poly1305.new(mac_data=ctxt, cipher=cipher_aes).verify(mac)
    except ValueError:
        raise ValueError("MAC check failed")
    
    k1_int = bytes_to_int(k1)
    cipher = SimonCipher(k1_int, mode='CTR', init=bytes_to_int(nonce))
    plaintext_int = cipher.decrypt(bytes_to_int(ctxt))
    plaintext = int_to_bytes(plaintext_int, len(ctxt))

    return plaintext

nonce = 0
k1 = 0
k2 = 0
plaintext = b"Hello, world!" * 8

ctxt_mac = eam_encrypt(plaintext, k1, k2, nonce)
decrypted = eam_decrypt_and_verify(ctxt_mac, k1, k2, nonce)
assert decrypted == plaintext





