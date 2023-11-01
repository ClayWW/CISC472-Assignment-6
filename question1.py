import binascii
from Crypto.Random import get_random_bytes
from simon import SimonCipher
from Crypto.Hash import Poly1305
from Crypto.Cipher import AES

def bytes_to_int(input):
    if isinstance(input, int):
        return input
    return int(binascii.hexlify(input), 16)

def int_to_bytes(input, length):
    if isinstance(input, bytes):
        return input
    return binascii.unhexlify(f'{input:0{2*length}x}')

def bytes_to_hex(input_bytes):
    if isinstance(input, hex):
        return input
    return binascii.hexlify(input_bytes).decode()

def hex_to_bytes(input_hex):
    if isinstance(input, bytes):
        return input
    return binascii.unhexlify(input_hex)

def eam_encrypt(plaintext, k1, k2, nonce):
    k1_int = bytes_to_int(k1)
    #plaintext_int = bytes_to_int(plaintext)

    cipher = SimonCipher(k1_int, mode='CTR', init=bytes_to_int(nonce), block_size=128, key_size=128)
    ciphertext = cipher.encrypt(plaintext)
    #ciphertext_int = cipher.encrypt(plaintext_int)
    #ciphertext = int_to_bytes(ciphertext_int, len(plaintext))

    mac = Poly1305.new(key=k2, cipher=AES, nonce=nonce, data=ciphertext).digest()

    return ciphertext, mac

def eam_decrypt_and_verify(ctxt, mac, k1, k2, nonce):
    try:
        Poly1305.new(key=k2, cipher=AES, nonce=nonce, data=ctxt).verify(mac)
    except ValueError:
        raise ValueError("MAC check failed")
    
    k1_int = bytes_to_int(k1)
    #ctxt_int = bytes_to_int(ctxt)
    
    cipher = SimonCipher(k1_int, mode='CTR', init=bytes_to_int(nonce), block_size=128, key_size=128)
    #plaintext_int = cipher.decrypt(ctxt_int)
    #plaintext = int_to_bytes(plaintext_int, len(ctxt))
    plaintext = cipher.decrypt(ctxt)

    return plaintext

nonce = get_random_bytes(16)
k1 = get_random_bytes(16)
k2 = get_random_bytes(32)
plaintext = b"Hello, world!" * 8

ctxt, mac = eam_encrypt(plaintext, k1, k2, nonce)
decrypted = eam_decrypt_and_verify(ctxt, mac, k1, k2, nonce)

print("Original plaintext:", plaintext)
print("Decrypted text:", decrypted)

print("\nOriginal ciphertext:", ctxt)
print("Decrypted ciphertext before decryption:", bytes_to_int(ctxt))

def test_simon_cipher_directly():
    k1_int = bytes_to_int(k1)
    plaintext_int = bytes_to_int(plaintext)
    
    cipher = SimonCipher(k1_int, mode='CTR', init=bytes_to_int(nonce))
    ciphertext_int = cipher.encrypt(plaintext_int)
    
    cipher = SimonCipher(k1_int, mode='CTR', init=bytes_to_int(nonce))
    decrypted_int = cipher.decrypt(ciphertext_int)
    
    decrypted_text = int_to_bytes(decrypted_int, len(plaintext))

    print("Encrypted with SimonCipher:", int_to_bytes(ciphertext_int, len(plaintext)))
    print("Decrypted with SimonCipher:", decrypted_text)
    
    assert decrypted_text == plaintext

test_simon_cipher_directly()

assert plaintext == decrypted



