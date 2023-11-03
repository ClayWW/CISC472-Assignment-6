from binascii import unhexlify
from Crypto.Random import get_random_bytes
from simon import SimonCipher
from Crypto.Hash import Poly1305
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, CMAC
from Crypto.Hash import SHA256
from speck import SpeckCipher


# Encrypts a plaintext using Simon cipher in CTR mode.
# It first encodes the plaintext, calculates integer values for the IV and key,
# then encrypts the plaintext in 16-byte blocks, padding the last block if necessary.
# It also generates a MAC (Message Authentication Code) using Poly1305 and returns the encrypted text,
# the MAC, and a nonce used for the MAC.
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

# Decrypts ciphertext and verifies its integrity using the provided MAC and nonce.
# It uses the Simon cipher in CTR mode to decrypt the data and Poly1305 to verify the MAC.
# It returns the decrypted plaintext if the MAC is verified, otherwise, it returns None.
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
        return ptxt
    else:
        print("MAC verification failed.")
        return None

# Generates a MAC using the Poly1305 algorithm for a given plaintext and key.
# It returns the MAC and the nonce used during the MAC computation.
def poly(k2, ptxt):
    poly = Poly1305.new(key=k2, cipher=AES)
    poly.update(ptxt)
    poly_mac = poly.hexdigest()
    mac_nonce = poly.nonce.hex()
    
    return poly_mac, mac_nonce

# Encrypts plaintext using Speck cipher in CBC mode and HMAC for integrity.
# It first encodes the plaintext, calculates integer values for the IV and key,
# generates an HMAC for the plaintext, appends it to the plaintext, and encrypts everything in 16-byte blocks.
# The last block is padded if necessary. Returns the encrypted text as an integer.
def mte_encrypt(ptxt, k1, k2, iv):
    ptxt_bytes = ptxt.encode()
    iv_int = int.from_bytes(iv, byteorder='big')
    k1_int = int.from_bytes(k1, byteorder='big')
    hmac = HMAC.new(key=k2, msg=ptxt_bytes, digestmod=SHA256)
    mac = hmac.digest() #in bytes

    ptxt_mac = ptxt_bytes + mac

    speck_cipher = SpeckCipher(k1_int, block_size=128, key_size=128, mode='CBC', init=iv_int)
    ctxt = b''
    for i in range(0, len(ptxt_mac), 16):
        block = ptxt_mac[i:i+16]
        if len(block) < 16:
            block = pad(block, 16)
        block_int = int.from_bytes(block, byteorder='big')
        ctxt_block = speck_cipher.encrypt(block_int)
        ctxt += ctxt_block.to_bytes(16, byteorder='big')
    ctxt_int = int.from_bytes(ctxt, byteorder='big')
    
    return ctxt_int

# Decrypts ciphertext encrypted by mte_encrypt and verifies HMAC.
# Uses Speck cipher in CBC mode for decryption and HMAC with SHA256 for MAC verification.
# It decodes the ciphertext from integer to bytes, decrypts it block by block, unpads it,
# and then verifies the HMAC. Returns the plaintext if HMAC is valid, else returns None.
def mte_decrypt_and_verify(ctxt, k1, k2, iv):
    iv_int = int.from_bytes(iv, byteorder='big')
    k1_int = int.from_bytes(k1, byteorder='big')
    speck_cipher = SpeckCipher(k1_int, block_size=128, key_size=128, mode='CBC', init=iv_int)
    ctxt_bytes = ctxt.to_bytes((ctxt.bit_length() + 7) // 8, byteorder='big')
    ptxt_mac = b''
    for i in range(0, len(ctxt_bytes), 16):
        block = ctxt_bytes[i:i+16]
        block_int = int.from_bytes(block, byteorder='big')
        ptxt_mac_block = speck_cipher.decrypt(block_int)
        ptxt_mac += ptxt_mac_block.to_bytes(16, byteorder='big')

    try:
        ptxt_mac = unpad(ptxt_mac, 16)
    except ValueError as e:
        raise ValueError("Incorrect padding or corrupted data") from e

    ptxt = ptxt_mac[:-32]
    print("Plaintext: ", ptxt)
    mac = ptxt_mac[-32:]
    print("MAC: ", mac)
    

    hmac = HMAC.new(k2, digestmod=SHA256)
    hmac.update(ptxt)
    try:
        hmac.verify(mac)
        print("MAC verification successful.")
        return ptxt.decode()
    except ValueError:
        print("MAC verification failed.")
        return None

# Encrypts plaintext using Simon cipher in CTR mode and CMAC for integrity.
# It encodes the plaintext to bytes, encrypts it in 16-byte blocks with necessary padding,
# and then generates a CMAC. Returns the encrypted text and the CMAC.
def etm_encrypt(ptxt, k1, k2, iv):
    ptxt_bytes = ptxt.encode()
    iv_int = int.from_bytes(iv, byteorder='big')
    k1_int = int.from_bytes(k1, byteorder='big')

    cipher = SimonCipher(k1_int, block_size=128, key_size=256, mode='CTR', init=iv_int)

    ctxt = b''
    for i in range(0, len(ptxt_bytes), 16):
        block = ptxt_bytes[i:i+16]
        if len(block) < 16:
            block = pad(block, 16)
        block_int = int.from_bytes(block, byteorder='big')
        ctxt_block = cipher.encrypt(block_int)
        ctxt += ctxt_block.to_bytes(16, byteorder='big')

    cmac = CMAC.new(k2, ciphermod=AES)
    cmac.update(ctxt)
    mac = cmac.digest()

    return ctxt, mac 

# Decrypts ciphertext encrypted by etm_encrypt and verifies CMAC.
# It first verifies the CMAC, then decrypts the ciphertext using Simon cipher in CTR mode.
# If CMAC is valid, it unpads and decodes the plaintext and returns it, otherwise returns None.
def etm_decrypt_and_verify(ctxt, mac, k1, k2, iv):
    cmac = CMAC.new(k2, ciphermod=AES)
    cmac.update(ctxt)
    try:
        cmac.verify(mac)
        print("MAC verification successful")

        iv_int = int.from_bytes(iv, byteorder='big')
        k1_int = int.from_bytes(k1, byteorder='big')
        cipher = SimonCipher(k1_int, block_size=128, key_size=256, mode='CTR', init=iv_int)

        ptxt = b''
        for i in range(0, len(ctxt), 16):
            block = ctxt[i:i+16]
            block_int = int.from_bytes(block, byteorder='big')
            ptxt_block = cipher.decrypt(block_int)
            ptxt += ptxt_block.to_bytes(16, byteorder='big')
        
        try:
            ptxt = unpad(ptxt, 16)
        except ValueError as e:
            raise ValueError("Incorrect padding or corrupted data") from e

        return ptxt.decode()
    except ValueError:
        print("MAC verification failed.")
        return None



#Testing 1a

iv = get_random_bytes(16)
k1 = get_random_bytes(16)
k2 = get_random_bytes(32)
plaintext = "Hello, world!"

print("Original Plaintext: ", plaintext)
ctxt, mac, mac_nonce = eam_encrypt(plaintext, k1, k2, iv)
decrypted = eam_decrypt_and_verify(ctxt, mac, k1, k2, iv, mac_nonce)
print("Decrypted Text: ", decrypted)

assert plaintext == decrypted

plaintext = "This is a really long message, I'm talking really long, like longer than 128 bits kind of long, I'm talking so long that it will really test my functions block splitting capabilities kind of long."
print("Original Plaintext: ", plaintext)
ctxt, mac, mac_nonce = eam_encrypt(plaintext, k1, k2, iv)
decrypted = eam_decrypt_and_verify(ctxt, mac, k1, k2, iv, mac_nonce)
print("Decrypted Text: ", decrypted)

assert plaintext == decrypted


#Testing 1b

plaintext = "Hello, world!"
print("Original Plaintext:", plaintext)
ctxt = mte_encrypt(plaintext, k1, k2, iv)
decrypted = mte_decrypt_and_verify(ctxt, k1, k2, iv)
print("Decrypted Text: ", decrypted)

assert plaintext == decrypted

plaintext = "This is a really long message, I'm talking really long, like longer than 128 bits kind of long, I'm talking so long that it will really test my functions block splitting capabilities kind of long."
print("Original Plaintext:", plaintext)
ctxt = mte_encrypt(plaintext, k1, k2, iv)
decrypted = mte_decrypt_and_verify(ctxt, k1, k2, iv)
print("Decrypted Text: ", decrypted)

assert plaintext == decrypted


#Testing 1c

plaintext = "Hello, world!"
temp = k1
k2 = k1
k1 = temp
print("Original Plaintext:", plaintext)
ctxt, mac = etm_encrypt(plaintext, k1, k2, iv)
decrypted = etm_decrypt_and_verify(ctxt, mac, k1, k2, iv)
print("Decrypted Text: ", decrypted)

assert plaintext == decrypted

plaintext = "This is a really long message, I'm talking really long, like longer than 128 bits kind of long, I'm talking so long that it will really test my functions block splitting capabilities kind of long."

print("Original Plaintext:", plaintext)
ctxt, mac = etm_encrypt(plaintext, k1, k2, iv)
decrypted = etm_decrypt_and_verify(ctxt, mac, k1, k2, iv)
print("Decrypted Text: ", decrypted)

assert plaintext == decrypted