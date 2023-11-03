from Crypto.Random import get_random_bytes
from simon import SimonCipher
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class question2:
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
            ptxt = unpad(ptxt, 8).decode()
            return ptxt  
        except ValueError as e:
            raise ValueError("Incorrect padding or corrupted data") from e

    def __init__(self, k1, k2):
        self.key1 = k1
        self.key2 = k2

    def bhash(self, associated, ptxt):
        state, _ = self.simon_ctr_encrypt(self.key2, b'\x00'*16, b'\x00'*16)
        associated_blocks = 0
        ptxt_blocks = 0
        for i in range(0, len(associated), 8):
            associated_block = associated[i:i+8]
            associated_block_int = int.from_bytes(associated_block, byteorder='big')
            state ^= associated_block_int
            associated_blocks += 1
        
        for i in range(0, len(ptxt), 8):
            ptxt_block = ptxt[i:i+8]
            ptxt_block_int = int.from_bytes(ptxt_block, byteorder='big')
            state ^= ptxt_block_int
            ptxt_blocks += 1
        
        ctxt_block = (associated_blocks << 32) | ptxt_blocks
        state ^= ctxt_block
        return state

    def cw_mac(self, plaintext, associated, nonce):
        nonce_int = int.from_bytes(nonce, byteorder='big')
        input_val = nonce_int ^ self.bhash(associated, plaintext)
        input_val_bytes = input_val.to_bytes((input_val.bit_length() + 7) //8, byteorder='big')
        print(input_val_bytes)
        tag, _ = self.simon_ctr_encrypt(self.key2, input_val_bytes, b'\x00'*16)
        print(tag)

        return tag

#Testing 2a

    key = get_random_bytes(16)
    nonce = get_random_bytes(8)
    plaintext = "Hello, world!"
    print(plaintext)
    ctxt = simon_ctr_encrypt(plaintext, key, nonce)
    decrypted = simon_ctr_decrypt(ctxt, key, nonce)
    print(decrypted)

    plaintext = "This is a really long message, I'm talking really long, like longer than 128 bits kind of long, I'm talking so long that it will really test my functions block splitting capabilities kind of long."
    print(plaintext)
    ctxt = simon_ctr_encrypt(plaintext, key, nonce)
    decrypted = simon_ctr_decrypt(ctxt, key, nonce)
    print(decrypted)