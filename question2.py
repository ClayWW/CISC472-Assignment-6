from Crypto.Random import get_random_bytes
from simon import SimonCipher
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long

class Question2:
    
    @staticmethod
    def simon_ctr_encrypt(ptxt, key, nonce):
        ptxt_bytes = ptxt.encode() if not isinstance(ptxt, bytes) else ptxt
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
    
    @staticmethod
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
    '''
    def gf_mult(self, x, y):
        primitive = 0b100011011
        result = 0
        for i in range(64):
            if y & (1 << i):
                result ^= x << 1
            if result & (1 << 64):
                result >>= 1
                result ^= primitive
            x <<= 1
            if x & (1 << 64):
                x >>= 1
                x ^= primitive
        return result & ((1 << 64) - 1)
    
    def gf_mult(self, x, y):
        result = 0
        for i in range(64):
            if y & (1 << i):
                result ^= x
            if x & (1 << 63):  # Check if x needs reduction
                x ^= (1 << 63)  # Reduction for polynomial X^64 + 1 is just removing the bit
            x <<= 1
        return result
    '''
    def gf_mult(self, x, y):
        result = 0
        for i in range(64):
            if y & (1 << i):
                result ^= x
            if x & (1 << 63):
                x <<= 1
                x &= (1 << 64) - 1
            else:
                x <<= 1
        return result

    def bhash(self, associated, ptxt):
        state= self.simon_ctr_encrypt(self.key2, b'\x00'*16, b'\x00'*16)
        associated_blocks = 0
        ptxt_blocks = 0

        associated_bytes = associated.encode() if isinstance(associated, str) else associated
        ptxt_bytes = ptxt.encode() if isinstance(ptxt, str) else ptxt

        for i in range(0, len(associated_bytes), 8):
            associated_block = associated_bytes[i:i+8]
            #associated_block_int = int.from_bytes(associated_block, byteorder='big')
            if len(associated_block) < 8:
                associated_block = pad(associated_block, 8)
            associated_blocks += 1
            #state ^= associated_block_int
            state = self.gf_mult(state, bytes_to_long(associated_block))
        

        
        for i in range(0, len(ptxt_bytes), 8):
            ptxt_block = ptxt_bytes[i:i+8]
            #ptxt_block_int = int.from_bytes(ptxt_block, byteorder='big')
            if len(ptxt_block) < 8:
                ptxt_block = pad(ptxt_block, 8)
            ptxt_blocks += 1
            #state ^= ptxt_block_int
            state = self.gf_mult(state, bytes_to_long(ptxt_block))
        
        ctxt_block = (associated_blocks << 32) | ptxt_blocks
        #state ^= ctxt_block
        state = self.gf_mult(state, ctxt_block)
        return state

    def cw_mac(self, plaintext, associated, nonce):
        nonce_int = int.from_bytes(nonce, byteorder='big')
        input_val = nonce_int ^ self.bhash(associated, plaintext)
        input_val_bytes = input_val.to_bytes((input_val.bit_length() + 7) //8, byteorder='big')
        #print(input_val_bytes)
        tag = self.simon_ctr_encrypt(self.key2, input_val_bytes, b'\x00'*16)
        #print(tag)

        return tag


#Testing 2a
key = get_random_bytes(16)       
nonce = get_random_bytes(8)
plaintext = "Hello, world!"
print(plaintext)
ctxt = Question2.simon_ctr_encrypt(plaintext, key, nonce)
decrypted = Question2.simon_ctr_decrypt(ctxt, key, nonce)
print(decrypted)

plaintext = "This is a really long message, I'm talking really long, like longer than 128 bits kind of long, I'm talking so long that it will really test my functions block splitting capabilities kind of long."
print(plaintext)
ctxt = Question2.simon_ctr_encrypt(plaintext, key, nonce)
decrypted = Question2.simon_ctr_decrypt(ctxt, key, nonce)
print(decrypted)

#Testing 2b and 2c

k1 = get_random_bytes(16)
k2 = get_random_bytes(16)
q2_instance = Question2(k1, k2)

plaintext = "Hello, world!"
associated_data = b"header"
tag = q2_instance.cw_mac(associated_data, plaintext, nonce)

#bhash testing
k2 = get_random_bytes(16)
q2_instance_2 = Question2(k1, k2)

hash1 = q2_instance_2.bhash(associated_data, plaintext)
hash2 = q2_instance_2.bhash(associated_data, plaintext)

assert hash1 == hash2

plaintext = "Hello World!"
hash_changed = q2_instance_2.bhash(associated_data, plaintext)
assert hash1 != hash_changed

#cw_mac testing
k1 = get_random_bytes(16)
k2 = get_random_bytes(16)
associated_data = b"header"
plaintext = "Hello, world!"
nonce = get_random_bytes(8)
q2_instance_2 = Question2(k1, k2)

tag = q2_instance_2.cw_mac(plaintext, associated_data, nonce)
new_tag = q2_instance_2.cw_mac(plaintext, associated_data, nonce)
assert tag == new_tag

new_nonce = get_random_bytes(8)
diff_tag = q2_instance_2.cw_mac(plaintext, associated_data, new_nonce)
assert tag != diff_tag