from Crypto.Hash import SHA256

class hash_chain:
    h = SHA256.new()

    def __init__(self, length, seedP, seedQ):
        self.chainLength = length
        self.indexLoc = -1
        self.hash_chain_p = [seedP] * length
        self.hash_chain_q = [seedQ] * length

        print("Generating hash chains length: ", length, "with seeds p: ", seedP, " q: ", seedQ)
        for i in range (0, length-1):
            temp = self.generate_hash(self.hash_chain_p[i])
            self.hash_chain_p[i+1] = temp
            temp = self.generate_hash(self.hash_chain_q[i])
            self.hash_chain_q[i+1] = temp
   
    def generate_key(self):
        self.indexLoc += 1
        print("Generating key using hash: p,", self.indexLoc, " q,", (self.chainLength-1 - self.indexLoc))
        if self.indexLoc > self.chainLength-1:
            return None
        else:
            xor = self.XOR(self.hash_chain_p[self.indexLoc], self.hash_chain_q[self.chainLength-1 - self.indexLoc])
            print("New key: ", xor)
            return xor

    def generate_hash(self, curr):
        hash_chain.h.update(curr)
        #print(hash_chain.h.digest())
        return hash_chain.h.digest()

    def XOR(self, seedP, seedQ):
        result = b''
        for p, q in zip(seedP, seedQ):
            result = result + bytes([p^q])
            #print(result)
        return result