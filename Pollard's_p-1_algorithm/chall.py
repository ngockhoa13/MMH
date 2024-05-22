from Crypto.Util.number import getPrime, isPrime
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from random import randint
from secret import FLAG

def gensmoothprime(bitlen, smoothness ):
    p = 2
    while (bitlen - p.bit_length()) > 2*smoothness:
        p = p * getPrime(smoothness)
    while True:
        bit = bitlen - p.bit_length()
        q = p * getPrime(bit//2) * getPrime(bit//2)
        if isPrime(q+1):
            return q + 1

def genprimes():
    p = gensmoothprime(1024, 18)
    q = getPrime(1024)
    return p, q

p, q = genprimes()

n = p * q

e = 65537

msg = btl(FLAG)

c = pow(msg, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")

