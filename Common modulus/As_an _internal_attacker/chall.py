from Crypto.Util.number import *
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from secret import FLAG

e=65537
your_e = getPrime(20)
msg=btl(FLAG)
p=getPrime(2048)
q=getPrime(2048)
n=p*q
assert(msg < n)
ct=pow(msg, e, n)
your_d = inverse(your_e, (p-1)*(q-1))
print(f"{your_e = }")
print(f"{your_d = }")
print(f"{n = }")
print(f"{e = }")
print(f"{ct = }")
