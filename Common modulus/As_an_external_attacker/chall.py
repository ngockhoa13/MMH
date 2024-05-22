from Crypto.Util.number import *
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from secret import FLAG

p=getPrime(512)
q=getPrime(512)
n=p*q
e1=71
e2=101
msg=btl(FLAG)
c1 = pow(msg, e1, n)
c2 = pow(msg, e2, n)
print(f"{n = }")
print(f"{e1 = }")
print(f"{e2 = }")
print(f"{c1 = }")
print(f"{c2 = }")
