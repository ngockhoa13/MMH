from Crypto.Util.number import *
from secret import FLAG

pt=bytes_to_long(FLAG)
p1=getPrime(512)
q1=getPrime(512)
N1=p1*q1
e=3
ct1=pow(pt,e,N1)
p2=getPrime(512)
q2=getPrime(512)
N2=p2*q2
ct2=pow(pt,e,N2)
p3=getPrime(512)
q3=getPrime(512)
N3=p3*q3
ct3=pow(pt,e,N3)

print(f"{N1 = }")
print(f"{N2 = }")
print(f"{N3 = }")
print(f"{e = }")
print(f"{ct1 = }")
print(f"{ct2 = }")
print(f"{ct3 = }")
