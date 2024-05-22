from Crypto.Util.number import getPrime, isPrime 
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl 
from random import randint 
from secret import FLAG

def genprimes():
    ok =  btl(b'nn90ckh04_w4s_h3r3')
    while True:
        p = getPrime(512)
        q = ok *p +  randint(pow(2,255), pow(2, 256) - 1)
        if isPrime(q):
            return p, q

p, q = genprimes()

n = p * q

e = 65537

msg = btl(FLAG)

c = pow(msg, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{c = }")

"""
n = 946902507540700615116722778989450653590548094719975258404428635824223885429859400013148542750532655848137817236501427137842632394178636593414898111773400259737436539561093396387247554233652190487195750937208192296180729433557694572192789421746385636865478410379375957638720811646078283629092428814402371897453063819196203710745379142644672365434900851
e = 65537
c = 411257753205137951966849655426265417206577646557374469102494036697912658917165733681993108277730599648861187118466540881908546077797135619101266856247036847986323105673547950251650071688369706147562374659677471207169077621176021927834571204253019708824395824083281088555423225202289205856131539673564626195816372274312361153612659898448360481945012792
"""


