from Crypto.Util.number import *
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
import math
from random import randint

n = 946902507540700615116722778989450653590548094719975258404428635824223885429859400013148542750532655848137817236501427137842632394178636593414898111773400259737436539561093396387247554233652190487195750937208192296180729433557694572192789421746385636865478410379375957638720811646078283629092428814402371897453063819196203710745379142644672365434900851
e = 65537
c = 411257753205137951966849655426265417206577646557374469102494036697912658917165733681993108277730599648861187118466540881908546077797135619101266856247036847986323105673547950251650071688369706147562374659677471207169077621176021927834571204253019708824395824083281088555423225202289205856131539673564626195816372274312361153612659898448360481945012792

ok = bytes_to_long(b'nn90ckh04_w4s_h3r3')
def isqrt(n):
    x = n
    y = (x + n // x) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def fermat(n):
    a = isqrt(n)
    b2 = a*a - n
    b = isqrt(n)
    count = 0
    while b*b != b2:
        a = a + 1
        b2 = a*a - n
        b = isqrt(b2)
        count += 1
    p = a+b
    q = a-b
    assert n == p * q
    return p, q
n1 = n * ok 

p, q = fermat(n1)
q = q // ok 
assert p*q == n
pl = long_to_bytes(pow(c,pow(65537,-1,(p-1)*(q-1)),n))
print(pl)
