from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl 
from gmpy2 import mpz, powmod, next_prime, gcd
n = 14090066340769492892687721051395083732848531945440621483246230325785810408947771566776702261063429678632393503800218806124753109322072934858824097727839071280654420287173728649372680726989806257870962310367254445129428046758398593654841521304954484643443057367289493400935838036412754775756761777673116618404852262719575597640844372730888506784543733419706800609372566457253914512232906503338467846039128571992198068537953839930859911444458067659489614806618797726125368711294742230828305976453668621064071432163243027382059658544483913491450465670391956760603388219682474601466365864712464099405924165099304723125153
e = 65537
c = 1697250861096906815725469337536133199646346640402130878937413247350919145953179933447918537956993734927062083225221453448644734502521343950768568873404947274324821727822954072445988211354297594565913536961459391941337854164877963789740377918563166386113577105636240729037940932413161906181548959327392470405841320788778394859965343020858962035773551545025726702325801962420022757015919130708057418239422883994032138542561598385254627936011296380714101102015421540464202908294005568291650147308349669384480117250131637267924350422080277578011616299256074498117724121271444883432366746737652955345007189321480283917048
def polard(n: int, cap):
    g = mpz(3)
    cur = mpz(2)
    while cur < cap:
        g = powmod(g, cur**10, n)
        if g == 1:
            break
        check = gcd(g - 1, n)
        if check != 1:
            return int(check)
        nx = next_prime(cur)
        cur = nx
    return None

p = polard(n, 2**18)
q = n//p
assert p*q == n

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

m = ltb(pow(c, d, n))

print(m)