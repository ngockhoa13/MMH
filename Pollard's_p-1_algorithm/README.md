## **Pollard's p-1 algorithm**
Pollard's p−1 attack là một phương pháp tấn công trên các hệ thống mật mã RSA khi một trong các thừa số của mô-đun $n$ có tính chất đặc biệt. Cụ thể, tấn công này dựa trên việc $p − 1$ hoặc $q − 1$ có các thừa số nguyên tố nhỏ, tức là $p − 1$ hoặc $q − 1$ là "smooth".
Mục tiêu là tìm một trong các thừa số nguyên tố $p$ hoặc $q$ của mô-đun $n=p×q$. Một khi tìm được $p$, ta có thể dễ dàng tính được $q=\frac{n}{p}$ và từ đó phá được hệ thống RSA.

Từ [Định lý nhỏ của Fermat](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem)$^{(1)}$: $a^{p -1}$ ≡ $1$ $(mod$ $p$$)$ trong đó $p$ là số nguyên tố và $a$ là số nguyên dương bất kì sao cho $a$ và $p$ là 2 số nguyên tố cùng nhau.
Khi đó, tồn tại một số $k$, sao cho:
$a^{k(p -1)}$ ≡ $1 \pmod{p}$,
$a^{k(p -1)}$ - $1$ = $r * p$.

Bây giờ ta lấy GCD của $p*r$ và $n = p*q$, ta sẽ có:
$gcd(p*r, n) = p$
Và như vậy, ta đã thu được một trong các thừa số của $n$.

Để thực hiện phương pháp này, chúng ta cần đoán giá trị của $L = k(p-1)$ bằng cách thử nghiệm. Đặt $a$ lên lũy thừa của các số nguyên với một số lượng lớn các thừa số nguyên tố, ta có khả năng cao sẽ tìm thấy các thừa số của $p-1$. Sau đó, chúng ta tính $gcd(a^L - 1, N)$ và nếu kết quả khác không, chúng ta đã thành công trong việc phân tích $n$.

Cách phổ biến nhất là tính $a^{k!} \pmod{n}$ và sau đó tính $gcd$ từ đó. Chúng ta có thể làm điều này một cách hiệu quả hơn bằng cách lặp đi lặp lại việc đặt $a$ vào lũy thừa lớn hơn một đơn vị so với lần lặp trước đó. Ví dụ, tính $a$, $a^2$, $(a^2)^3$, $((a^2)^3)^4$, ... và tính $gcd$ mỗi lần - điều này giúp chúng ta tìm được nhiều thừa số hơn. Một lựa chọn phổ biến cho $a$ là 2.

#### Challenge:
1. Problem:
```
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
```
2. Ý tưởng
* Điểm yếu chính của bài này đó là p là 1 smooth number (nghĩa là p-1 có thể factor thành tích các số nguyên tố nhỏ)
* Vì thế ở bài này, ta sẽ sử dụng thuật toán Pollard's p − 1 algorithm
3. Giải mã
```
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
```
Kết quả:
![image](https://hackmd.io/_uploads/Syxa4A3XC.png)
$=>$ **Giải pháp:** 
- Chọn các số nguyên tố ngẫu nhiên và lớn: Đảm bảo rằng các số nguyên tố $p$ và $q$ được chọn ngẫu nhiên và có độ dài đủ lớn, ví dụ như 1024-bit hoặc lớn hơn. Tránh chọn các số nguyên tố mà $p-1$ hoặc $q-1$ có các thừa số nguyên tố nhỏ.
- Kiểm tra tính "smooth": Trước khi sử dụng các số nguyên tố $p$ và $q$, kiểm tra xem $p-1$ và $q-1$ có các thừa số nguyên tố nhỏ hay không. Nếu có, chọn lại các số nguyên tố khác.