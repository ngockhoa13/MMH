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
    p = gensmoothprime(2048, 18)
    q = getPrime(2048)
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

n = 126292694631338918323183674346082201224823400801238971169207231289116533933478702806693693754888209671277842075203437443710467284961803512354069182430556633288465671864567172805937082197360829508056460015745786247374268228514494497413150345579545449156914128912046490186668557935991938933737956430063635788384679590406767833000546221879780346405407367585841887887800043212228542430246601418517714869726080322899932609372923771385233534323248411898789065018357038870216201115504825581232195487545232148308347855607275378749427008431937603719300397312295251224202142648688457768390564220512298866547069838321183103439259792003074630619115062250159012080585841945678953918806515749987369377397137042963999660996667239336033166055381696036540189635178824478305768054565649565860907696681575237405570329533585544828404851214282033372317734485038316271776153525934082758972156256431110220365000713005029276248598508944246302881938441275105695868653927904243252050887460182329134513847142576630265982115555274321516570134883827525226516166535871431401579364278729404086064102609516126645381622353918453221209645546537781460668432365239411830088466574185187652297932974108879292510088142571601148492081651286809586064035778393612464529604973
e = 65537
c = 121931961047086397322252430185145062380253326478344338793368357222450510524901555361499090490753113095495924773831769146857823251800567938127638021012975553552605832887904944324100637556692738992895005379525856673541648430262273636917917708745257156820110267551697203826072400407185637887923135833247199738496130621999381420632182517357986242758777873461767106437610958573410258751791745543285506809862937014972074688506672359960605626611819852813090535922152859081686477784100324779193508784446712396628503714079074901506736892809045618135294746826218763072560379616962852080704220837377593780786757901103668522022286903282979884783839899305676400066987003888930630925256761506238043034054949107713315266905432273896326184749526000128120021884148370591169925629265239522425483761251531309616205593873978067831167607593610806763616484284579898553129423827386500493937245230051028852782918741816499919627281039402910334745314637839027298480438682697709525642960892818855282587224798071730335955562880609056894132184882697024640662080388385961163813914376494029465139607021029779435828783150672978551489448222618986666515110359318224081947434359369262553007753215481481578129209183915544591628031914389871336224595560806731123719385956

def pollard(n):
    a = mpz(2)
    b = mpz(2)
    while True:
        a = powmod(a, b, n)
        d = gcd(a - 1, n)
        if 1 < d < n: return d
        b += 1

p = pollard(n)
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