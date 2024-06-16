## **Common modulus**
### **As an internal attacker**
Tình huống trước, bạn chặn hai tin nhắn giống hệt nhau. Bây giờ, giả định rằng bạn là thành viên của công ty và sở hữu khóa riêng tư, khóa công khai riêng và có cùng mô-đun $n$ với những người khác.
Ta có: $ed$ ≡ $1 \pmod{φ(n)}$, suy ra $ed$ - $1$ là bội số của $φ(n)$, hay $ed$ - $1$ = $k$ * $φ(n)$.
Giả sử $φ(n)$ xấp xỉ bằng $n$ $=>$ $k$ = $\frac{e*d - 1}{n}$.
Từ đó tính được $φ(n)$ = $\frac{e*d - 1}{k}$. (Nếu $φ(n)$ không phải là số nguyên thì tăng dần k đến khi $φ(n)$ nguyên vì giá trị $k$ là xấp xỉ)
Lúc này ta đã biết được $φ(n)$ và khóa công khai $e$ của nạn nhân A. Ta sẽ tính được khóa riêng tư của nạn nhân A $d_A$ ≡ $e_A^{-1} \pmod{φ(n)}$ rồi từ đó giải mã được tin nhắn.
#### Challenge:
1. Problem:
```
from Crypto.Util.number import *
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from secret import FLAG

e=65537
your_e = getPrime(20)
msg=btl(FLAG)
p=getPrime(512)
q=getPrime(512)
n=p*q
assert(msg < n)
ct=pow(msg, e, n)
your_d = inverse(your_e, (p-1)*(q-1))
print(f"{your_e = }")
print(f"{your_d = }")
print(f"{n = }")
print(f"{e = }")
print(f"{ct = }")
```
2. Ý tưởng
* Ta đã sở hữu một cặp khóa ($your_e$, $your_d$) với cùng mô-đun $n$ và $e$ của nạn nhân
* Ta có thể tính được $φ(n)$ từ $your_e$, $your_d$ như đã nói ở trên, từ đó tìm được $d$ của nạn nhân và giải mã thông điệp.
3. Giải mã
```
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
your_e = 587179
your_d = 116574138274153425681158422128580239663111884465377821858780576727343574236964511025773393567710410774585694348201568228206538372093811740362750617639926498805331888788247534728551858007629519609577947708965382694547788212544367371818936521487338877498270784426809616903043461499418607797941579658446698467459
n = 174801667929086163289895249439555082523753079038821827290089329705824193349319395023322068362236217046090650385056280435638881356298928674402199120793885409582198844442311754906362780161919502444251364267604118399028208585245792788755794357994213586087801334869120611067636368104353457554296916681893452471133
e = 65537
ct = 53465085122620172726606536088151896695089891957619791347718614711293081179069089096711080241562161246197157386101555428494861370272376601862361907035948009956591858206364705462591267272303847542672035857072800527004059308615800494273674182486092387395531924597343613852979408433572334206929477220188001816526

phi = 0
k = (your_e * your_d - 1) // n
for i in range(1000000):
    if (your_e * your_d - 1) % k == 0:
        # right value of phi found
        phi = (your_e * your_d - 1) // k
        break
    k += 1

d = pow(e, -1 ,phi)
m = pow(ct, d, n)

print(ltb(m))
```
Kết quả:
![image](https://hackmd.io/_uploads/B1vI2phXR.png)
$=>$ **Giải pháp:** Sử dụng khóa riêng cho mỗi người dùng: Thay vì sử dụng chung một mô-đun $N$ cho tất cả các người dùng, hãy tạo một mô-đun $N$ riêng cho mỗi người dùng. Điều này sẽ ngăn chặn bất kỳ cuộc tấn công Common modulus nào vì mỗi khóa công khai sẽ duy nhất cho mỗi người dùng.