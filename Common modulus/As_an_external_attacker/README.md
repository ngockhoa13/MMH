## **Common modulus**
### **As an external attacker**
Giả sử rằng tại một công ty, người ta quyết định sẽ sử dụng hệ mật mã RSA với một mô-đun $n$ và mỗi nhân viên sẽ có một khóa riêng tư $d$ và khóa công khai $e$ riêng.
Một người quản lý gửi cùng một thông điệp $M$ cho hai đồng nghiệp của mình. Điều này sẽ tạo ra hai bản mã khác nhau.

$C_A$ ≡ $M^{e_A} \pmod{n}$,
$C_B$ ≡ $M^{e_B} \pmod{n}$.

Bạn đã chặn được một thông điệp quan trọng được gửi đến người A và B, được mã hóa bằng cặp khóa công khai tương ứng của họ ($C_A$ và $C_B$). Làm thế nào để giải mã nó?

Đầu tiên, chúng ta cần kiểm tra xem $gcd(e_A, e_B) = 1$ hay không. Nếu có, chúng ta sẽ sử dụng [Giải thuật Euclid mở rộng](https://vi.wikipedia.org/wiki/Gi%E1%BA%A3i_thu%E1%BA%ADt_Euclid_m%E1%BB%9F_r%E1%BB%99ng)$^{(1)}$ để tìm các số nguyên $u$ và $v$ sao cho:
$e_A * u + e_B * v = 1$ (*)

$C_A = M^{e_A} \pmod{n}$ và $C_B = M^{e_B} \pmod{n}$
$C_A^u = {M^{e_A}}^u \pmod{n}$ = $M^{{e_A}*u} \pmod{n}$ và $C_B^v = {M^{e_B}}^v \pmod{n}$ = $M^{{e_B}*v} \pmod{n}$

Bây giờ, nhân cả hai để xuất hiện (*).
$M^{{e_A}*u} *  M^{{e_B}*v} = M^{{e_A}*u+{e_B}*v} = M^1 = M$

Bằng cách này, chúng ta khôi phục lại thông điệp ban đầu $M$. Đây là cách thực hiện cuộc tấn công trên Common modulus.
#### Challenge:
1. Problem:
```
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
```
2. Ý tưởng
* Nhìn vào đoạn code trên, ta thấy được cùng một thông điệp `msg` được mã hóa với 2 số mũ công khai `e1`, `e2` khác nhau trên cùng một module `n`
* $gcd(e_1, e_2) = 1$ => Có thể thực hiện tấn công **Common modulus**
![Screenshot 2024-05-22 184032](https://hackmd.io/_uploads/H1NBq8oXA.png)
3. Giải mã
```
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl

def extended_euclid_gcd(a, b):
    
    s = 0; old_s = 1
    t = 1; old_t = 0
    r = b; old_r = a

    while r != 0:
        quotient = old_r//r 
        old_r, r = r, old_r - quotient*r
        old_s, s = s, old_s - quotient*s
        old_t, t = t, old_t - quotient*t
    return [old_r, old_s, old_t]

n = 107134870430813189645882484100833022762609284797615973689883996254723080902485547524527027103179260290016317812761007542319744101663285995237151198871297684007040766788327415986942170855041906741506156832353589854297154536809777479546012849098651040112235391776555662314987184071843321491087369634120481147041
e1 = 71
e2 = 101
c1 = 83864568465138779882910366965980013620629845890710956120302270144769701416149339128668188680182735905951579270028136183540166952237531777634570020422505733711873906622991895081303689281724637541489714713551478839452749906442325819094904846211331110253518358599417252111565272989748759144633889964824784045008
c2 = 26879051489881487980558451823719222194604990480989321681145557353738340068343371415520479319415896527047949828376357639032230483800899257624991672631708681376232481672369681654873617488352304396490709707936637869232157408550576919598829742862475770091566098943457458619827987421018489471184199933544162321478

gcd, x, y = extended_euclid_gcd(e1, e2)
m = (pow(c1, x, n) * pow(c2, y, n)) % n
print(ltb(m))
```
Kết quả:
![image](https://hackmd.io/_uploads/S1XIjT3XC.png)