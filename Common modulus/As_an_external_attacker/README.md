## **Common modulus**
### **As an external attacker**
Giả sử rằng tại một công ty, người ta quyết định sẽ sử dụng hệ mật mã RSA với một mô-đun $n$ và mỗi nhân viên sẽ có một khóa riêng tư $d$ và khóa công khai $e$ riêng.
Một người quản lý gửi cùng một thông điệp $M$ cho hai đồng nghiệp của mình. Điều này sẽ tạo ra hai bản mã khác nhau.

$C_A$ ≡ $M^{e_A} \pmod{n}$,
$C_B$ ≡ $M^{e_B} \pmod{n}$.

Bạn đã chặn được một thông điệp quan trọng được gửi đến người A và B, được mã hóa bằng cặp khóa công khai tương ứng của họ ($C_A$ và $C_B$). Làm thế nào để giải mã nó?

Đầu tiên, chúng ta cần tính $gcd(e_A, e_B) = d$. Nếu d nhỏ, chúng ta sẽ sử dụng [Bổ đề Bézout](https://vi.wikipedia.org/wiki/B%E1%BB%95_%C4%91%E1%BB%81_B%C3%A9zout)$^{(1)}$ để tìm các số nguyên $u$ và $v$ sao cho:
$e_A * u + e_B * v = d$ (*)

$C_A = M^{e_A} \pmod{n}$ và $C_B = M^{e_B} \pmod{n}$
$C_A^u = {M^{e_A}}^u \pmod{n}$ = $M^{{e_A}*u} \pmod{n}$ và $C_B^v = {M^{e_B}}^v \pmod{n}$ = $M^{{e_B}*v} \pmod{n}$

Bây giờ, nhân cả hai để xuất hiện (*).
$M^{{e_A}*u} *  M^{{e_B}*v} = M^{{e_A}*u+{e_B}*v} = M^d$
Sau đó khai căn bậc $d$ của giá trị vừa tìm được.
Bằng cách này, chúng ta khôi phục lại thông điệp ban đầu $M$. Đây là cách thực hiện cuộc tấn công trên Common modulus.
#### Challenge:
1. Problem:
```
from Crypto.Util.number import *
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from secret import FLAG

p=getPrime(2048)
q=getPrime(2048)
n=p*q
e1=49155
e2=196611
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
* $gcd(e_1, e_2) = 3$ => Có thể thực hiện tấn công **Common modulus**

![image](https://hackmd.io/_uploads/ByS2-jTBR.png)

3. Giải mã
```
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
import gmpy2

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

n = 384551944731400036381810776767496661829658752693711118715285724516754898572022813584490815475287507985082097114052364994067026603408735473782926372983617830571992342318755370118285903055284159581935977331832377995677004276029990202222680861544195566359332551354253348663851032455431172511259672410803916378836808447382614507738042338951402035854719734928804454492727441259067631764072994337258154098311090326420857966731340343919943105753300416498911557025995122420137392750720974133165801380569737730211032074565317742316872282570825212101297592064692991234274832588588789468274476881983540937956375131115544822470211889420528295212136115217186621258146606169465309827602963586860875448120368211678689900889765241527974595474805928316015375274352722697316401936222041162460767257558624148121047909398798001310484773307323079894014532279993952247459155937518105178285724283870292821536131572116898348322187415388681702968912949561340145242682333784749139651176671331901150336426664408798661371543833950415689007225407894040012807723551329108119499443733430291655681183822428525891869138447827302511992609610706631294856174706010673176608220434607142488669594494388460607963476808925014310542543394214330451323862142290373003148503527
e1 = 49155
e2 = 196611
c1 = 334623988827618993598782894733002241797530576094571458990300053870668795985232787359108188695781479273018640216862673356572803943586960866046010993766742101660728680781397015002894875788497246449809441822665493699543524715601842455564473643870082385920768860619872162686327617273810269681717705815011682729907135686145954961627937177199907518771185469540563318025263602500062807912163052413474635831185905662591539240485606723203304928941341085233231554787287748288107870466769027958588583204141805649983574995723709849171755853852231462065048772726960047109944214677313786078499887540505853617592163042818725194018162452598260884302346562838127576315174305048979100123367966565051250613648852437906109002327513611982707197807506459642123878905726926774277964860226783054888606100422989203547078299778230364639525504769684083498419378626089263650989231700073711044831313019919812042535775766920668503708055772222001232614101747267994313783070256993549281079448912234811563611727264543558120826318478947461476129436847535907013700909936906857648530733161167759413424356597334019692606189169406911072127095517298350442809239408976314412860566198773430105449057268123091266046424722242158314361208574429486836703942513182133567680571771
c2 = 363885559993585822543801840244273543021862566951306692537667765468164957290130874104337355444770910105061415135309430175080226207326234080733060582073689705741981284460762108259628568458675650925819154374802775657409234796090824940062488165845795808163423738506664593859678866321632957834417314984366758032226301361999669608376096304354965863244865989968401359611567940657092706287487631528296571002262796906173755675645748176291242614105627240193197179298635414980434142908243033558790113623842783837313292400324985845954743812042372133207621424502810800126416489777531717173103538306432900552998798541613286980095262508284501724082634286696886952309766491916097877098465111634758057577077986339081371383227619361616270428044672164534118946223202039013343614057066882726500873403845045454217750559366711799441778113968063202694691469677887355171927675673781741874409425545050643626693694440881703048146753608635159236376324231373099863351097356323515161749532517868601051940939915401370947654603550836395452344675408659818553688647058324579663590902956888989927091701473635293094402441410332606150017739832578967916505735835738753864069292998009725937895488469013727062143909687886170690252564727041662186277819357007866091557558487

gcd, x, y = extended_euclid_gcd(e1, e2)
print(gcd)
m = (pow(c1, x, n) * pow(c2, y, n)) % n
print(ltb(gmpy2.iroot(m,gcd)[0]))
```
Kết quả:
![image](https://hackmd.io/_uploads/S1XIjT3XC.png)