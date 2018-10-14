### 一、实验名称
自己动手编程实现并讲解TCP connect scan/TCP stealth scan/TCP XMAS scan/UDP scan
### 二、实验要求
- 手动编程实现：
    - TCP connect scan
    - TCP stealth scan 
    - TCP XMAS scan 
    - UDP scan
### 三、实验过程
- TCP connect scan
  - 1.在KaliAttackhost执行'tcpconnectscan.py'，同时在Kalitarget执行'tcpdump -i -n eth0 -w tcpconnectscan.cap'
    ```bash  
    tcpdump -i -n eth0 -w tcpconnectscan.cap
    ```
    
    ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/682121178E9244C69B79A1669CFD2C50/4016)
    
    从执行结果来看，此时3100端口关闭

   - 2.在Kalitarget执行mitmproxy -p 3100，开启对端口3100的监听，同时在KaliAttackhost执行tcpconnectscan.py
     ```bash  
     mitmproxy -p 3100
     ```
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/EAF142A1CDAA45CCB70ED9E75D90AF11/4020)
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/B0EFFF38B1534243855D5E89E2EEA429/4022)
     
     从执行结果来看，此时3100端口开启
  - 3.在KaliAttackhost执行nmap 192.168.111.2
     ```bash  
     nmap 192.168.111.2
     ```
     
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/A0474CA80E354992B23E2AE25AE50773/4076)
     80端口是为HTTP即超文本传输协议开放的；53端口为DNS服务器所开放，DNS服务在NT系统中使用的最为广泛；而3100端口不是著名端口，在nmap扫描中，即使已经在Kalitarget中开启，依旧在扫描结果中没有显示。
     
  - 4.用wireshark分析在Kalitarget的抓取得的据包
  
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/B4D7FFF22A0F41369AFC73F4B76632D5/4059)

    从显示结果来看，192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送带SYN标志位的数据包，192.168.111.2（Kalitarget）向192.168.111.3（KaliAttackhost）回复带RST+ACK标志位的数据包说明，3100端口关闭。
    
    ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/A0AC11DE4154489FA9AD738E753A360A/4028)
    
    从显示结果来看，192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送带SYN标志位的数据包，192.168.111.2（Kalitarget）向 192.168.111.3（KaliAttackhost）回复带SYN+ACK标志位的数据包，192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送带RST+ACK标志位的数据包表明3100端口开放。
    
- TCP stealth scan
  - 1.在KaliAttackhost执行tcpstealthscan.py，同时在Kalitarget执行'tcpdump -i -n eth0 -w tcpstealthcan.cap'
     ```bash  
     tcpdump -i -n eth0 -w tcpstealthscan.cap
     ```
     
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/D7E3BADB0B914333BDBDE9E9AFCE1420/4041)
     
     从执行结果来看，此时80端口关闭

   - 2.在Kalitarget执行'mitmproxy -p 80'，开启对端口80的监听，同时在KaliAttackhost执行tcpconnectscan.py
     ```bash  
     mitmproxy -p 80
     ```
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/C4339314F9C643418AF40BA12D5FE59A/4044)
     
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/E3BC6DB810074A04922B145CAAF8E74E/4046)
     
     此时80端口开启
     
  - 3.在KaliAttackhost执行nmap 192.168.111.2
     ```bash  
     nmap 192.168.111.2
     ```
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/04F07017EB06449DAD5056B70B6E7FD9/4050)
     
     验证80端口开启
     
  - 4.用wireshark分析在Kalitarget的抓取的数据包
   
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/CADAC56EFCFD4D6BB8E9F896D75C0166/4066)

     从显示结果来看，192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送带SYN标志位的数据包，192.168.111.2（Kalitarget）向192.168.111.3（KaliAttackhost）回复标志位为RST+ACK的数据包说明，80端口关闭。
     
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/473E9563C81E462FBB9026C4D1A9D780/4054)
     从显示结果来看，192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送带SYN标志位的数据包，192.168.111.2（Kalitarget）向192.168.111.3（KaliAttackhost）回复带SYN+ACK标志位的数据包，192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送带RST标志位的数据包表明80端口开放。

 - TCP XMAS scan
   - 1.在KaliAttackhost执行tcpsXMASscan.py，同时在Kalitarget执行'tcpdump -i -n eth0 -w tcpXMASscan.cap'
     ```bash  
     tcpdump -i -n eth0 -w tcpXMASscan.cap
     ```
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/14A1E9D112AA4E25B195EEF78EF3332A/4079)
     
     从执行结果来看，此时53端口关闭

   - 2.在Kalitarget执行'mitmproxy -p 53'，开启对端口53的监听，同时在KaliAttackhost执行tcpXMASscan.py
     ```bash  
     mitmproxy -p 53
     ```
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/AF1CA83555F04AB9BCE9230B59E33B04/4082)
    
     此时53端口开启

   - 3.在KaliAttackhost执行'nmap 192.168.111.2'
       ```bash  
        nmap 192.168.111.2
       ```
       ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/DD3AC31A596546C0A359AA32BF665A0E/4085)
       
       验证端口53开启
    - 4.用wireshark分析在Kalitarget的抓取的数据包
    
       ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/97BA6CDEEC484E758C7C8EAC282FB2DA/4096)
    
       序号3、4的数据包：192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送带PSH, FIN,  URG 标志位的数据包，192.168.111.2（Kalitarget）向 192.168.111.3（KaliAttackhost）回复标志位为RST+ACK的数据包说明，53端口关闭。

       序号9、12的数据包：192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送带PSH, FIN,  URG 标志位的数据包，192.168.111.2（Kalitarget）一直没有回复，53端口开启。
    
    - 5.尝试一些命令，如尝试用iptables设置防火墙规则，但未能够从实验中验证：
    当客户端向服务器段发送带 PSH, FIN,URG标记的TCP数据包，如果服务器端回复了error type为3 、 ICMP code为1, 2, 3, 9, 10, 或者13的数据包，表明端口被过滤，无法判断端口关闭还是开启。

- UDP scan
  - 1.在KaliAttackhost执行udpscan.py，同时在Kalitarget执行'tcpdump -i -n eth0 -w udpscan.cap'
    ```bash  
    tcpdump -i -n eth0 -wudpscan.cap
    ```
    
    ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/66631F949CDB4F99B9CC4FBCA091CBA2/4141)
    
    从执行结果来看53端口关闭
  - 2.在Kalitarget执行'nc -ulp 53'，开启对端口53的监听，同时在KaliAttackhost执行udpscan.py
     ```bash  
      nc -ulp 53
     ```
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/AE04013A33B04A369415F3A9A48AA43B/4150)
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/2136654E155E4EFF84A89E74F2AB9F3B/4192)

     从执行结果来看53端口开启
   - 3.在KaliAttackhost执行'nmap -sU 192.168.111.2'
     ```bash  
     nmap 192.168.111.2
     ```
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/D88315F3F9CC4F0FA106D2CB1D19BF03/4355)
     ！[image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/DABC6DA0A353496AA1F4C10EDF661E9C/4359)
     nmap并没有扫描出执行‘nc -ulp 53’的53端口 
   - 4.用wireshark分析在Kalitarget的抓取的数据包
   
      ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/E83FA67383E24ADCB93BD424673150FD/4136)

      192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送UDP数据包;192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）回复ICMP数据包（error type：3，error code：3）说明53端口关闭。
      
      ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/5FEAF32BA739422F973224A24B4A676A/4194)
      
      192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送UDP数据包；192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）回复UDP数据包说明53端口开启。

    - 5.在本次实验的前多次尝试中还观测到了以下现象[实验代码存在差异，执行结果不同]
    
      ```bash
      import logging
      logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
      from scapy.all import *

      dst_ip = "192.168.111.2"
      src_port = RandShort()
      dst_port=53
      dst_timeout=10

      def udp_scan(dst_ip,dst_port,dst_timeout):
         udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
         if (str(type(udp_scan_resp))=="< type 'NoneType'>"):
            retrans = []
            for count in range(0,3):
               retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
               for item in retrans:
                  if (str(type(item))!="<type 'NoneType'>"):
                       udp_scan(dst_ip,dst_port,dst_timeout)
                        print("<type 'NoneType'>.The port is open|Filtered",dst_port)
         elif (udp_scan_resp.haslayer(UDP)):
           print("The port is open",dst_port)
         elif(udp_scan_resp.haslayer(ICMP)):
           if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
              print("ICMP error type:3.ICMP error code:3.The port is closed",dst_port)
         elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
              print("ICMP error type:3.Filtered")

      udp_scan(dst_ip,dst_port,dst_timeout)
      ```
      
      ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/7EF4386695F14CBF8437F74584C50DAA/4202)
      ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/73AFFE19040847AD88E9826B19DF9DED/4209)
    
      192.168.111.3（KaliAttackhost）向192.168.111.2（Kalitarget）发送UDP数据包;192.168.111.3（KaliAttackhost）并没有向192.168.111.2（Kalitarget）回复任何数据包，说明53端口开启或者被过滤。
    
    - 6.尝试一些命令，如尝试用iptables设置防火墙规则，但未能够从实验中验证：
    当客户端向服务器段发送UDP数据包，如果服务器端回复了error type为3 、 ICMP code为1, 2, 3, 9, 10, 或者13的数据包，表明端口被过滤，无法判断端口关闭还是开启。

 ### 四、实验代码
- TCP connect scan
```bash
   import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
dst_ip = "192.168.111.2"
src_port = RandShort()
dst_port = 3100

pkt = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
pkt1 = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="AR")
tcp_connect_scan_resp = sr1(pkt, timeout=10)

if (str(type(tcp_connect_scan_resp)) == "<type 'NoneType'>"):
    print("<type 'NoneType'>.The port is closed",dst_port)
elif (tcp_connect_scan_resp.haslayer(TCP)):
    if (tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
        send_rst = sr(pkt1, timeout=10)
        print("The tcpflags:0x12.The port is open",dst_port)
    elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
        print("The tcpflags:0x14.The port is closed",dst_port)
```
- TCP stealth scan 
```bash
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "192.168.111.2"
src_port = RandShort()
dst_port = 80

pkt = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S")
pkt1 = IP(dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="R")

stealth_scan_resp = sr1(pkt, timeout=10)

if (str(type(stealth_scan_resp)) == "<type 'NoneType'>"):
    print("<type 'NoneType'>.The port is Filtered",dst_port)
elif (stealth_scan_resp.haslayer(TCP)):
    if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
        send_rst = sr(pkt1, timeout=10)
        print("TCP FLAGS:0X12.The port is open",dst_port)
    elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
        print("TCP FLAGS:0x14.The port is closed",dst_port)
elif (stealth_scan_resp.haslayer(ICMP)):
    if (int(stealth_scan_resp.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
        print("ICMP error type:3.The port is Filtered",dst_port)
```
- TCP XMAS scan
```bash
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "192.168.111.2"
src_port = RandShort()
dst_port = 53

pkt = IP(dst=dst_ip) / TCP(dport=dst_port, flags="FPU")

xmas_scan_resp = sr1(pkt, timeout=10)
if (str(type(xmas_scan_resp)) == "<type 'NoneType'>"):
    print("<type 'NoneType'>.The port is open|The port is Filtered",dst_port)
elif (xmas_scan_resp.haslayer(TCP)):
    if (xmas_scan_resp.getlayer(TCP).flags == 0x14):
        print("TCP FLAGS:0x14.The port is closed",dst_port)
elif (xmas_scan_resp.haslayer(ICMP)):
    if (int(xmas_scan_resp.getlayer(ICMP).type) == 3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
        print("ICMP error type:3.The port is Filtered",dst_port)
```
- UDP scan
```bash
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dst_ip = "192.168.111.2"
src_port = RandShort()
dst_port = 53
dst_timeout = 10

udp_scan_resp = sr1(IP(dst=dst_ip) / UDP(dport=dst_port), timeout=dst_timeout)
if (str(type(udp_scan_resp)) == "<type 'NoneType'>"):
      print("The port is open|The packet is Filtered",dst_port)
elif (udp_scan_resp.haslayer(UDP)):
     print("The port is open",dst_port)
elif (udp_scan_resp.haslayer(ICMP)):
    if (int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) == 3):
         print("ICMP error type:3.The port is closed",dst_port)
    elif (int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
        print("ICMP error type:3.The port is open|The packet is Filtered",dst_port)
```

### 五、实验问题
- [ ] 初始时利用‘mitmproxy -p 53’开启53端口，但是该条命令语句第四个实验UDPscan开启端口监听后，
在KaliAttackhost执行python udpscan.py，执行的结果依旧是

  ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/21EBC3A0DF644AB4B3C074DB3F8B2B7D/4162)

  尝试更换不同的端口号，得到的结果都是端口关闭
    - 直接执行结果
      1. 80端口
      
      ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/81296F10A9844EE4A0DCE9E191BB3A0E/4166)

      2. 3100端口
      
      ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/C2A674D6870F475F8B878C52FA7048C7/4167)

   - wireshark分析抓包结果
     1. 80端口
     ![image](https://note.youdao.com/yws/public/resource/640d061309262934f6a8c50398c0f774/xmlnote/86B1E3855FEC4B3A90FE9DF1C6BB5602/4182)

     抓包分析依旧是80端口关闭
     
- [x] 尝试多种修改方法，最终通过更换命令开启端口监听命令语句，成功观测到端口开启的实验现象。
  - 在Kalitarget执行‘nc -ulp 53’
    ```bash
     nc -ulp 53
    ```
    此时再在KaliAttackhost执行相关命令，成功观测到端口开启的实验现象

- [ ] 参考原实验代码中TCP connect scan/TCP stealth scan/TCP XMAS scan的dst_port都设置为80（HTTP服务监听），UDPscan的dst_port设置为53（DNS服务监听），是否因为TCP和UDP的协议原因不同所以测试的dst_port具有必然性吗？
- [x] 但是除了在实验中分别对应尝试80端口以及53端口，还有其他不著名端口，比如【报告中第三部分】第1个实验报告中里展示的3100端口，同样可以进行实验；第3个实报告中虽然是TCP XAMS scan，却进行53端口扫描，同样可以观察实验，在开始进行实验时寻找的参考代码中也存在除了80、53特定著名端口等其他端口的TCP/UDP扫描实验。
