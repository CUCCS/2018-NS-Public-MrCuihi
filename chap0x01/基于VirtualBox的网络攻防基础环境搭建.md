# 基于VirtualBox的网络攻防基础环境搭建
## 一、实验名称
基于VirtualBox的网络攻防基础环境搭建
## 二、实验要求

-  靶机可以直接访问攻击者主机
-  攻击者主机无法直接访问靶机
-  网关可以直接访问攻击者主机和靶机
-  靶机的所有对外上下行流量必须经过网关
-  所有节点均可以访问互联网
-  所有节点制作成基础镜像（多重加载的虚拟硬盘）
  

## 三、实验环境网络拓扑结构

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/5406CA7BB09F43F5BCEC237B75CD3828/2871)
## 四、实验过程
1.设置KaliGateway网关、KaliTarget靶机、KaliAttackhost攻击者主机虚拟硬盘；
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/32BF97F9AB6D4EC3A9106D33DEFDE51B/2332)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/F0374CEBD732454D8BCBD16A905E447F/2335)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/1C3A2F90F6074AE7A2EB6421C568DDD9/2336)

2.网络设置
- 设置KaliGateway网关网络（两块网卡）：

  1).网关虚拟机使用内部网络网卡：使网关KaliGateway与KaliTarget靶机处于同一个内部局域网；
 ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/593C743A3BAB4C80A61FD9E2FBC193CF/2330)
 
  2).网关虚拟机使用NAT网卡：使网关KaliGateway与KaliAttackhost攻击者主机处于另外一个局域网；
 ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/E0097C7036C540ACA6818A05CB8E61E6/2322)
 
  3).在网关系统内设置第二块网卡：取消DHCP，手动设置ip地址，掩码和网关。
 ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/0731FA0E484E4DD18D0B3047195EA454/2415)

- 设置KaliTarget靶机网络（一块网卡）

  1).靶机虚拟机使用内部网络网卡：使网关KaliGateway与KaliTarget靶机处于同一个内部局域网,KaliTarget靶机的默认网关为KaliGateway网关
 
 ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/5BF1048A87AA4015A7FBF804435C8FBA/2328)
 
  2).在靶机内部设置网络：取消DHCP，手动设置ip地址，掩码和网关
  
  ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/9639C069EDDA48E1A4D8E684A7ECD8E7/2401)
  ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/EFD875AF40A246F6AC5C7A862694A6E1/2413)
  
- 设置KaliAttackhost攻击者主机网络（一块网卡）

  1).攻击者主机用使用NAT网卡：使网关KaliGateway与KaliAttackhost攻击者主机处于另外一个局域网。

 ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/4D951B88E7234232A7C938F0E4276E02/2325)

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCE526ec91ed6004f2cd9cddb09760483a4/2419)

3.开启网关的ipv4转发
- 网关系统内设置 /proc/sys/net/ipv4/ip_forward把0改为1，或者执行

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```
开启ipv4转发。

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCE8697600e2bd15842bc319f67affa56d6/2447)
- 设置/etc/sysctrl.conf文件，将net.ipv4.ip_forward=1这一条取消注释，保存后重启网关虚拟机。（重启网络无效会造成断网问题）

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCE63237511e553775e6c84366fc7cc2ed2/2450)

4.在KaliGateway网关设置路由表，使得靶机可以访问攻击者主机。

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCE820840cdad741bf3cae2a3009ae7cd4c/2284)

## 五、实验结果

- 靶机可以直接访问攻击者主机

  1).在靶机机执行
  
```bash
ping 10.0.2.4
```
并在网关监测靶机，并在攻击者主机监测数据包流量情况。

通过网关监测结果来看可以看到靶机的ping包（request数据包）可以抵达攻击者主机。

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/623D73D238BF477B925BC8E817AED9F7/2458)

 2).在网关分别监测两个端口eth0和eth1：执行
    
```bash
tcpdump -i eth1（内网） icmp
tcpdump -i eth0（NAT） icmp 
```
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/D9D9CC5973F348D79FB700DE20CD64CD/2473)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/8FA597D7FA0B4EB0A1B3C3258B8A6E63/2470)

3).在攻击者主机检测eth0端口（NAT）

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/4DC65709D4384345A79A702D043DCA82/2480)

- 攻击者主机无法直接访问靶机 

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCE9a9687a7e4f53be329dec53640dea064/2484)

- 网关可以直接访问攻击者主机和靶机

1).网关执行

```bash
ping 10.0.2.15
```

 ping包可以抵达攻击者主机。
 ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/A711E910F5A04E079BB608EF934C604A/2407)
 
   2).网关执行
   
   ```bash
   ping 192.168.111.2
   ```
   ping包可以抵达靶机
   
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/BC10C7E0187D406EBA43D1FB5E34060B/2404)

- 靶机的所有对外上下行流量必须经过网关

  1).观察靶机的路由表可知，所有发送的数据包都要先转发给网关，同时在网关监测靶机的数据包流量情况可以观察到所有靶机的对外上下行流量都经过了网关;
 
 ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/119EE644C3B44282ADAC4E000B221D14/2410)

   2).靶机ping攻击者主机、192.168.1.16（物理主机）、www.baidu.com，分别监测网关两块网卡。

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/D9D9CC5973F348D79FB700DE20CD64CD/2473)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/8FA597D7FA0B4EB0A1B3C3258B8A6E63/2470)
-----------------
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/3A6FE1639507448BA7449EF969DDEDCE/2499)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/6B4FC51CDC074B19BCA9DF3BACF07DF5/2497)
---------------
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/354CEFA83BC94C48BD83C27DE8409E3F/2913)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/63B2ED71C27C4F7DB73D3BFC5FE99FD6/2911)

- 所有节点均可以访问互联网

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/F400261D70E74B46826D3FAE3E6DCB8D/2515)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/B55EC4D922994907BD7E8DDBB9B41D6A/2522)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/BE8A48E4A59E415AA17AC225A7425ED2/2887)

- 所有节点制作成基础镜像（多重加载的虚拟硬盘）

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/32BF97F9AB6D4EC3A9106D33DEFDE51B/2332)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/F0374CEBD732454D8BCBD16A905E447F/2335)

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/1C3A2F90F6074AE7A2EB6421C568DDD9/2336)

## 六、实验问题
1).开始的时候，设置网关的两块网卡分别为NAT网卡和Host-only网卡，设置靶机、攻击者主机仅有一块Host-only网卡。

- [ ]  VirtualBox无法设置第二块Host-only网卡
- [x] 通过管理->主机网络管理器，设置添加网络 

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/989BB5347696410E9962D9959C6DB417/2355)

- [ ] 处于这种设置下，网关、靶机和攻击者主机处于同一个局域网，这样虽然可以通过设置防火墙等实现实验要求，但是应用的实际互联网场景比较少，大多数实际互联网场景的攻击者主机与靶机不在同一个局域网。
- [x] 更改网络环境搭建配置：设置网关两块网卡分别为NAT网卡和内部网络网卡，靶机为内部网络网卡，攻击者主机为NAT网卡。

2).在网关终端执行ifconfig时，无法显示同时两块网卡分配的ip地址。

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/C905C605B50042ED8422456455B47F8B/2384)

- [ ] 尝试开启eth0(NAT网卡),eth1（内部网卡）会关闭，开启eth1，eth0会关闭，设置 

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/94610D3A9BCE4CEEB9741B79978CB7CA/2365)

![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/96F49B594A29489EB128013A9FD26814/2367)

- [x] 1).在网关中配置/etc/network/interfaces文件， 设置 eth0 和 eth1 的配置为
```bash
allow-hotplug eth0
iface eth0 inet dhcp
allow-hotplug eth1
iface eth1 inet static
address 192.168.111.1
netmask 255.255.255.0
```
2).在靶机中配置/etc/network/interfaces文件，设置 eth0 和 eth1 的配置为

```bash
allow-hotplug eth0
iface eth0 inet static
address 192.168.111.2
netmask 255.255.255.0
gateway 192.168.111.1
```
3).
- [ ] 在网关设置路由后，靶机的ping包依旧不能到达攻击者主机。
- [x] 检查路由表，后知道未设置网关的ipv4转发。

  网关系统内设置 /proc/sys/net/ipv4/ip_forward把0改为1，开启ipv4转发。
  
  ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCE8697600e2bd15842bc319f67affa56d6/2447)
  
  设置/etc/sysctrl.conf文件，将net.ipv4.ip_forward=1这一条取消注释，保存后重启网关虚拟机。（重启网络无效会造成断网问题）
  
  不能对收到的数据包转发
  ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCE63237511e553775e6c84366fc7cc2ed2/2450)
   
   设置后再通过设置iptables
   ```bash
   iptables -t nat -A POSTROUTING -o eth0 -s 192.168.111.0/24 -j MASQUERADE
   ```
   实验问题解决
   
   4).
   - [ ] 靶机无法通过域名访问互联网 
   
   ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCEe0b62897eaaf2b86c1a1eb3aabf0dba2/2510)
![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCEa174de7f31cf30d61e19c7f180ea00a5/2890)
   - [x] 在靶机内设置公共服务器，配置 /etc/resolv.conf文件，这里设置nameserver 180.76.76.76（百度云服务器
   
   ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/WEBRESOURCEe72e6f5ee6e1a2c8b98fa19ecf873dd1/2879)

   ![image](https://note.youdao.com/yws/public/resource/df0e1a3008d5a706774b678869cccda0/xmlnote/BE8A48E4A59E415AA17AC225A7425ED2/2887)
