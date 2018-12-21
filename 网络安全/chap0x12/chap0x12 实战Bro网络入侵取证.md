#### 一、实验名称

chap0x12 实战Bro网络入侵取证

####  二、实验过程
 ##### 1.安装bro，配置实验环境

 A. 执行`apt-get install bro bro-aux`，安装bro
  
 ```bash
  apt-get install bro bro-aux
 ```

 ![](/网络安全/chap0x12/images/1-A-1.png)
 ![](/网络安全/chap0x12/images/1-A-2.png)
 
 ##### 2.配置bro
 A.编辑`/etc/bro/site/local.bro`，在该文件末尾添加加两行代码

 ```bash
 @load frameworks/files/extract-all-files 
 # 提取所有文件
 @load mytuning.bro
 ```

 ![](/网络安全/chap0x12/images/2-A-1.png)

 B.在`/etc/bro/site/`目录下创建名为`mytuning.bro`的新文件，写入`redef ignore_checksums = T;`,忽略校验和认证。

 ```bash
 redef ignore_checksums = T;
 ```
 
 ![](/网络安全/chap0x12/images/2-B-1.png)
 ![](/网络安全/chap0x12/images/2-B-2.png)

 ##### 3.[下载pcap包](http://sec.cuc.edu.cn/huangwei/textbook/ns/chap0x12/attack-trace.pcap)

 A.执行命令`wget  https://sec.cuc.edu.cn/huangwei/textbook/ns/chap0x12/attack-trace.pcap`

 ```bash
 wget  https://sec.cuc.edu.cn/huangwei/textbook/ns/chap0x12/attack-trace.pcap
 ```
 
 ![](/网络安全/chap0x12/images/3-A-1.png)

 ##### 4.使用bro自动化分析下载的attack-trace.pcap包
 
 A.执行`bro -r attack-trace.pcap /etc/bro/site/local.bro`命令分析该pcap包

 ```bash
 bro -r attack-trace.pcap /etc/bro/site/local.bro
 ```

 ![](/网络安全/chap0x12/images/4-A-1.png)

 出现一个新的文件夹`extract-files`和`conn.log`、`files.log`等日志文件。

 ##### 5.分析相关文件
 
 A.进入`extract_files`文件夹，把`extract_files`文件夹里的文件上传至`VirusTotal`网站进行分析
 
 ![](/网络安全/chap0x12/images/5-A-1.png)
 ![](/网络安全/chap0x12/images/5-A-2.png)
 
 通过分析可知，这是一个已知后门程序。发现该后门程序后，可以进行逆向倒推，寻找入侵线索。

 ##### 6.入侵分析
 
 A.阅读`usr/share/bro/base/files/extract/main.bro`源代码
 
 ![](/网络安全/chap0x12/images/6-A-1.png)
 ![](/网络安全/chap0x12/images/6-A-2.png)
 
 通过源代码可知`extract_files`中文件的文件名`FHUsSu3rWdP07eRE4l`是files.log中的文件唯一标识(`f$id`)
 
 B.查看分析`files.log`
 ```bash
 cat files.log
 ```
 
 ![](/网络安全/chap0x12/images/6-B-1.png)
 
 通过分析可知，该文件提取自FTP会话，且该流量网络会话标识（该标识为bro根据IP五元组计算得出）
 `conn_uids`为`ClVvdv2GI5HkR81St8`
 
 C.查看分析`conn.log`
 
 ```bash
 cat conn.log
 ```

 ![](/网络安全/chap0x12/images/6-C-1.png)
 

 ```bash
 bro-cut ts uid id.orig_h id.resp_h proto < coon.log
 ```

 ![](/网络安全/chap0x12/images/6-C-2.png)

 
 通过`conn.log`的会话标识匹配找到id为`ClVvdv2GI5HkR81St8`的五元组信息,我们发现该PE文件来自于IPv4地址为`98.114.205.102`的主机。
 
 ##### 参考
 - [基于bro的计算机入侵取证实战分析](https://www.freebuf.com/articles/system/135843.html)
 - [实战Bro网络入侵取证](https://github.com/ghan3/ns/blob/4f62287a3ca402f727b3fca37805fc601d17bdc5/2017-2/GHHW/HW4/HW4.md)
 - [基于bro的计算机入侵取证分析](https://github.com/RachelLYY/ns/blob/c381e84540ae5916211eb024fa76bca3cc9725fb/2017-2/Lab4/%E5%9F%BA%E4%BA%8Ebro%E7%9A%84%E8%AE%A1%E7%AE%97%E6%9C%BA%E5%85%A5%E4%BE%B5%E5%8F%96%E8%AF%81%E5%88%86%E6%9E%90.md)

 
