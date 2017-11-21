# Nginx Admin Script

简介
---
便于生成和管理Nginx配置，Nginx的安装与lnmp命令由`lnmp.org`提供，脚本默认启用SSL，SSL证书由`Let's Encrypt`签发。

使用
---
1.环境  

Centos:`yum -y install git wget curl zip unzip screen`  

Debian/Ubuntu:`apt-get -y install git wget curl zip unzip screen`

2.执行
```
wget "https://raw.githubusercontent.com/qinghuas/Nginx-administration-script/master/nas.sh";bash nas.sh
```

3.选择   
   
![](https://raw.githubusercontent.com/qinghuas/Nginx-Admin-Script/master/V.1.3.png)

其他
---
```
cp /root/nas.sh /usr/bin/nas;chmod 777 /usr/bin/nas;nas
```
