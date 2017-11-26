# Nginx Admin Script

简介
---
便于生成和管理Nginx配置，Nginx的安装与lnmp命令由`lnmp.org`提供，脚本默认启用SSL，SSL证书由`Let's Encrypt`签发。

使用
---
首先：   

Centos:
```
yum -y install git wget curl zip unzip screen;wget -O /usr/bin/nas "https://raw.githubusercontent.com/qinghuas/Nginx-administration-script/master/nas.sh";chmod 777 /usr/bin/nas
```

Debian/Ubuntu:
```
apt-get -y install git wget curl zip unzip screen;wget -O /usr/bin/nas "https://raw.githubusercontent.com/qinghuas/Nginx-administration-script/master/nas.sh";chmod 777 /usr/bin/nas
```

然后：   
```
nas
```

截图
---
![](https://raw.githubusercontent.com/qinghuas/Nginx-Admin-Script/master/V.1.3.png)
