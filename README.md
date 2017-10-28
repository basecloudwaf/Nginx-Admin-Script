# Nginx administration script

简介
---
便于生成和管理nginx配置的脚本。nginx的安装，lnmp命令均基于`lnmp.org`。脚本生成的配置文件默认使用ssl，ssl均基于`Let's Encrypt`，您可以通过`lnmp vhost add`命令来自动配置ssl证书。初衷是为了方便自己，后续会根据自己的需要，增添一些新功能。

使用
---
1.执行
```
wget "https://raw.githubusercontent.com/qinghuas/Nginx-administration-script/master/nginx.sh"
```
若提示：`-bash: wget: command not found`，则
Centos：`yum -y install wget`
Debian/Ubuntu：`apt-get -y install wget`  

2.选择  
![](https://raw.githubusercontent.com/qinghuas/Nginx-administration-script/master/option.png)
