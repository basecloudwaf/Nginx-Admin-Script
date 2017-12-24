# Nginx Admin Script
便于生成和管理Nginx配置，Nginx的安装与lnmp命令由`lnmp.org`提供，脚本默认启用SSL，SSL证书由`Let's Encrypt`签发

准备
---
Centos
```
yum -y install git wget curl zip unzip screen
```
Debian / Ubuntu
```
apt-get -y install git wget curl zip unzip screen
```

安装
---
```
wget -O /usr/bin/nas "https://raw.githubusercontent.com/qinghuas/Nginx-administration-script/master/nas.sh"
chmod 777 /usr/bin/nas
```

使用
---
```
nas
```

快捷选项
---
暂无

更新日志
---
`2017-12-24`  
- 添加选项:生成域名访问跳转指定URL配置
- 优化选项:删除初始配置
- 优化选项:安装Nginx

选项预览
---
![](https://raw.githubusercontent.com/qinghuas/Nginx-Admin-Script/master/nas-1.4.png)

其他
---
- 脚本暂时不支持自定义证书路径
- 默认编译了`ngx_http_substitutions_filter_module`模块和`http_addition_module`模块
