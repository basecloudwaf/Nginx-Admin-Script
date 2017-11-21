#!/bin/bash

#Color
Warning='\033[31m[WARNING]\033[0m'
Tips='\033[32m[Tips]\033[0m'

Install_Nginx(){
	if [ ! -f /usr/bin/nginx ];then
		read -p "检测到未安装Nginx,现在安装?[y/n]" Installation_Qualification
			case "${Installation_Qualification}" in
			y)
				if [ ! -f /root/lnmp1.4/install.sh ];then
					wget -c "http://soft.vpser.net/lnmp/lnmp1.4.tar.gz";tar zxf lnmp1.4.tar.gz
					apt-get install -y git gcc;yum install -y git gcc
					git clone https://github.com/yaoweibin/ngx_http_substitutions_filter_module.git
					sed -i "4c Nginx_Modules_Options='--add-module=/root/ngx_http_substitutions_filter_module'" /root/lnmp1.4/lnmp.conf
				fi
				cd /root/lnmp1.4
				./install.sh nginx
				cd /root
				#lnmp
				apt-get install -y net-tools;yum install -y net-tools
				wget -P /usr/bin "https://file.52ll.win/lnmp";chmod 777 /usr/bin/lnmp;lnmp nginx
				#nginx -V
				nginx -V
			;;
			n)
				echo "安装被取消.";exit 0
			;;
			*)
				echo "选项不在范围内.";exit 0
			;;
			esac
	else
		echo -e "${Tips} Nginx已安装."
		lnmp nginx restart > /dev/null
		echo -e "${Tips} Nginx已重启."
	fi
}

Lnmp_Vhost_Add(){
	#Add_Vhost
	echo;echo -e "${Tips} 您能看见此提示,说明在刚刚的操作中,由于缺少[SSL]证书而无法继续,脚本将申请由[Let's Encrypt]免费签发的[SSL]证书,请在下方填写相应信息,然后脚本会继续.如何填写?您可参考:https://lnmp.org/faq/lnmp-vhost-add-howto.html"
	echo -e "${Warning} 请务必启用SSL项！！！";echo
	lnmp vhost add
	#Check_SSL_WWW_A
	if [ ! -f /etc/letsencrypt/live/${WWW_A}/fullchain.pem ];then
		echo -e "${Warning} 域名[${WWW_A}]仍然缺少SSL证书,您需手动配置SSL."
	else
		echo -e "${Tips} [Let's Encrypt]已为[${WWW_A}]签发[SSL]证书."
	fi
	#Check_SSL_WWW_B
	#if [ ! -f /etc/letsencrypt/live/${WWW_B}/fullchain.pem ];then
		#echo -e "${Warning} 域名[${WWW_B}]仍然缺少SSL证书,您需手动配置SSL."
	#else
		#echo -e "${Tips} [Let's Encrypt]已为[${WWW_B}]签发[SSL]证书."
	#fi
}

Check_Domain_Name(){
	#Check_SSL_WWW_A
	if [ ! -f /etc/letsencrypt/live/${WWW_A}/fullchain.pem ];then
		echo;echo -e "${Warning} 域名[${WWW_A}]的[SSL]证书不存在.";Lnmp_Vhost_Add
	else
		echo;echo -e "${Tips} 域名[${WWW_A}]的[SSL]证书存在."
	fi
	#Check_SSL_WWW_B
	#if [ ! -f /etc/letsencrypt/live/${WWW_B}/fullchain.pem ];then
		#echo;echo -e "${Warning} 域名[${WWW_B}]的[SSL]证书不存在.";Lnmp_Vhost_Add
	#else
		#echo;echo -e "${Tips} 域名[${WWW_B}]的[SSL]证书存在."
	#fi
	#Check_Domain_IP
	Server_IP=`curl -s https://app.52ll.win/ip/api.php`
	#https://zhidao.baidu.com/question/327919479.html
	Domain_IP=`ping ${WWW_A} -c 1 | grep ${WWW_A} | head -n 1 | cut -d'(' -f 2 | cut -d')' -f1`
	echo -e "${Tips} 域名[${WWW_A}]解析IP是[${Domain_IP}],请检查是否对应服务器IP[${Server_IP}]."
}

Add_Jump_Configuration(){
	#定义
	request_uri='$request_uri'
	#添加
	echo "server
    {
		listen 80;
		server_name ${WWW_A};
		return 301 https://${WWW_A}$request_uri;
	}

server
    {
		listen 443 ssl;
		server_name ${WWW_A};
		return 301 https://${WWW_B}$request_uri;
        
		#以下为ssl配置
		ssl on;
        ssl_certificate /etc/letsencrypt/live/${WWW_A}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${WWW_A}/privkey.pem;
        ssl_session_timeout 5m;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers \"EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5\";
        ssl_session_cache builtin:1000 shared:SSL:10m;
        # openssl dhparam -out /usr/local/nginx/conf/ssl/dhparam.pem 2048
        ssl_dhparam /usr/local/nginx/conf/ssl/dhparam.pem;
    }" > /usr/local/nginx/conf/vhost/${WWW_A}.conf
}

Jump_Configuration(){
	echo -e "${Tips} 效果:访问 a.com 跳转至 b.com"
	read -p "请输入访问域名:" WWW_A
	read -p "请输入跳转域名:" WWW_B
	Check_Domain_Name
	Add_Jump_Configuration
	lnmp nginx restart > /dev/null
	echo -e "${Tips} 已完成该项操作."
}

Add_Anti_Generation(){
	#定义
	scheme='$scheme'
	server_name='$server_name'
	request_uri='$request_uri'
	http_user_agent='$http_user_agent'
	remote_addr='$remote_addr'
	proxy_add_x_forwarded_for='$proxy_add_x_forwarded_for'
	#添加
	echo "server
	{
		listen 80;
		listen 443 ssl;
		server_name ${WWW_A};
		
		#以下为ssl配置
		ssl on;
        ssl_certificate /etc/letsencrypt/live/${WWW_A}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${WWW_A}/privkey.pem;
        ssl_session_timeout 5m;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers \"EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5\";
        ssl_session_cache builtin:1000 shared:SSL:10m;
        # openssl dhparam -out /usr/local/nginx/conf/ssl/dhparam.pem 2048
        ssl_dhparam /usr/local/nginx/conf/ssl/dhparam.pem;
		
		#以下为反代配置
		add_header Strict-Transport-Security \"max-age=31536000\";
		
		if ( $scheme = http ){
			return 301 https://$server_name$request_uri;
		}
		
		if ($http_user_agent ~* (baiduspider|360spider|haosouspider|googlebot|soso|bing|sogou|yahoo|sohu-search|yodao|YoudaoBot|robozilla|msnbot|MJ12bot|NHN|Twiceler)) {
		return  403;
		}
  
		location / {
		sub_filter ${WWW_B} ${WWW_A};
		sub_filter_once off;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header Referer https://${WWW_B};
		proxy_set_header Host ${WWW_B};
		proxy_pass https://${WWW_B};
		proxy_set_header Accept-Encoding \"\";
		}
}" > /usr/local/nginx/conf/vhost/${WWW_A}.conf
}

Anti_Generation(){
	echo -e "${Tips} 效果:访问 a.com 浏览的内容来自 b.com"
	read -p "请输入源站域名:" WWW_B
	read -p "请输入访问域名:" WWW_A
	Check_Domain_Name
	Add_Anti_Generation
	lnmp nginx restart > /dev/null
	echo -e "${Tips} 已完成该项操作."
}

Add_Access_phpmyadmin_Folder(){
	echo "server
    {
        listen 80;
        #listen [::]:80;
        server_name ${WWW_A} ;
        index index.html index.htm index.php default.html default.htm default.php;
        root  ${phpmyadmin_Path};

        include none.conf;
        #error_page   404   /404.html;

        # Deny access to PHP files in specific directory
        #location ~ /(wp-content|uploads|wp-includes|images)/.*\.php$ { deny all; }

        include enable-php.conf;

        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }

        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }

        location ~ /.well-known {
            allow all;
        }

        location ~ /\.
        {
            deny all;
        }

        access_log off;
    }
" > /usr/local/nginx/conf/vhost/${WWW_A}.conf
}

Access_phpmyadmin_Folder(){
	echo -e "${Tips} 效果:访问 a.com = 访问本机phpmyadmin目录"
	read -p "请输入访问域名:" WWW_A
	echo;echo -e "${Tips} phpmyadmin目录绝对路径示例/默认值:/home/wwwroot/default/phpmyadmin"
	read -p "请输入phpmyadmin目录绝对路径:" phpmyadmin_Path
	
	if [[ ${phpmyadmin_Path} = '' ]];then
		phpmyadmin_Path='/home/wwwroot/default/phpmyadmin'
		echo;echo -e "${Tips} 未输入任何内容,默认phpmyadmin目录绝对路径为:/home/wwwroot/default/phpmyadmin";echo
	fi
	
	Add_Access_phpmyadmin_Folder
	lnmp nginx restart > /dev/null
	echo -e "${Tips} 已完成该项操作."
}

Add_Http_Jump_Https(){
	#定义
	server_name='$server_name'
	request_uri='$request_uri'
	#配置
	echo "server
    {
		listen 80;
		server_name ${WWW_A};
		return 301 https://$server_name$request_uri;
	}

server
    {
        listen 443 ssl http2;
        #listen [::]:443 ssl http2;
        server_name ${WWW_A} ;
        index index.html index.htm index.php default.html default.htm default.php;
        root  /home/wwwroot/${WWW_A};
        ssl on;
        ssl_certificate /etc/letsencrypt/live/${WWW_A}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${WWW_A}/privkey.pem;
        ssl_session_timeout 5m;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers \"EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5\";
        ssl_session_cache builtin:1000 shared:SSL:10m;
        # openssl dhparam -out /usr/local/nginx/conf/ssl/dhparam.pem 2048
        ssl_dhparam /usr/local/nginx/conf/ssl/dhparam.pem;

        include wordpress.conf;
        #error_page   404   /404.html;

        # Deny access to PHP files in specific directory
        #location ~ /(wp-content|uploads|wp-includes|images)/.*\.php$ { deny all; }

        include enable-php.conf;

        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }

        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }

        location ~ /.well-known {
            allow all;
        }

        location ~ /\.
        {
            deny all;
        }

        access_log off;
    }
" > /usr/local/nginx/conf/vhost/${WWW_A}.conf
}

Http_Jump_Https(){
	echo -e "${Tips} 效果:访问http://a.com 将跳转至 https://a.com"
	read -p "请输入访问域名:" WWW_A
	Check_Domain_Name
	Add_Http_Jump_Https
	lnmp nginx restart > /dev/null
	echo -e "${Tips} 已完成该项操作."
}

Add_Resume_Initial_Configuration(){
	mkdir -p /home/wwwroot/${Visit_Domain_Name} > /dev/null
	#配置
	echo "server
    {
        listen 80;
        #listen [::]:80;
        server_name ${WWW_A} ;
        index index.html index.htm index.php default.html default.htm default.php;
        root  /home/wwwroot/${WWW_A};

        include none.conf;
        #error_page   404   /404.html;

        # Deny access to PHP files in specific directory
        #location ~ /(wp-content|uploads|wp-includes|images)/.*\.php$ { deny all; }

        include enable-php.conf;

        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }

        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }

        location ~ /.well-known {
            allow all;
        }

        location ~ /\.
        {
            deny all;
        }

        access_log off;
    }

server
    {
        listen 443 ssl http2;
        #listen [::]:443 ssl http2;
        server_name ${WWW_A} ;
        index index.html index.htm index.php default.html default.htm default.php;
        root  /home/wwwroot/${WWW_A};
        ssl on;
        ssl_certificate /etc/letsencrypt/live/${WWW_A}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${WWW_A}/privkey.pem;
        ssl_session_timeout 5m;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers \"EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5\";
        ssl_session_cache builtin:1000 shared:SSL:10m;
        # openssl dhparam -out /usr/local/nginx/conf/ssl/dhparam.pem 2048
        ssl_dhparam /usr/local/nginx/conf/ssl/dhparam.pem;

        include none.conf;
        #error_page   404   /404.html;

        # Deny access to PHP files in specific directory
        #location ~ /(wp-content|uploads|wp-includes|images)/.*\.php$ { deny all; }

        include enable-php.conf;

        location ~ .*\.(gif|jpg|jpeg|png|bmp|swf)$
        {
            expires      30d;
        }

        location ~ .*\.(js|css)?$
        {
            expires      12h;
        }

        location ~ /.well-known {
            allow all;
        }

        location ~ /\.
        {
            deny all;
        }

        access_log off;
    }
" > /usr/local/nginx/conf/vhost/${WWW_A}.conf
}

Resume_Initial_Configuration(){
	echo -e "${Tips} 效果:访问 a.com = 访问 /home/wwwroot/a.com 目录"
	read -p "请输入访问域名:" WWW_A
	Check_Domain_Name
	Add_Resume_Initial_Configuration
	lnmp nginx restart > /dev/null
	echo -e "${Tips} 已完成该项操作."
}

Delete_The_Initial_Configuration(){
	echo -e "${Tips} 效果:删除 conf 文件 删除 /home/wwwroot/ 下对应目录"
	echo;lnmp vhost list;echo
	read -p "请输入删除域名:" WWW_A
	
	rm -rf /usr/local/nginx/conf/vhost/${WWW_A}.conf
	chattr -i /home/wwwroot/${WWW_A}/.user.ini > /dev/null
	rm -rf /home/wwwroot/${WWW_A}
	
	read -p "删除由[Let's Encrypt]签发的[SSL]证书?[y/n]" Delete_SSL
	case "${Delete_SSL}" in
	y)
		rm -rf /etc/letsencrypt/live/${WWW_A}
		echo -e "${Warning} 不保留由[Let's Encrypt]签发的[SSL]证书";;
	n)
		echo -e "${Tips} 保留由[Let's Encrypt]签发的[SSL]证书";;
	*)
		echo -e "${Tips} 未选择选项,保留由[Let's Encrypt]签发的[SSL]证书";;
	esac

	lnmp nginx restart > /dev/null
	echo -e "${Tips} 已完成该项操作."
}

clear;echo "##################################################
# https://github.com/qinghuas/Nginx-Admin-Script #
# @qinghua V.1.3 2017-11-19                      #
##################################################
#[1] 安装Nginx                                   #
#[2] 生成跳转配置                                #
#[3] 生成反代配置                                #
#[4] 生成访问phpmyadmin配置                      #
#[5] 生成http访问跳转https配置                   #
##################################################
#[a] 新加初始配置                                #
#[b] 恢复初始配置                                #
#[c] 删除初始配置                                #
##################################################"
read -p "请选择选项:" Select_Options;echo

case "${Select_Options}" in
	1)
	Install_Nginx;;
	2)
	Jump_Configuration;;
	3)
	Anti_Generation;;
	4)
	Access_phpmyadmin_Folder;;
	5)
	Http_Jump_Https;;
	a)
	lnmp vhost add;;
	b)
	Resume_Initial_Configuration;;
	c)
	Delete_The_Initial_Configuration;;
	*)
	echo "选项不在范围内.";exit 0;;
esac
