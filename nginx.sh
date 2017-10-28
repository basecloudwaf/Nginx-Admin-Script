#!/bin/bash

#分隔：echo ${separated};
separated='###############################'
server_native_ip=`curl -s ip.cn | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`

install_nginx(){
	if [ ! -f /usr/bin/nginx ];then
		echo "检测到没有安装nginx,正在准备安装..."
		wget -c "http://soft.vpser.net/lnmp/lnmp1.4.tar.gz"
		tar zxf lnmp1.4.tar.gz
		bash /root/lnmp1.4/install.sh nginx
	fi
}

add_the_lnmp_command(){
	if [ ! -f /usr/bin/lnmp ];then
		echo "检测到没有lnmp命令,正在配置..."
		wget -P /usr/bin "https://file.52ll.win/lnmp"
		chmod 777 /usr/bin/lnmp
	fi
}

restart_the_nginx_service(){
	echo "该设定需重启nginx服务才可生效,现在重启吗?[y/n]:";read restart_the_nginx_service_confirm
	if [ ${restart_the_nginx_service_confirm} = 'y' ];then
		lnmp nginx restart
		echo "已重启nginx服务."
	else
		echo "您需手动重启nginx服务使新配置文件生效."
	fi
}

generate_nginx_jump_configuration(){
	echo ${separated};echo "生成跳转配置";echo ${separated}
	echo "请设置[访问]域名:";read access_to_the_domain_name
	echo "请设置[跳转]域名:";read jump_domain_name
	#设定
	request_uri='$request_uri'
	#检查证书
	if [ ! -f /etc/letsencrypt/live/${access_to_the_domain_name}/fullchain.pem ];then
		echo "域名[${access_to_the_domain_name}]的ssl证书不存在!";exit 0
	fi
	#校验域名与ip对应关系
	domain_name_corresponds_to_ip=`curl -s ip.cn/${access_to_the_domain_name} | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
	if [ ${server_native_ip} != ${domain_name_corresponds_to_ip} ];then
		echo -e "\033[31m[WARNING]域名[${access_to_the_domain_name}]对应IP是[${domain_name_corresponds_to_ip}]而非[${server_native_ip}]\033[0m"
	fi
	#配置
	echo "server
    {
		listen 80;
		server_name ${access_to_the_domain_name};
		return 301 https://${jump_domain_name}$request_uri;
	}

server
    {
		listen 443 ssl;
		server_name ${access_to_the_domain_name};
		return 301 https://${jump_domain_name}$request_uri;
        
		#以下为ssl配置
		ssl on;
        ssl_certificate /etc/letsencrypt/live/${access_to_the_domain_name}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${access_to_the_domain_name}/privkey.pem;
        ssl_session_timeout 5m;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_prefer_server_ciphers on;
        ssl_ciphers \"EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5\";
        ssl_session_cache builtin:1000 shared:SSL:10m;
        # openssl dhparam -out /usr/local/nginx/conf/ssl/dhparam.pem 2048
        ssl_dhparam /usr/local/nginx/conf/ssl/dhparam.pem;
    }" > /usr/local/nginx/conf/vhost/${access_to_the_domain_name}.conf
	echo "Done.";echo ${separated}
	restart_the_nginx_service
}

generate_an_antigenerational_configuration(){
	echo ${separated};echo "生成反代配置";echo ${separated}
	echo "请设置[访问]域名:";read access_to_the_domain_name
	echo "请设置[反代]域名:";read generation_of_the_domain_name
	#设定
	scheme='$scheme'
	server_name='$server_name'
	request_uri='$request_uri'
	http_user_agent='$http_user_agent'
	remote_addr='$remote_addr'
	proxy_add_x_forwarded_for='$proxy_add_x_forwarded_for'
	#检查证书
	if [ ! -f /etc/letsencrypt/live/${access_to_the_domain_name}/fullchain.pem ];then
		echo "域名[${access_to_the_domain_name}]的ssl证书不存在!";exit 0
	fi
	#校验域名与ip对应关系
	domain_name_corresponds_to_ip=`curl -s ip.cn/${access_to_the_domain_name} | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
	if [ ${server_native_ip} != ${domain_name_corresponds_to_ip} ];then
		echo -e "\033[31m[WARNING]域名[${access_to_the_domain_name}]对应IP是[${domain_name_corresponds_to_ip}]而非[${server_native_ip}]\033[0m"
	fi
	#配置
	echo "server
	{
		listen 80;
		listen 443 ssl;
		server_name ${access_to_the_domain_name};
		
		#以下为ssl配置
		ssl on;
        ssl_certificate /etc/letsencrypt/live/${access_to_the_domain_name}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${access_to_the_domain_name}/privkey.pem;
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
		sub_filter ${generation_of_the_domain_name} ${access_to_the_domain_name};
		sub_filter_once off;
		proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
		proxy_set_header Referer https://${generation_of_the_domain_name};
		proxy_set_header Host ${generation_of_the_domain_name};
		proxy_pass https://${generation_of_the_domain_name};
		proxy_set_header Accept-Encoding \"\";
		}
}" > /usr/local/nginx/conf/vhost/${access_to_the_domain_name}.conf
	echo "Done.";echo ${separated}
	restart_the_nginx_service
}

delete_domain_name_configuration(){
	echo "需要删除的域名是:";read need_to_deleted_domain
	echo "正在删除nginx的conf文件...";rm -rf /usr/local/nginx/conf/vhost/${need_to_deleted_domain}.conf
	echo "正在解除.user.ini的chattr锁定...";chattr -i /home/wwwroot/${need_to_deleted_domain}/.user.ini
	echo "正在删除/home/wwwroot/${need_to_deleted_domain}目录及其所有文件..."
	rm -rf /home/wwwroot/${need_to_deleted_domain}
	echo "Done."
}

continue_or_abort(){
#继续or中止
	echo ${separated};echo -n "继续(y)还是中止(n)? [y/n]:";read continue_or_stop
	if [ ${continue_or_stop} = 'y' ];then
		bash nginx.sh
	fi
}

nginx_shell_start(){
	clear;echo -n "####################
[1]安装nginx
[2]添加配置文件
[3]生成跳转配置
[4]生成反代配置
[5]重启nginx服务
[6]删除域名配置

[exit]退出
####################
请输入选项:"
	read nginx_option;clear

	if [ ${nginx_option} = '1' ];then
		install_nginx
	elif [ ${nginx_option} = '2' ];then
		lnmp vhost add
	elif [ ${nginx_option} = '3' ];then
		generate_nginx_jump_configuration
	elif [ ${nginx_option} = '4' ];then
		generate_an_antigenerational_configuration
	elif [ ${nginx_option} = '5' ];then
		restart_the_nginx_service
	elif [ ${nginx_option} = '6' ];then
		delete_domain_name_configuration
	elif [ ${nginx_option} = 'exit' ];then
		echo "已退出";exit 0
	else
		echo "选项不在范围!";exit 0
	fi
}

#执行
add_the_lnmp_command
nginx_shell_start
continue_or_abort

#END @qinghuas 2017-10-28 20:50
