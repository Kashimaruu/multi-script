#!/usr/bin/env bash
installType='yum -y install'
removeType='yum -y remove'
upgrade="yum -y update"
echoType='echo -e'
cp=`which cp`
# Print Echo
echoColor(){
    case $1 in
        # Red
        "red")
            ${echoType} "\033[31m$2 \033[0m"
        ;;
        # Sky Blue
        "skyBlue")
            ${echoType} "\033[36m$2 \033[0m"
        ;;
        # Green
        "green")
            ${echoType} "\033[32m$2 \033[0m"
        ;;
        # White
        "white")
            ${echoType} "\033[37m$2 \033[0m"
        ;;
        "magenta")
            ${echoType} "\033[31m$2 \033[0m"
        ;;
        "skyBlue")
            ${echoType} "\033[36m$2 \033[0m"
        ;;
        # Yellow
        "yellow")
            ${echoType} "\033[33m$2 \033[0m"
        ;;
    esac
}
# Check the System Ver
checkSystem(){

	if [[ ! -z `find /etc -name "redhat-release"` ]] || [[ ! -z `cat /proc/version | grep -i "centos" | grep -v grep ` ]] || [[ ! -z `cat /proc/version | grep -i "red hat" | grep -v grep ` ]] || [[ ! -z `cat /proc/version | grep -i "redhat" | grep -v grep ` ]]
	then
		release="centos"
		installType='yum -y install'
		removeType='yum -y remove'
		upgrade="yum update -y"
	elif [[ ! -z `cat /etc/issue | grep -i "debian" | grep -v grep` ]] || [[ ! -z `cat /proc/version | grep -i "debian" | grep -v grep` ]]
    then
		release="debian"
		installType='apt -y install'
		upgrade="apt update -y"
		removeType='apt -y autoremove'
	elif [[ ! -z `cat /etc/issue | grep -i "ubuntu" | grep -v grep` ]] || [[ ! -z `cat /proc/version | grep -i "ubuntu" | grep -v grep` ]]
	then
		release="ubuntu"
		installType='apt -y install'
		upgrade="apt update -y"
		removeType='apt --purge remove'
    fi
    if [[ -z ${release} ]]
    then
        echoContent red "This machine is incompatible to run the script, please send logs below to author."
        cat /etc/issue
        cat /proc/version
        exit 0;
    fi
}
# Install tools
installTools(){
    echoColor yellow "Checking socat"
    ${upgrade}
    if [[ -z `find /usr/bin/ -executable -name "socat"` ]]
    then
        echoColor yellow "\nsocat not installed, installing\n"
        ${installType} socat >/dev/null
        echoColor green "socat installed"
    fi
    echoColor yellow "\nChecking Nginx"
    if [[ -z `find /sbin/ -executable -name 'nginx'` ]]
    then
        echoColor yellow "nginx not installed, installing\n"
        ${installType} nginx >/dev/null
        echoColor green "nginx installed"
    else
        echoColor green "nginx already installed\n"
    fi
    echoColor yellow "Checking acme.sh"
    if [[ -z `find ~/.acme.sh/ -name "acme.sh"` ]]
    then
        echoColor yellow "\nacme.sh not installed, installing\n"
        curl -s https://get.acme.sh | sh >/dev/null
        echoColor green "acme.sh installed\n"
    else
        echoColor green "acme.sh already installed\n"
    fi

}
# Restore config
resetNginxConfig(){
    `cp -Rrf /tmp/mack-a/nginx/nginx.conf /etc/nginx/nginx.conf`
    rm -rf /etc/nginx/conf.d/5NX2O9XQKP.conf
    echoColor green "\nNGINX Configuration Restored"
}
# Backup Config
bakConfig(){
    mkdir -p /tmp/mack-a/nginx
    `cp -Rrf /etc/nginx/nginx.conf /tmp/mack-a/nginx/nginx.conf`
}
# Install TLS
installTLS(){
    echoColor yellow "Please enter domain name【example: blog.v2ray-agent.com】:"
    read domain
    if [[ -z ${domain} ]]
    then
        echoColor red "Enter a valid domain name\n"
        installTLS
    fi
    # Backup
    bakConfig
    # Replace the domain name in original file
    if [[ ! -z `cat /etc/nginx/nginx.conf|grep -v grep|grep "${domain}"` ]]
    then
        sed -i "s/${domain}/X655Y0M9UM9/g"  `grep "${domain}" -rl /etc/nginx/nginx.conf`
    fi

    touch /etc/nginx/conf.d/6GFV1ES52V2.conf
    echo "server {listen 80;server_name ${domain};root /usr/share/nginx/html;location ~ /.well-known {allow all;}location /test {return 200 '5NX2O9XQKP';}}" > /etc/nginx/conf.d/5NX2O9XQKP.conf
    nginxStatus=1;
    if [[ ! -z `ps -ef|grep -v grep|grep nginx` ]]
    then
        nginxStatus=2;
        ps -ef|grep -v grep|grep nginx|awk '{print $2}'|xargs kill -9
        sleep 0.5
        nginx
    else
        nginx
    fi
    echoColor yellow "\nVerify domain name and server availability"
    if [[ ! -z `curl -s ${domain}/test|grep 5NX2O9XQKP` ]]
    then
        ps -ef|grep -v grep|grep nginx|awk '{print $2}'|xargs kill -9
        sleep 0.5
        echoColor green "Service available, generating TLS"
    else
        echoColor red "Service unavailable, please check configuration on DNS"
        # Restore Backup
        resetNginxConfig
        exit 0;
    fi
    sudo ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 >/dev/null
    ~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /tmp/mack-a/nginx/${domain}.crt --keypath /tmp/mack-a/nginx/${domain}.key --ecc >/dev/null
    if [[ -z `cat /tmp/mack-a/nginx/${domain}.key` ]]
    then
        echoColor red "Certificate Key generation Failed, please re-run script"
        resetNginxConfig
        exit
    elif [[ -z `cat /tmp/mack-a/nginx/${domain}.crt` ]]
    then
        echoColor red "Certificate CRT generation Failed, please re-run script"
        resetNginxConfig
        exit
    fi
    echoColor green "Certificate Successfully Created"
    echoColor green "View Certificate at [ /tmp/mack-a/nginx ]"
    ls /tmp/mack-a/nginx

    resetNginxConfig
    if [[ ${nginxStatus} = 2  ]]
    then
        nginx
    fi
}

init(){
    echoColor red "\n=============================="
    echoColor yellow "Guidelines"
    echoColor green "   01.  Required dependancies will be installed"
    echoColor green "   02.  Backup NGINX Configuration Files available"
    echoColor green "   03.  NGINX and acme.sh will be installed if unavailable in directory"
    echoColor green "   04.  NGINX will be backed up during installation, do not force stop"
    echoColor green "   05.  Do not restart machine while execution"
    echoColor green "   06.  Backup files and certificates saved in [ /tmp ]"
    echoColor green "   07.  Multiple execution of script will overwrite previous backups"
    echoColor green "   08.  Default certificate EC-256"
    echoColor green "   09.  Wildcard Certificate Unavailable [TODO]"
    echoColor green "   10.  Certificates for multiple domains & sub-domains can be generated [https://letsencrypt.org/zh-cn/docs/rate-limits/]"
    echoColor green "   11.  Supported OS are Centos, Ubuntu & Debian"
    echoColor green "   12.  Github Repo [https://github.com/mack-a]"
    echoColor red "=============================="
    echoColor yellow "Enter [y] to Install, [any] to exit the script: "
    read isExecStatus
    if [[ ${isExecStatus} = "y" ]]
    then
        installTools
        installTLS
    else
        echoColor green "See you next time!"
        exit
    fi
}
checkSystem
init
