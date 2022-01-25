#!/usr/bin/env bash
# Bash Detection
# -------------------------------------------------------------
# Check System
export LANG=en_US.UTF-8

#=================================================
#	System Required: CentOS 7/8,Debian/ubuntu,oraclelinux
#	Description: Translated to English 
#	Version: REV1-240122
#	Credit: mack-a
#=================================================

echoContent() {
	case $1 in
	# Red
	"red")
		# shellcheck disable=SC2154
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# Sky Blue
	"skyBlue")
		${echoType} "\033[1;36m${printN}$2 \033[0m"
		;;
		# Green
	"green")
		${echoType} "\033[32m${printN}$2 \033[0m"
		;;
		# White
	"white")
		${echoType} "\033[37m${printN}$2 \033[0m"
		;;
	"magenta")
		${echoType} "\033[31m${printN}$2 \033[0m"
		;;
		# Yellow
	"yellow")
		${echoType} "\033[33m${printN}$2 \033[0m"
		;;
	esac
}
checkSystem() {
	if [[ -n $(find /etc -name "redhat-release") ]] || grep </proc/version -q -i "centos"; then
		mkdir -p /etc/yum.repos.d

		if [[ -f "/etc/centos-release" ]]; then
			centosVersion=$(rpm -q centos-release | awk -F "[-]" '{print $3}' | awk -F "[.]" '{print $1}')

			if [[ -z "${centosVersion}" ]] && grep </etc/centos-release -q -i "release 8"; then
				centosVersion=8
			fi
		fi

		release="centos"
		installType='yum -y install'
		removeType='yum -y remove'
		upgrade="yum update -y --skip-broken"

	elif grep </etc/issue -q -i "debian" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "debian" && [[ -f "/proc/version" ]]; then
		release="debian"
		installType='apt -y install'
		upgrade="apt update"
		updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
		removeType='apt -y autoremove'

	elif grep </etc/issue -q -i "ubuntu" && [[ -f "/etc/issue" ]] || grep </etc/issue -q -i "ubuntu" && [[ -f "/proc/version" ]]; then
		release="ubuntu"
		installType='apt -y install'
		upgrade="apt update"
		updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
		removeType='apt -y autoremove'
		if grep </etc/issue -q -i "16."; then
			release=
		fi
	fi

	if [[ -z ${release} ]]; then
		echoContent red "\nThis script does not support this system, please send log below to the developer\n"
		echoContent yellow "$(cat /etc/issue)"
		echoContent yellow "$(cat /proc/version)"
		exit 0
	fi
}

# Checking CPU
checkCPUVendor() {
	if [[ -n $(which uname) ]]; then
		if [[ "$(uname)" == "Linux" ]]; then
			case "$(uname -m)" in
			'amd64' | 'x86_64')
				xrayCoreCPUVendor="Xray-linux-64"
				v2rayCoreCPUVendor="v2ray-linux-64"
				;;
			'armv8' | 'aarch64')
				xrayCoreCPUVendor="Xray-linux-arm64-v8a"
				v2rayCoreCPUVendor="v2ray-linux-arm64-v8a"
				;;
			*)
				echo "  This CPU Architecture is not Supported --->"
				exit 1
				;;
			esac
		fi
	else
		echoContent red "  CPU unrecoqnized, default is amd64、x86_64--->"
		xrayCoreCPUVendor="Xray-linux-64"
		v2rayCoreCPUVendor="v2ray-linux-64"
	fi
}

# Initialize global vars
initVar() {
	installType='yum -y install'
	removeType='yum -y remove'
	upgrade="yum -y update"
	echoType='echo -e'

	# Core Supported CPU Version
	xrayCoreCPUVendor=""
	v2rayCoreCPUVendor=""
	# Domain/Hostname
	domain=

	# CDN Node Address
	add=

	# Overall installation progress
	totalProgress=1

	# 1.xray-core install
	# 2.v2ray-core install
	# 3.v2ray-core[xtls] install
	coreInstallType=

	# Core installation path (unused)
	# coreInstallPath=

	# v2ctl Path
	ctlPath=
	# 1. Install All
	# 2. Personalized Install
	# v2rayAgentInstallType=

	# Current Personalized Installation Methods 01234
	currentInstallProtocolType=

	# Order of Current ALPN
	currentAlpn=

	# Pre-type
	frontingType=

	# Personalized Installation Method Choice
	selectCustomInstallType=

	# v2ray-core、xray-core Configuration Path
	configPath=

	# Configuration File Path
	currentPath=

	# Configuration Host File
	currentHost=

	# Selected Core Type
	selectCoreType=

	# Default Core Version
	v2rayCoreVersion=

	# Random Custom Path
	customPath=

	# centOS version
	centosVersion=

	# UUID
	currentUUID=

	localIP=

	# Integrated Update Certificate Logic (Not Separated)--RenewTLS
	renewTLS=$1

	# TLS Number of attempts
	installTLSCount=

	# BTPanel Status
	BTPanelStatus=

	# NGINX Default Configuration Path
	nginxConfigPath=/etc/nginx/conf.d/
}

# Installation Method Check
readInstallType() {
	coreInstallType=
	configPath=

	# 1. Directory Check
	if [[ -d "/etc/v2ray-agent" ]]; then
		# Install Method - v2ray-core
		if [[ -d "/etc/v2ray-agent/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ray" && -f "/etc/v2ray-agent/v2ray/v2ctl" ]]; then
			if [[ -d "/etc/v2ray-agent/v2ray/conf" && -f "/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json" ]]; then
				configPath=/etc/v2ray-agent/v2ray/conf/

				if ! grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q xtls; then
					# Without XTLS - v2ray-core
					coreInstallType=2
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
				elif grep </etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json -q xtls; then
					# With XTLS - v2ray-core
					ctlPath=/etc/v2ray-agent/v2ray/v2ctl
					coreInstallType=3
				fi
			fi
		fi

		if [[ -d "/etc/v2ray-agent/xray" && -f "/etc/v2ray-agent/xray/xray" ]]; then
			# Verify xray-core
			if [[ -d "/etc/v2ray-agent/xray/conf" ]] && [[ -f "/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json" || -f "/etc/v2ray-agent/xray/conf/02_trojan_TCP_inbounds.json" ]]; then
				# xray-core
				configPath=/etc/v2ray-agent/xray/conf/
				ctlPath=/etc/v2ray-agent/xray/xray
				coreInstallType=1
			fi
		fi
	fi
}

# Read Installation Protocol Type
readInstallProtocolType() {
	currentInstallProtocolType=

	while read -r row; do
		if echo "${row}" | grep -q 02_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'trojan'
			frontingType=02_trojan_TCP_inbounds
		fi
		if echo "${row}" | grep -q VLESS_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'0'
			frontingType=02_VLESS_TCP_inbounds
		fi
		if echo "${row}" | grep -q VLESS_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'1'
		fi
		if echo "${row}" | grep -q trojan_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'2'
		fi
		if echo "${row}" | grep -q VMess_WS_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'3'
		fi
		if echo "${row}" | grep -q 04_trojan_TCP_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'4'
		fi
		if echo "${row}" | grep -q VLESS_gRPC_inbounds; then
			currentInstallProtocolType=${currentInstallProtocolType}'5'
		fi
	done < <(find ${configPath} -name "*inbounds.json" | awk -F "[.]" '{print $1}')
}

# Check BT Panel Installed
checkBTPanel() {
	if pgrep -f "BT-Panel"; then
		nginxConfigPath=/www/server/panel/vhost/nginx/
		BTPanelStatus=true
	fi
}
# Check ALPN Installation Order
readInstallAlpn() {
	if [[ -n ${currentInstallProtocolType} ]]; then
		local alpn
		alpn=$(jq -r .inbounds[0].streamSettings.xtlsSettings.alpn[0] ${configPath}${frontingType}.json)
		if [[ -n ${alpn} ]]; then
			currentAlpn=${alpn}
		fi
	fi
}

# Firewall Check
allowPort() {
	# If firewall is already enabled, add the corresponding open port
	if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
		local updateFirewalldStatus=
		if ! iptables -L | grep -q "http(kashifabs)"; then
			updateFirewalldStatus=true
			iptables -I INPUT -p tcp --dport 80 -m comment --comment "allow http(kashifabs)" -j ACCEPT
		fi

		if ! iptables -L | grep -q "https(kashifabs)"; then
			updateFirewalldStatus=true
			iptables -I INPUT -p tcp --dport 443 -m comment --comment "allow https(kashifabs)" -j ACCEPT
		fi

		if echo "${updateFirewalldStatus}" | grep -q "true"; then
			netfilter-persistent save
		fi
	elif systemctl status ufw 2>/dev/null | grep -q "active (exited)"; then
		if ! ufw status | grep -q 443; then
			sudo ufw allow https
			checkUFWAllowPort 443
		fi

		if ! ufw status | grep -q 80; then
			sudo ufw allow 80
			checkUFWAllowPort 80
		fi
	elif systemctl status firewalld 2>/dev/null | grep -q "active (running)"; then
		local updateFirewalldStatus=
		if ! firewall-cmd --list-ports --permanent | grep -qw "80/tcp"; then
			updateFirewalldStatus=true
			firewall-cmd --zone=public --add-port=80/tcp --permanent
			checkFirewalldAllowPort 80
		fi

		if ! firewall-cmd --list-ports --permanent | grep -qw "443/tcp"; then
			updateFirewalldStatus=true
			firewall-cmd --zone=public --add-port=443/tcp --permanent
			checkFirewalldAllowPort 443
		fi
		if echo "${updateFirewalldStatus}" | grep -q "true"; then
			firewall-cmd --reload
		fi
	fi
}

# Check Used Port -> 80 | 443
checkPortUsedStatus() {
	if lsof -i tcp:80 | grep -q LISTEN; then
		echoContent red "\n ---> Port 80 is already used, Please Close Manually and Re-install\n"
		lsof -i tcp:80 | grep LISTEN
		exit 0
	fi

	if lsof -i tcp:443 | grep -q LISTEN; then
		echoContent red "\n ---> Port 443 is already used, Please Close Manually and Re-install\n"
		lsof -i tcp:80 | grep LISTEN
		exit 0
	fi
}

# Output UFW Port Open Status
checkUFWAllowPort() {
	if ufw status | grep -q "$1"; then
		echoContent green " ---> Port ($1) Successfully Opened"
	else
		echoContent red " ---> Port ($1) Failed to Open"
		exit 0
	fi
}

# Output Firewall Port Open Status
checkFirewalldAllowPort() {
	if firewall-cmd --list-ports --permanent | grep -q "$1"; then
		echoContent green " ---> Port ($1) Successfully Opened"
	else
		echoContent red " ---> Port ($1) Failed to Open"
		exit 0
	fi
}
# Check File Directory and PATH
readConfigHostPathUUID() {
	currentPath=
	currentUUID=
	currentHost=
	currentPort=
	currentAdd=
	# PATH Read
	if [[ -n "${configPath}" ]]; then
		local fallback
		fallback=$(jq -r -c '.inbounds[0].settings.fallbacks[]|select(.path)' ${configPath}${frontingType}.json | head -1)

		local path
		path=$(echo "${fallback}" | jq -r .path | awk -F "[/]" '{print $2}')

		if [[ $(echo "${fallback}" | jq -r .dest) == 31297 ]]; then
			currentPath=$(echo "${path}" | awk -F "[w][s]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) == 31298 ]]; then
			currentPath=$(echo "${path}" | awk -F "[t][c][p]" '{print $1}')
		elif [[ $(echo "${fallback}" | jq -r .dest) == 31299 ]]; then
			currentPath=$(echo "${path}" | awk -F "[v][w][s]" '{print $1}')
		fi
	fi

	if [[ "${coreInstallType}" == "1" ]]; then
		currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)
		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		fi
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)

	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		if [[ "${coreInstallType}" == "3" ]]; then
			currentHost=$(jq -r .inbounds[0].streamSettings.xtlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		else
			currentHost=$(jq -r .inbounds[0].streamSettings.tlsSettings.certificates[0].certificateFile ${configPath}${frontingType}.json | awk -F '[t][l][s][/]' '{print $2}' | awk -F '[.][c][r][t]' '{print $1}')
		fi
		currentAdd=$(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json)

		if [[ "${currentAdd}" == "null" ]]; then
			currentAdd=${currentHost}
		fi
		currentUUID=$(jq -r .inbounds[0].settings.clients[0].id ${configPath}${frontingType}.json)
		currentPort=$(jq .inbounds[0].port ${configPath}${frontingType}.json)
	fi
}

# Installation Status Display
showInstallStatus() {
	if [[ -n "${coreInstallType}" ]]; then
		if [[ "${coreInstallType}" == 1 ]]; then
			if [[ -n $(pgrep -f xray/xray) ]]; then
				echoContent yellow "\nCORE:Xray-core[RUNNING]"
			else
				echoContent yellow "\nCORE:Xray-core[NOT RUNNING]"
			fi

		elif [[ "${coreInstallType}" == 2 || "${coreInstallType}" == 3 ]]; then
			if [[ -n $(pgrep -f v2ray/v2ray) ]]; then
				echoContent yellow "\nCORE:v2ray-core[RUNNING]"
			else
				echoContent yellow "\nCORE:v2ray-core[NOT RUNNING]"
			fi
		fi
		# Reading Protocol Type
		readInstallProtocolType

		if [[ -n ${currentInstallProtocolType} ]]; then
			echoContent yellow "Installed Protocol(s):\c"
		fi
		if echo ${currentInstallProtocolType} | grep -q 0; then
			if [[ "${coreInstallType}" == 2 ]]; then
				echoContent yellow "VLESS+TCP[TLS] \c"
			else
				echoContent yellow "VLESS+TCP[TLS/XTLS] \c"
			fi
		fi

		if echo ${currentInstallProtocolType} | grep -q trojan; then
			if [[ "${coreInstallType}" == 1 ]]; then
				echoContent yellow "Trojan+TCP[TLS/XTLS] \c"
			fi
		fi

		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent yellow "VLESS+WS[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			echoContent yellow "Trojan+gRPC[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent yellow "VMess+WS[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			echoContent yellow "Trojan+TCP[TLS] \c"
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent yellow "VLESS+gRPC[TLS] \c"
		fi
	fi
}

# Cleanup Old Files
cleanUp() {
	if [[ "$1" == "v2rayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/v2ray/* | grep -E '(config_full.json|conf)')"
		handleV2Ray stop >/dev/null
		rm -f /etc/systemd/system/v2ray.service
	elif [[ "$1" == "xrayClean" ]]; then
		rm -rf "$(find /etc/v2ray-agent/xray/* | grep -E '(config_full.json|conf)')"
		handleXray stop >/dev/null
		rm -f /etc/systemd/system/xray.service

	elif [[ "$1" == "v2rayDel" ]]; then
		rm -rf /etc/v2ray-agent/v2ray/*

	elif [[ "$1" == "xrayDel" ]]; then
		rm -rf /etc/v2ray-agent/xray/*
	fi
}

initVar "$1"
checkSystem
checkCPUVendor
readInstallType
readInstallProtocolType
readConfigHostPathUUID
readInstallAlpn
checkBTPanel

# -------------------------------------------------------------

# Initialize Installation Directory
mkdirTools() {
	mkdir -p /etc/v2ray-agent/tls
	mkdir -p /etc/v2ray-agent/subscribe
	mkdir -p /etc/v2ray-agent/subscribe_tmp
	mkdir -p /etc/v2ray-agent/v2ray/conf
	mkdir -p /etc/v2ray-agent/xray/conf
	mkdir -p /etc/v2ray-agent/trojan
	mkdir -p /etc/systemd/system/
	mkdir -p /tmp/v2ray-agent-tls/
}

# Installation Kit
installTools() {
	echo 'Installation Tools'
	echoContent skyBlue "\n $1/${totalProgress} : Installing Dependancies"
	# Fix Ubuntu Individual System Problem
	if [[ "${release}" == "ubuntu" ]]; then
		dpkg --configure -a
	fi

	if [[ -n $(pgrep -f "apt") ]]; then
		pgrep -f apt | xargs kill -9
	fi

	echoContent green " ---> Checking and Installing Updates【The VPS will run slowly, if there is stuck progression, stop&restart manually】"

	${upgrade} >/etc/v2ray-agent/install.log 2>&1
	if grep <"/etc/v2ray-agent/install.log" -q "changed"; then
		${updateReleaseInfoChange} >/dev/null 2>&1
	fi

	if [[ "${release}" == "centos" ]]; then
		rm -rf /var/run/yum.pid
		${installType} epel-release >/dev/null 2>&1
	fi

	#	[[ -z `find /usr/bin /usr/sbin |grep -v grep|grep -w curl` ]]

	if ! find /usr/bin /usr/sbin | grep -q -w wget; then
		echoContent green " ---> Installing wget"
		${installType} wget >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w curl; then
		echoContent green " ---> Installing curl"
		${installType} curl >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w unzip; then
		echoContent green " ---> Installing unzip"
		${installType} unzip >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w socat; then
		echoContent green " ---> Installing socat"
		${installType} socat >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w tar; then
		echoContent green " ---> Installing tar"
		${installType} tar >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w cron; then
		echoContent green " ---> Installing crontabs"
		if [[ "${release}" == "ubuntu" ]] || [[ "${release}" == "debian" ]]; then
			${installType} cron >/dev/null 2>&1
		else
			${installType} crontabs >/dev/null 2>&1
		fi
	fi
	if ! find /usr/bin /usr/sbin | grep -q -w jq; then
		echoContent green " ---> Installing jq"
		${installType} jq >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w binutils; then
		echoContent green " ---> Installing binutils"
		${installType} binutils >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w ping6; then
		echoContent green " ---> Installing ping6"
		${installType} inetutils-ping >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w qrencode; then
		echoContent green " ---> Installing qrencode"
		${installType} qrencode >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w sudo; then
		echoContent green " ---> Installing sudo"
		${installType} sudo >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w lsb-release; then
		echoContent green " ---> Installing lsb-release"
		${installType} lsb-release >/dev/null 2>&1
	fi

	if ! find /usr/bin /usr/sbin | grep -q -w lsof; then
		echoContent green " ---> Installing lsof"
		${installType} lsof >/dev/null 2>&1
	fi

	# Detecting NGINX version, and providing Uninstall Option

	if ! find /usr/bin /usr/sbin | grep -q -w nginx; then
		echoContent green " ---> Installing nginx"
		installNginxTools
	else
		nginxVersion=$(nginx -v 2>&1)
		nginxVersion=$(echo "${nginxVersion}" | awk -F "[n][g][i][n][x][/]" '{print $2}' | awk -F "[.]" '{print $2}')
		if [[ ${nginxVersion} -lt 14 ]]; then
			read -r -p "The Current NGINX Version doesn't support gRPC and failiing installation. Uninstall NGINX and Re-Install it? [y/n]:" unInstallNginxStatus
			if [[ "${unInstallNginxStatus}" == "y" ]]; then
				${removeType} nginx >/dev/null 2>&1
				echoContent yellow " ---> Uninstalled NGINX"
				echoContent green " ---> Re-Installing NGINX"
				installNginxTools >/dev/null 2>&1
			else
				exit 0
			fi
		fi
	fi
	if ! find /usr/bin /usr/sbin | grep -q -w semanage; then
		echoContent green " ---> Installing semanage"
		${installType} bash-completion >/dev/null 2>&1

		if [[ "${centosVersion}" == "7" ]]; then
			policyCoreUtils="policycoreutils-python.x86_64"
		elif [[ "${centosVersion}" == "8" ]]; then
			policyCoreUtils="policycoreutils-python-utils-2.9-9.el8.noarch"
		fi

		if [[ -n "${policyCoreUtils}" ]]; then
			${installType} ${policyCoreUtils} >/dev/null 2>&1
		fi
		if [[ -n $(which semanage) ]]; then
			semanage port -a -t http_port_t -p tcp 31300

		fi
	fi

	if [[ ! -d "$HOME/.acme.sh" ]] || [[ -d "$HOME/.acme.sh" && -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
		echoContent green " ---> Installing acme.sh"
		curl -s https://get.acme.sh | sh -s >/etc/v2ray-agent/tls/acme.log 2>&1
		if [[ ! -d "$HOME/.acme.sh" ]] || [[ -z $(find "$HOME/.acme.sh/acme.sh") ]]; then
			echoContent red "  Failed to install acme --->"
			tail -n 100 /etc/v2ray-agent/tls/acme.log
			echoContent yellow "Troubleshooting:"
			echoContent red "  1. Failed to retrieve Github files, check Github Status [https://www.githubstatus.com/]"
			echoContent red "  2. If there is a bug in acme.sh script, visit the site to view issues [https://github.com/acmesh-official/acme.sh]"
			exit 0
		fi
	fi
}

# NGINX Installation
installNginxTools() {

	if [[ "${release}" == "debian" ]]; then
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
		echo "deb http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
		echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
		curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
		# gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
		sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		cat <<EOF >/etc/yum.repos.d/nginx.repo
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true

[nginx-mainline]
name=nginx mainline repo
baseurl=http://nginx.org/packages/mainline/centos/\$releasever/\$basearch/
gpgcheck=1
enabled=0
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
		sudo yum-config-manager --enable nginx-mainline >/dev/null 2>&1
	fi
	${installType} nginx >/dev/null 2>&1
	systemctl daemon-reload
	systemctl enable nginx
}

# Install Warp
installWarp() {
	${installType} gnupg2 -y >/dev/null 2>&1
	if [[ "${release}" == "debian" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "ubuntu" ]]; then
		curl -s https://pkg.cloudflareclient.com/pubkey.gpg | sudo apt-key add - >/dev/null 2>&1
		echo "deb http://pkg.cloudflareclient.com/ focal main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list >/dev/null 2>&1
		sudo apt update >/dev/null 2>&1

	elif [[ "${release}" == "centos" ]]; then
		${installType} yum-utils >/dev/null 2>&1
		sudo rpm -ivh "http://pkg.cloudflareclient.com/cloudflare-release-el${centosVersion}.rpm" >/dev/null 2>&1
	fi

	echoContent green " ---> Installing WARP"
	${installType} cloudflare-warp >/dev/null 2>&1
	if [[ -z $(which warp-cli) ]]; then
		echoContent red " ---> Failed to Install WARP"
		exit 0
	fi
	systemctl enable warp-svc
	warp-cli --accept-tos register
	warp-cli --accept-tos set-mode proxy
	warp-cli --accept-tos set-proxy-port 31303
	warp-cli --accept-tos connect
	warp-cli --accept-tos enable-always-on


	#	if [[]];then
	#	fi
	# todo curl --socks5 127.0.0.1:31303 https://www.cloudflare.com/cdn-cgi/trace
	# systemctl daemon-reload
	# systemctl enable cloudflare-warp
}
# Initialize NGINX Application Certificate Config
initTLSNginxConfig() {
	handleNginx stop
	echoContent skyBlue "\n $1/${totalProgress} : Initializing NGINX Application Certificate Configuration"
	if [[ -n "${currentHost}" ]]; then
		echo
		read -r -p "Are you using the same domain/hostname for NGINX TLS (${currentHost}) ? [y/n]:" historyDomainStatus
		if [[ "${historyDomainStatus}" == "y" ]]; then
			domain=${currentHost}
			echoContent yellow "\n ---> Domain/Hostname:${domain}"
		else
			echo
			echoContent yellow "Please enter the domain name to be configured, example:www.v2ray-agent.com --->"
			read -r -p "Domain:" domain
		fi
	else
		echo
		echoContent yellow "Please enter the domain name to be configured, example:www.v2ray-agent.com --->"
		read -r -p "Domain:" domain
	fi

	if [[ -z ${domain} ]]; then
		echoContent red "  Domain name cannot be Empty, please fill in --->"
		initTLSNginxConfig 3
	else
		# Change settings
		touch ${nginxConfigPath}alone.conf
		cat <<EOF >${nginxConfigPath}alone.conf
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    root /usr/share/nginx/html;
    location ~ /.well-known {
    	allow all;
    }
    location /test {
    	return 200 'NGINX Configured - kashifabs.ml';
    }
	location /ip {
		proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header REMOTE-HOST \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		default_type text/plain;
		return 200 \$proxy_add_x_forwarded_for;
	}
}
EOF
		# Start NGINX
		handleNginx start
		checkIP
	fi
}

# Modify NGINX Redirect Configuration
updateRedirectNginxConf() {

	if [[ ${BTPanelStatus} == "true" ]]; then

		cat <<EOF >${nginxConfigPath}alone.conf
        server {
        		listen 127.0.0.1:31300;
        		server_name _;
        		return 403;
        }
EOF

	else
		cat <<EOF >${nginxConfigPath}alone.conf
        server {
        	listen 80;
        	listen [::]:80;
        	server_name ${domain};
        	# shellcheck disable=SC2154
        	return 301 https://${domain}\${request_uri};
        }
        server {
        		listen 127.0.0.1:31300;
        		server_name _;
        		return 403;
        }
EOF
	fi

	if echo "${selectCustomInstallType}" | grep -q 2 && echo "${selectCustomInstallType}" | grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }

    location /${currentPath}grpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}

	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31304;
	}
}
EOF
	elif echo "${selectCustomInstallType}" | grep -q 5 || [[ -z "${selectCustomInstallType}" ]]; then
		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}grpc {
		client_max_body_size 0;
#		keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
}
EOF

	elif echo "${selectCustomInstallType}" | grep -q 2 || [[ -z "${selectCustomInstallType}" ]]; then

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location /${currentPath}trojangrpc {
		client_max_body_size 0;
		# keepalive_time 1071906480m;
		keepalive_requests 4294967296;
		client_body_timeout 1071906480m;
 		send_timeout 1071906480m;
 		lingering_close always;
 		grpc_read_timeout 1071906480m;
 		grpc_send_timeout 1071906480m;
		grpc_pass grpc://127.0.0.1:31301;
	}
}
EOF
	else

		cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31302 http2;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
    		add_header Content-Type text/plain;
    		alias /etc/v2ray-agent/subscribe/;
    }
	location / {
	}
}
EOF
	fi

	cat <<EOF >>${nginxConfigPath}alone.conf
server {
	listen 127.0.0.1:31300;
	server_name ${domain};
	root /usr/share/nginx/html;
	location /s/ {
		add_header Content-Type text/plain;
		alias /etc/v2ray-agent/subscribe/;
	}
	location / {
		add_header Strict-Transport-Security "max-age=15552000; preload" always;
	}
}
EOF

}

# Check IP
checkIP() {
	echoContent skyBlue "\n ---> Check Domain Name IP Address"
	localIP=$(curl -s -m 2 "${domain}/ip")
	handleNginx stop
	if [[ -z ${localIP} ]] || ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q '\.' && ! echo "${localIP}" | sed '1{s/[^(]*(//;s/).*//;q}' | grep -q ':'; then
		echoContent red "\n ---> IP of current Domain Name (${domain}) is not detected"
		echoContent yellow " ---> Please check if domain name spelling correctly"
		echoContent yellow " ---> Please check DNS resolution setup correctly"
		echoContent yellow " ---> If the DNS is setup correctly, wait for 3 minutes for changes to take effect"
		echoContent yellow " ---> If all the settings are correct, re-install on a clean vps and try again"
		if [[ -n ${localIP} ]]; then
			echoContent yellow " ---> NGINX is not installed properly, please manually remove NGINX and re-run the script"
		fi
		echoContent red " ---> Please check for firewall rules on port [ 443 | 80 ]\n"
		read -r -p "Remodify firewall rules for open port (443, 80) using installation script? [y/n]:" allPortFirewallStatus
		if [[ ${allPortFirewallStatus} == "y" ]]; then
			allowPort
			handleNginx start
			checkIP
		else
			exit 0
		fi
	else
		if echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q "." || echo "${localIP}" | awk -F "[,]" '{print $2}' | grep -q ":"; then
			echoContent red "\n ---> Multiple IPs are detected, please close Cloudflare Proxy (Orange Cloud Icon)"
			echoContent yellow " ---> Wait for 3 minutes after closing Cloudflare proxy"
			echoContent yellow " ---> IPs detected:[${localIP}]"
			exit 0
		fi
		echoContent green " ---> Current domain name used:[${localIP}]"
	fi

}
# Install TLS
installTLS() {
	echoContent skyBlue "\n $1/${totalProgress} : Requesting TLS Certificate\n"
	local tlsDomain=${domain}
	# TLS Installation
	if [[ -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" && -f "/etc/v2ray-agent/tls/${tlsDomain}.key" && -n $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]] || [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
		echoContent green " ---> Certificate Detected"
		# checkTLStatus
		renewalTLS

		if [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.crt") ]] || [[ -z $(find /etc/v2ray-agent/tls/ -name "${tlsDomain}.key") ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
		else
			echoContent yellow " ---> Please select custom certificate if not expired[n]\n"
			read -r -p "Re-install TLS? [y/n]:" reInstallStatus
			if [[ "${reInstallStatus}" == "y" ]]; then
				rm -rf /etc/v2ray-agent/tls/*
				installTLS "$1"
			fi
		fi

	elif [[ -d "$HOME/.acme.sh" ]] && [[ ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" || ! -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" ]]; then
		echoContent green " ---> Installing TLS Certificate"
		if echo "${localIP}" | grep -q ":"; then
			sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server letsencrypt --listen-v6 | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
		else
			sudo "$HOME/.acme.sh/acme.sh" --issue -d "${tlsDomain}" --standalone -k ec-256 --server letsencrypt | tee -a /etc/v2ray-agent/tls/acme.log >/dev/null
		fi

		if [[ -d "$HOME/.acme.sh/${tlsDomain}_ecc" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.key" && -f "$HOME/.acme.sh/${tlsDomain}_ecc/${tlsDomain}.cer" ]]; then
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${tlsDomain}" --fullchainpath "/etc/v2ray-agent/tls/${tlsDomain}.crt" --keypath "/etc/v2ray-agent/tls/${tlsDomain}.key" --ecc >/dev/null
		fi
		if [[ ! -f "/etc/v2ray-agent/tls/${tlsDomain}.crt" || ! -f "/etc/v2ray-agent/tls/${tlsDomain}.key" ]] || [[ -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.key") || -z $(cat "/etc/v2ray-agent/tls/${tlsDomain}.crt") ]]; then
			tail -n 10 /etc/v2ray-agent/tls/acme.log
			if [[ ${installTLSCount} == "1" ]]; then
				echoContent red " ---> TLS Installation Failed, Please check acme.log file"
				exit 0
			fi
			echoContent red " ---> TLS Installation failed, checking port status [ 80 | 443 ]"
			allowPort
			echoContent yellow " ---> Retrying TLS Certificate Installation"
			installTLSCount=1
			installTLS "$1"
		fi
		echoContent green " ---> TLS Installation Success"
	else
		echoContent yellow " ---> acme.sh is not installed"
		exit 0
	fi
}
# Configuring Camouflage Page
initNginxConfig() {
	echoContent skyBlue "\n $1/${totalProgress} : Configuring NGINX"

	cat <<EOF >${nginxConfigPath}alone.conf
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};
    root /usr/share/nginx/html;
    location ~ /.well-known {allow all;}
    location /test {return 200 'NGINX Configured - kashifabs.ml';}
}
EOF
}

# Custom/Random Path
randomPathFunction() {
	echoContent skyBlue "\n $1/${totalProgress} : Generating Random PATH"

	if [[ -n "${currentPath}" ]]; then
		echo
		read -r -p "Install using previous PATH (${currentPath}) ? [y/n]:" historyPathStatus
		echo
	fi

	if [[ "${historyPathStatus}" == "y" ]]; then
		customPath=${currentPath}
		echoContent green " ---> Custom PATH Setup Successfully using ${currentPath}\n"
	else
		echoContent yellow "Please enter a custom path name [example: custom], no slashes '/' required, press [Enter]"
		read -r -p 'PATH:' customPath

		if [[ -z "${customPath}" ]]; then
			customPath=$(head -n 50 /dev/urandom | sed 's/[^a-z]//g' | strings -n 4 | tr '[:upper:]' '[:lower:]' | head -1)
			currentPath=${customPath:0:4}
			customPath=${currentPath}
		else
			currentPath=${customPath}
		fi

	fi
	echoContent yellow "\n PATH:${currentPath}"
	echoContent skyBlue "\n----------------------------"
}
# NGINX Camouflage Website
nginxBlog() {
	echoContent skyBlue "\n $1/${totalProgress} : Adding camouflage website"
	if [[ -d "/usr/share/nginx/html" && -f "/usr/share/nginx/html/check" ]]; then
		echo
		read -r -p "Previous Website Installation Detected, do you want to re-install? [y/n]:" nginxBlogInstallStatus
		if [[ "${nginxBlogInstallStatus}" == "y" ]]; then
			rm -rf /usr/share/nginx/html
			randomNum=$((RANDOM % 6 + 1))
			wget -q -P /usr/share/nginx https://raw.githubusercontent.com/kashimaruu/multi-script/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
			unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
			rm -f /usr/share/nginx/html${randomNum}.zip*
			echoContent green " ---> Successfully added camouflage website"
		fi
	else
		randomNum=$((RANDOM % 6 + 1))
		rm -rf /usr/share/nginx/html
		wget -q -P /usr/share/nginx https://raw.githubusercontent.com/kashimaruu/multi-script/master/fodder/blog/unable/html${randomNum}.zip >/dev/null
		unzip -o /usr/share/nginx/html${randomNum}.zip -d /usr/share/nginx/html >/dev/null
		rm -f /usr/share/nginx/html${randomNum}.zip*
		echoContent green " ---> Successfully added camouflage website"
	fi

}
# Handle NGINX
handleNginx() {

	if [[ -z $(pgrep -f "nginx") ]] && [[ "$1" == "start" ]]; then
		systemctl start nginx
		sleep 0.5

		if [[ -z $(pgrep -f nginx) ]]; then
			echoContent red " ---> NGINX Failed to Start"
			echoContent red " ---> Please install NGINX manually and execute the script again"
			exit 0
		fi
	elif [[ -n $(pgrep -f "nginx") ]] && [[ "$1" == "stop" ]]; then
		systemctl stop nginx
		sleep 0.5
		if [[ -n $(pgrep -f "nginx") ]]; then
			pgrep -f "nginx" | xargs kill -9
		fi
	fi
}

# Schedule task to update TLS Certificate
installCronTLS() {
	echoContent skyBlue "\n $1/${totalProgress} : Adding regular maintenance TLS certificate"
	crontab -l >/etc/v2ray-agent/backup_crontab.cron
	local historyCrontab
	historyCrontab=$(sed '/v2ray-agent/d;/acme.sh/d' /etc/v2ray-agent/backup_crontab.cron)
	echo "${historyCrontab}" >/etc/v2ray-agent/backup_crontab.cron
	echo "30 1 * * * /bin/bash /etc/v2ray-agent/install.sh RenewTLS >> /etc/v2ray-agent/crontab_tls.log 2>&1" >>/etc/v2ray-agent/backup_crontab.cron
	crontab /etc/v2ray-agent/backup_crontab.cron
	echoContent green "\n ---> Successfully added regular maintenance TLS certificate"
}

# Update TLS Certificate
renewalTLS() {
	if [[ -n $1 ]]; then
		echoContent skyBlue "\n $1/1 : Renewing TLS certificate"
	fi
	local domain=${currentHost}
	if [[ -z "${currentHost}" && -n "${tlsDomain}" ]]; then
		domain=${tlsDomain}
	fi

	if [[ -d "$HOME/.acme.sh/${domain}_ecc" ]] && [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.key" ]] && [[ -f "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" ]]; then
		modifyTime=$(stat "$HOME/.acme.sh/${domain}_ecc/${domain}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

		modifyTime=$(date +%s -d "${modifyTime}")
		currentTime=$(date +%s)
		((stampDiff = currentTime - modifyTime))
		((days = stampDiff / 86400))
		((remainingDays = 90 - days))

		tlsStatus=${remainingDays}
		if [[ ${remainingDays} -le 0 ]]; then
			tlsStatus="Expired"
		fi

		echoContent skyBlue " ---> Certificate Check Date: $(date "+%F %H:%M:%S")"
		echoContent skyBlue " ---> Certificate Generated on: $(date -d @"${modifyTime}" +"%F %H:%M:%S")"
		echoContent skyBlue " ---> Certificate Duration (days): ${days}"
		echoContent skyBlue " ---> Certificate Expiry (days): "${tlsStatus}
		echoContent skyBlue " ---> Certificate is automatically updated on last expiry date, please update manually if certificate update fails."

		if [[ ${remainingDays} -le 1 ]]; then
			echoContent yellow " ---> Regenerate Certificate"
			handleNginx stop
			sudo "$HOME/.acme.sh/acme.sh" --cron --home "$HOME/.acme.sh"
			sudo "$HOME/.acme.sh/acme.sh" --installcert -d "${domain}" --fullchainpath /etc/v2ray-agent/tls/"${domain}.crt" --keypath /etc/v2ray-agent/tls/"${domain}.key" --ecc
			reloadCore
			handleNginx start
		else
			echoContent green " ---> Certificate is Valid"
		fi
	else
		echoContent red " ---> TLS Certificate Not Installed"
	fi
}
# Check TLS Certificate Status
checkTLStatus() {

	if [[ -d "$HOME/.acme.sh/${currentHost}_ecc" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.key" ]] && [[ -f "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" ]]; then
		modifyTime=$(stat "$HOME/.acme.sh/${currentHost}_ecc/${currentHost}.cer" | sed -n '7,6p' | awk '{print $2" "$3" "$4" "$5}')

		modifyTime=$(date +%s -d "${modifyTime}")
		currentTime=$(date +%s)
		((stampDiff = currentTime - modifyTime))
		((days = stampDiff / 86400))
		((remainingDays = 90 - days))

		tlsStatus=${remainingDays}
		if [[ ${remainingDays} -le 0 ]]; then
			tlsStatus="Expired"
		fi

		echoContent skyBlue " ---> Certificate Generated on: $(date -d "@${modifyTime}" +"%F %H:%M:%S")"
		echoContent skyBlue " ---> Certificate Duration (days): ${days}"
		echoContent skyBlue " ---> Certificate Expiry (days): ${tlsStatus}"
	fi
}

# Installing v2Ray, specifying version
installV2Ray() {
	readInstallType
	echoContent skyBlue "\n $1/${totalProgress} : Installing V2Ray"

	if [[ "${coreInstallType}" != "2" && "${coreInstallType}" != "3" ]]; then
		if [[ "${selectCoreType}" == "2" ]]; then

			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | head -1)
		else
			version=${v2rayCoreVersion}
		fi

		echoContent green " ---> v2ray-core version: ${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
	else
		if [[ "${selectCoreType}" == "3" ]]; then
			echoContent green " ---> v2ray-core version default (v4.32.1)"
			rm -f /etc/v2ray-agent/v2ray/v2ray
			rm -f /etc/v2ray-agent/v2ray/v2ctl
			installV2Ray "$1"
		else
			echoContent green " ---> v2ray-core version: $(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
			read -r -p "Do you want to update v2ray-core? [y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				installV2Ray "$1"
			fi
		fi
	fi
}

# Install Xray
installXray() {
	readInstallType
	echoContent skyBlue "\n $1/${totalProgress} : Installing Xray"

	if [[ "${coreInstallType}" != "1" ]]; then

		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name | head -1)

		echoContent green " ---> Xray-core version: ${version}"
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
		rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
		chmod 655 /etc/v2ray-agent/xray/xray
	else
		echoContent green " ---> Xray-core version: $(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
		read -r -p "Do you want to update Xray-core? [y/n]:" reInstallXrayStatus
		if [[ "${reInstallXrayStatus}" == "y" ]]; then
			rm -f /etc/v2ray-agent/xray/xray
			installXray "$1"
		fi
	fi
}

# v2Ray Version Management
v2rayVersionManageMenu() {
	echoContent skyBlue "\n $1/${totalProgress} : Checking V2Ray Version"
	if [[ ! -d "/etc/v2ray-agent/v2ray/" ]]; then
		echoContent red " ---> V2Ray is not installed/detected. Please execute the script to install V2Ray"
		menu
		exit 0
	fi
	echoContent red "\n=============================================================="
	echoContent yellow "1. Update V2Ray"
	echoContent yellow "2. Downgrade V2Ray version"
	echoContent yellow "3. Close v2ray-core"
	echoContent yellow "4. Open v2ray-core"
	echoContent yellow "5. Reboot v2ray-core"
	echoContent red "=============================================================="
	read -r -p "Select (1-5): " selectV2RayType
	if [[ "${selectV2RayType}" == "1" ]]; then
		updateV2Ray
	elif [[ "${selectV2RayType}" == "2" ]]; then
		echoContent yellow "\n1. Only previous 5 versions can be re-installed"
		echoContent yellow "2. There is no guarantee on the previous version to work normally"
		echoContent yellow "3. If the previous version does not support current config, V2Ray might not work"
		echoContent yellow "4. Please proceed with caution"
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | head -5 | awk '{print ""NR""":"$0}'

		echoContent skyBlue "--------------------------------------------------------------"
		read -r -p "Please enter v2ray-core previous version: " selectV2rayVersionType
		version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[]|select (.prerelease==false)|.tag_name' | head -5 | awk '{print ""NR""":"$0}' | grep "${selectV2rayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateV2Ray "${version}"
		else
			echoContent red "\n ---> Input is incorrect, please try again"
			v2rayVersionManageMenu 1
		fi
	elif [[ "${selectXrayType}" == "3" ]]; then
		handleV2Ray stop
	elif [[ "${selectXrayType}" == "4" ]]; then
		handleV2Ray start
	elif [[ "${selectXrayType}" == "5" ]]; then
		reloadCore
	fi
}

# xray Version Management
xrayVersionManageMenu() {
	echoContent skyBlue "\n $1/${totalProgress} : Checking Xray Version"
	if [[ ! -d "/etc/v2ray-agent/xray/" ]]; then
		echoContent red " ---> XRay is not installed/detected. Please execute the script to install XRay"
		menu
		exit 0
	fi
	echoContent red "\n=============================================================="
	echoContent yellow "1. Update XRay"
	echoContent yellow "2. Downgrade Xray version"
	echoContent yellow "3. Close Xray-core"
	echoContent yellow "4. Open Xray-core"
	echoContent yellow "5. Reboot Xray-core"
	echoContent red "=============================================================="
	read -r -p "Select (1-5): " selectXrayType
	if [[ "${selectXrayType}" == "1" ]]; then
		updateXray
	elif [[ "${selectXrayType}" == "2" ]]; then
		echoContent yellow "\n1. Due to frequent Xray-core updates, only previous 2 versions can be re-installed"
		echoContent yellow "2. There is no guarantee on the previous version to work normally"
		echoContent yellow "3. If the previous version does not support current config, XRay might not work"
		echoContent skyBlue "------------------------Version-------------------------------"
		curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name | head -2 | awk '{print ""NR""":"$0}'
		echoContent skyBlue "--------------------------------------------------------------"
		read -r -p "Please enter Xray-core previous version: " selectXrayVersionType
		version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[].tag_name | head -2 | awk '{print ""NR""":"$0}' | grep "${selectXrayVersionType}:" | awk -F "[:]" '{print $2}')
		if [[ -n "${version}" ]]; then
			updateXray "${version}"
		else
			echoContent red "\n ---> Input is incorrect, please try again"
			xrayVersionManageMenu 1
		fi
	elif [[ "${selectXrayType}" == "3" ]]; then
		handleXray stop
	elif [[ "${selectXrayType}" == "4" ]]; then
		handleXray start
	elif [[ "${selectXrayType}" == "5" ]]; then
		reloadCore
	fi

}
# Update V2Ray
updateV2Ray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[0]|select (.prerelease==false)|.tag_name')
		fi
		# Use default version
		if [[ -n "${v2rayCoreVersion}" ]]; then
			version=${v2rayCoreVersion}
		fi
		echoContent green " ---> v2ray-core version: ${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/v2ray/ "https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip"
		else
			wget -c -P "/etc/v2ray-agent/v2ray/ https://github.com/v2fly/v2ray-core/releases/download/${version}/${v2rayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip" -d /etc/v2ray-agent/v2ray >/dev/null
		rm -rf "/etc/v2ray-agent/v2ray/${v2rayCoreCPUVendor}.zip"
		handleV2Ray stop
		handleV2Ray start
	else
		echoContent green " ---> Current v2ray-core version: $(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/v2fly/v2ray-core/releases | jq -r '.[0]|select (.prerelease==false)|.tag_name')
		fi

		if [[ -n "${v2rayCoreVersion}" ]]; then
			version=${v2rayCoreVersion}
		fi
		if [[ -n "$1" ]]; then
			read -r -p "Previous v2ray-core version ${version}, continue installation? [y/n]:" rollbackV2RayStatus
			if [[ "${rollbackV2RayStatus}" == "y" ]]; then
				if [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
					echoContent green " ---> Current v2ray-core version: $(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)"
				elif [[ "${coreInstallType}" == "1" ]]; then
					echoContent green " ---> Curent xray-core version: $(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"
				fi

				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray "${version}"
			else
				echoContent green " ---> Aborted current process (Downgrade)"
			fi
		elif [[ "${version}" == "v$(/etc/v2ray-agent/v2ray/v2ray --version | awk '{print $2}' | head -1)" ]]; then
			read -r -p "Current version detected, do you want to re-install instead? [y/n]:" reInstallV2RayStatus
			if [[ "${reInstallV2RayStatus}" == "y" ]]; then
				handleV2Ray stop
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				echoContent green " ---> Re-install aborted"
			fi
		else
			read -r -p "Latest version: ${version}, update to the latest version? [y/n]:" installV2RayStatus
			if [[ "${installV2RayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/v2ray/v2ray
				rm -f /etc/v2ray-agent/v2ray/v2ctl
				updateV2Ray
			else
				echoContent green " ---> Update aborted"
			fi

		fi
	fi
}

# Update Xray
updateXray() {
	readInstallType
	if [[ -z "${coreInstallType}" ]]; then
		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[0].tag_name)
		fi

		echoContent green " ---> Xray-core version: ${version}"

		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip"
		else
			wget -c -P /etc/v2ray-agent/xray/ "https://github.com/XTLS/Xray-core/releases/download/${version}/${xrayCoreCPUVendor}.zip" >/dev/null 2>&1
		fi

		unzip -o "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip" -d /etc/v2ray-agent/xray >/dev/null
		rm -rf "/etc/v2ray-agent/xray/${xrayCoreCPUVendor}.zip"
		chmod 655 /etc/v2ray-agent/xray/xray
		handleXray stop
		handleXray start
	else
		echoContent green " ---> Current Xray-core version: $(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

		if [[ -n "$1" ]]; then
			version=$1
		else
			version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | jq -r .[0].tag_name)
		fi

		if [[ -n "$1" ]]; then
			read -r -p "Previous Xray version ${version}, continue installation? [y/n]:" rollbackXrayStatus
			if [[ "${rollbackXrayStatus}" == "y" ]]; then
				echoContent green " ---> Current Xray-core version: $(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)"

				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				updateXray "${version}"
			else
				echoContent green " ---> Aborted current process (Downgrade)"
			fi
		elif [[ "${version}" == "v$(/etc/v2ray-agent/xray/xray --version | awk '{print $2}' | head -1)" ]]; then
			read -r -p "Current version detected, do you want to re-install instead? [y/n]:" reInstallXrayStatus
			if [[ "${reInstallXrayStatus}" == "y" ]]; then
				handleXray stop
				rm -f /etc/v2ray-agent/xray/xray
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				echoContent green " ---> Re-install aborted"
			fi
		else
			read -r -p "Latest Version: ${version}, update to the latest version? [y/n]:" installXrayStatus
			if [[ "${installXrayStatus}" == "y" ]]; then
				rm -f /etc/v2ray-agent/xray/xray
				updateXray
			else
				echoContent green " ---> Update Aborted"
			fi

		fi
	fi
}

# Verify Service Availability
checkGFWStatue() {
	readInstallType
	echoContent skyBlue "\n $1/${totalProgress} : Verifying Service Startup"
	if [[ "${coreInstallType}" == "1" ]] && [[ -n $(pgrep -f xray/xray) ]]; then
		echoContent green " ---> Xray Service Started Succesfully"
	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]] && [[ -n $(pgrep -f v2ray/v2ray) ]]; then
		echoContent green " ---> V2Ray Service Started Succesfully"
	else
		echoContent red " ---> Service failed to Start, please check for error log in the terminal"
		exit 0
	fi

}

# Install V2Ray service
installV2RayService() {
	echoContent skyBlue "\n $1/${totalProgress} : Configuring V2Ray to Start Automatically on Boot"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/v2ray.service
		touch /etc/systemd/system/v2ray.service
		execStart='/etc/v2ray-agent/v2ray/v2ray -confdir /etc/v2ray-agent/v2ray/conf'
		cat <<EOF >/etc/systemd/system/v2ray.service
[Unit]
Description=V2Ray - A unified platform for anti-censorship (kashifabs.ml)
Documentation=https://v2ray.com https://guide.v2fly.org
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable v2ray.service
		echoContent green " ---> V2Ray Boot Configured"
	fi
}

# Install Xray Service
installXrayService() {
	echoContent skyBlue "\n $1/${totalProgress} : Configuring XRay to Start Automatically on Boot"
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]]; then
		rm -rf /etc/systemd/system/xray.service
		touch /etc/systemd/system/xray.service
		execStart='/etc/v2ray-agent/xray/xray run -confdir /etc/v2ray-agent/xray/conf'
		cat <<EOF >/etc/systemd/system/xray.service
[Unit]
Description=Xray - A unified platform for anti-censorship (kashifabs.ml)
# Documentation=https://v2ray.com https://guide.v2fly.org
After=network.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=yes
ExecStart=${execStart}
Restart=on-failure
RestartPreventExitStatus=23


[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable xray.service
		echoContent green " ---> XRay Boot Configured"
	fi
}

# V2Ray Operation
handleV2Ray() {
	# shellcheck disable=SC2010
	if find /bin /usr/bin | grep -q systemctl && ls /etc/systemd/system/ | grep -q v2ray.service; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "start" ]]; then
			systemctl start v2ray.service
		elif [[ -n $(pgrep -f "v2ray/v2ray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop v2ray.service
		fi
	fi
	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green " ---> V2Ray Started Successfully"
		else
			echoContent red "V2Ray Failed to Start"
			echoContent red "Please manually execute【/etc/v2ray-agent/v2ray/v2ray -confdir /etc/v2ray-agent/v2ray/conf】to view error log"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "v2ray/v2ray") ]]; then
			echoContent green " ---> V2Ray Stopped Successfully"
		else
			echoContent red "V2Ray Failed to Stop"
			echoContent red "Please manually execute【ps -ef|grep -v grep|grep v2ray|awk '{print \$2}'|xargs kill -9】to stop"
			exit 0
		fi
	fi
}
# Xray Operation
handleXray() {
	if [[ -n $(find /bin /usr/bin -name "systemctl") ]] && [[ -n $(find /etc/systemd/system/ -name "xray.service") ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]] && [[ "$1" == "start" ]]; then
			systemctl start xray.service
		elif [[ -n $(pgrep -f "xray/xray") ]] && [[ "$1" == "stop" ]]; then
			systemctl stop xray.service
		fi
	fi

	sleep 0.8

	if [[ "$1" == "start" ]]; then
		if [[ -n $(pgrep -f "xray/xray") ]]; then
			echoContent green " ---> Xray Started Successfully"
		else
			echoContent red "Xray Failed to Start"
			echoContent red "Please manually execute【/etc/v2ray-agent/xray/xray -confdir /etc/v2ray-agent/xray/conf】, to view error log"
			exit 0
		fi
	elif [[ "$1" == "stop" ]]; then
		if [[ -z $(pgrep -f "xray/xray") ]]; then
			echoContent green " ---> Xray Stopped Successfully"
		else
			echoContent red "Xray Failed to Stop"
			echoContent red "Please manually execute【ps -ef|grep -v grep|grep xray|awk '{print \$2}'|xargs kill -9】to stop"
			exit 0
		fi
	fi
}

# Initialize V2Ray Config file
initV2RayConfig() {
	echoContent skyBlue "\n $2/${totalProgress} : Initialize V2Ray Configuration"
	echo

	read -r -p "Customize UUID ? [y/n]:" customUUIDStatus
	echo
	if [[ "${customUUIDStatus}" == "y" ]]; then
		read -r -p "Please enter a valid UUID:" currentCustomUUID
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		fi
	fi

	if [[ -n "${currentUUID}" && -z "${uuid}" ]]; then
		read -r -p "Use previous UUID from installation ? [y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then
			uuid=${currentUUID}
		else
			uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
		fi
	elif [[ -z "${uuid}" ]]; then
		uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	fi

	if [[ -z "${uuid}" ]]; then
		echoContent red "\n ---> UUID Error, Regenerating.."
		uuid=$(/etc/v2ray-agent/v2ray/v2ctl uuid)
	fi

	rm -rf /etc/v2ray-agent/v2ray/conf/*
	rm -rf /etc/v2ray-agent/v2ray/config_full.json

	# log
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/v2ray/error.log",
    "loglevel": "warning"
  }
}
EOF
	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

	else
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	fi

	# dns
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF

	# VLESS_TCP_TLS
	# Revert NGINX
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

	# trojan
	if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then
		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}_trojan_tcp"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
	fi

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
  "port": 31297,
  "listen": "127.0.0.1",
  "protocol": "vless",
  "tag":"VLESSWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "email": "${domain}_VLESS_WS"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}ws"
    }
  }
}
]
}
EOF
	fi

	# trojan_grpc
	if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
		if ! echo "${selectCustomInstallType}" | grep -q 5 && [[ -n ${selectCustomInstallType} ]]; then
			fallbacksList=${fallbacksList//31302/31304}
		fi

		cat <<EOF >/etc/v2ray-agent/v2ray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "${domain}_trojan_gRPC"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
	fi

	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}_vmess_ws"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
	fi

	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
		cat <<EOF >/etc/v2ray-agent/v2ray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
                    "email": "${domain}_VLESS_gRPC"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
	fi

	# VLESS_TCP
	cat <<EOF >/etc/v2ray-agent/v2ray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": 443,
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "email": "${domain}_VLESS_TLS-direct_TCP"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "tls",
    "tlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF

}

# Initialize XRay Trojan XTLS Configuration File
initXrayFrontingConfig() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Config File Not Installed, Please Re-install from Script"
		menu
		exit 0
	fi
	if [[ "${coreInstallType}" != "1" ]]; then
		echoContent red " ---> Available Types Not Installed"
	fi
	local xtlsType=
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		xtlsType=VLESS
	else
		xtlsType=Trojan

	fi

	echoContent skyBlue "\nFeatures 1/${totalProgress} : Front switch to ${xtlsType}"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "Replacing prefix with ${xtlsType}"
	echoContent yellow "If included Trojan, account viewing will include 2 nodes of Trojan (XTLS unavailable)"
	echoContent yellow "Execute Again to switch from previous config\n"

	echoContent yellow "1. Switch to ${xtlsType}"
	echoContent red "=============================================================="
	read -r -p "Please choose (1):" selectType
	if [[ "${selectType}" == "1" ]]; then

		if [[ "${xtlsType}" == "Trojan" ]]; then

			local VLESSConfig
			VLESSConfig=$(cat ${configPath}${frontingType}.json)
			VLESSConfig=${VLESSConfig//"id"/"password"}
			VLESSConfig=${VLESSConfig//VLESSTCP/TrojanTCPXTLS}
			VLESSConfig=${VLESSConfig//VLESS/Trojan}
			VLESSConfig=${VLESSConfig//"vless"/"trojan"}
			VLESSConfig=${VLESSConfig//"id"/"password"}

			echo "${VLESSConfig}" | jq . >${configPath}02_trojan_TCP_inbounds.json
			rm ${configPath}${frontingType}.json
		elif [[ "${xtlsType}" == "VLESS" ]]; then

			local VLESSConfig
			VLESSConfig=$(cat ${configPath}02_trojan_TCP_inbounds.json)
			VLESSConfig=${VLESSConfig//"password"/"id"}
			VLESSConfig=${VLESSConfig//TrojanTCPXTLS/VLESSTCP}
			VLESSConfig=${VLESSConfig//Trojan/VLESS}
			VLESSConfig=${VLESSConfig//"trojan"/"vless"}
			VLESSConfig=${VLESSConfig//"password"/"id"}

			echo "${VLESSConfig}" | jq . >${configPath}02_VLESS_TCP_inbounds.json
			rm ${configPath}02_trojan_TCP_inbounds.json
		fi
		reloadCore
	fi

	exit 0
}

# Initialize XRay Configuration File
initXrayConfig() {
	echoContent skyBlue "\n $2/${totalProgress} : Initializing XRay Configuration"
	echo
	local uuid=
	if [[ -n "${currentUUID}" ]]; then
		read -r -p "Do you want to use previous UUID from installation? [y/n]:" historyUUIDStatus
		if [[ "${historyUUIDStatus}" == "y" ]]; then
			uuid=${currentUUID}
			echoContent green "\n ---> Previous UUID used successfully"
		else
			uuid=$(/etc/v2ray-agent/xray/xray uuid)
		fi
	fi

	if [[ -z "${uuid}" ]]; then
		echoContent yellow "Please enter custom UUID [must be valid], press [enter] random UUID"
		read -r -p 'UUID:' customUUID

		if [[ -n ${customUUID} ]]; then
			uuid=${customUUID}
		else
			uuid=$(/etc/v2ray-agent/xray/xray uuid)
		fi

	fi

	if [[ -z "${uuid}" ]]; then
		echoContent red "\n ---> UUID Error, Regenerating"
		uuid=$(/etc/v2ray-agent/xray/xray uuid)
	fi

	echoContent yellow "\n ${uuid}"

	rm -rf /etc/v2ray-agent/xray/conf/*

	# log
	cat <<EOF >/etc/v2ray-agent/xray/conf/00_log.json
{
  "log": {
    "error": "/etc/v2ray-agent/xray/error.log",
    "loglevel": "warning"
  }
}
EOF

	# outbounds
	if [[ -n "${pingIPv6}" ]]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv6_outbounds.json
{
    "outbounds": [
        {
          "protocol": "freedom",
          "settings": {},
          "tag": "direct"
        }
    ]
}
EOF

	else
		cat <<EOF >/etc/v2ray-agent/xray/conf/10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF
	fi

	# dns
	cat <<EOF >/etc/v2ray-agent/xray/conf/11_dns.json
{
    "dns": {
        "servers": [
          "localhost"
        ]
  }
}
EOF

	# VLESS_TCP_TLS/XTLS
	# Revert NGINX
	local fallbacksList='{"dest":31300,"xver":0},{"alpn":"h2","dest":31302,"xver":0}'

	# trojan
	if echo "${selectCustomInstallType}" | grep -q 4 || [[ "$1" == "all" ]]; then
		fallbacksList='{"dest":31296,"xver":1},{"alpn":"h2","dest":31302,"xver":0}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_TCP_inbounds.json
{
"inbounds":[
	{
	  "port": 31296,
	  "listen": "127.0.0.1",
	  "protocol": "trojan",
	  "tag":"trojanTCP",
	  "settings": {
		"clients": [
		  {
			"password": "${uuid}",
			"email": "${domain}_trojan_tcp"
		  }
		],
		"fallbacks":[
			{"dest":"31300"}
		]
	  },
	  "streamSettings": {
		"network": "tcp",
		"security": "none",
		"tcpSettings": {
			"acceptProxyProtocol": true
		}
	  }
	}
	]
}
EOF
	fi

	# VLESS_WS_TLS
	if echo "${selectCustomInstallType}" | grep -q 1 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'ws","dest":31297,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/03_VLESS_WS_inbounds.json
{
"inbounds":[
    {
  "port": 31297,
  "listen": "127.0.0.1",
  "protocol": "vless",
  "tag":"VLESSWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "email": "${domain}_VLESS_WS"
      }
    ],
    "decryption": "none"
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}ws"
    }
  }
}
]
}
EOF
	fi

	# trojan_grpc
	if echo "${selectCustomInstallType}" | grep -q 2 || [[ "$1" == "all" ]]; then
		if ! echo "${selectCustomInstallType}" | grep -q 5 && [[ -n ${selectCustomInstallType} ]]; then
			fallbacksList=${fallbacksList//31302/31304}
		fi

		cat <<EOF >/etc/v2ray-agent/xray/conf/04_trojan_gRPC_inbounds.json
{
    "inbounds": [
        {
            "port": 31304,
            "listen": "127.0.0.1",
            "protocol": "trojan",
            "tag": "trojangRPCTCP",
            "settings": {
                "clients": [
                    {
                        "password": "${uuid}",
                        "email": "${domain}_trojan_gRPC"
                    }
                ],
                "fallbacks": [
                    {
                        "dest": "31300"
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "${customPath}trojangrpc"
                }
            }
        }
    ]
}
EOF
	fi

	# VMess_WS
	if echo "${selectCustomInstallType}" | grep -q 3 || [[ "$1" == "all" ]]; then
		fallbacksList=${fallbacksList}',{"path":"/'${customPath}'vws","dest":31299,"xver":1}'
		cat <<EOF >/etc/v2ray-agent/xray/conf/05_VMess_WS_inbounds.json
{
"inbounds":[
{
  "listen": "127.0.0.1",
  "port": 31299,
  "protocol": "vmess",
  "tag":"VMessWS",
  "settings": {
    "clients": [
      {
        "id": "${uuid}",
        "alterId": 0,
        "add": "${add}",
        "email": "${domain}_vmess_ws"
      }
    ]
  },
  "streamSettings": {
    "network": "ws",
    "security": "none",
    "wsSettings": {
      "acceptProxyProtocol": true,
      "path": "/${customPath}vws"
    }
  }
}
]
}
EOF
	fi

	if echo "${selectCustomInstallType}" | grep -q 5 || [[ "$1" == "all" ]]; then
		cat <<EOF >/etc/v2ray-agent/xray/conf/06_VLESS_gRPC_inbounds.json
{
    "inbounds":[
    {
        "port": 31301,
        "listen": "127.0.0.1",
        "protocol": "vless",
        "tag":"VLESSGRPC",
        "settings": {
            "clients": [
                {
                    "id": "${uuid}",
                    "add": "${add}",
                    "email": "${domain}_VLESS_gRPC"
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": "grpc",
            "grpcSettings": {
                "serviceName": "${customPath}grpc"
            }
        }
    }
]
}
EOF
	fi

	# VLESS_TCP
	cat <<EOF >/etc/v2ray-agent/xray/conf/02_VLESS_TCP_inbounds.json
{
"inbounds":[
{
  "port": 443,
  "protocol": "vless",
  "tag":"VLESSTCP",
  "settings": {
    "clients": [
     {
        "id": "${uuid}",
        "add":"${add}",
        "flow":"xtls-rprx-direct",
        "email": "${domain}_VLESS_XTLS/TLS-direct_TCP"
      }
    ],
    "decryption": "none",
    "fallbacks": [
        ${fallbacksList}
    ]
  },
  "streamSettings": {
    "network": "tcp",
    "security": "xtls",
    "xtlsSettings": {
      "minVersion": "1.2",
      "alpn": [
        "http/1.1",
        "h2"
      ],
      "certificates": [
        {
          "certificateFile": "/etc/v2ray-agent/tls/${domain}.crt",
          "keyFile": "/etc/v2ray-agent/tls/${domain}.key",
          "ocspStapling": 3600,
          "usage":"encipherment"
        }
      ]
    }
  }
}
]
}
EOF
}

# Initialize Trojan-GO Configuration
initTrojanGoConfig() {

	echoContent skyBlue "\n $1/${totalProgress} : Initializing Trojan-GO Configuration"
	cat <<EOF >/etc/v2ray-agent/trojan/config_full.json
{
    "run_type": "server",
    "local_addr": "127.0.0.1",
    "local_port": 31296,
    "remote_addr": "127.0.0.1",
    "remote_port": 31300,
    "disable_http_check":true,
    "log_level":3,
    "log_file":"/etc/v2ray-agent/trojan/trojan.log",
    "password": [
        "${uuid}"
    ],
    "dns":[
        "localhost"
    ],
    "transport_plugin":{
        "enabled":true,
        "type":"plaintext"
    },
    "websocket": {
        "enabled": true,
        "path": "/${customPath}tws",
        "host": "${domain}",
        "add":"${add}"
    },
    "router": {
        "enabled": false
    }
}
EOF
}

# Custom CDN IP
customCDNIP() {
	echoContent skyBlue "\n $1/${totalProgress} : Add Cloudflare Custom CNAME"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions"
	echoContent red "\nIf you don't know what are you doing, please don't use this method"
	echoContent yellow "\n 1. Mobile:104.16.123.96"
	echoContent yellow " 2. Link:www.cloudflare.com"
	echoContent yellow " 3. Telecommunication:www.digitalocean.com"
	echoContent skyBlue "----------------------------"
	read -r -p "Please select and press [enter] (leave blank if none):" selectCloudflareType
	case ${selectCloudflareType} in
	1)
		add="104.16.123.96"
		;;
	2)
		add="www.cloudflare.com"
		;;
	3)
		add="www.digitalocean.com"
		;;
	*)
		add="${domain}"
		echoContent yellow "\n ---> Do Not Use ${domain}"
		;;
	esac
}
# Universal
defaultBase64Code() {
	local type=$1
	local email=$2
	local id=$3
	local hostPort=$4
	local host=
	local port=
	if echo "${hostPort}" | grep -q ":"; then
		host=$(echo "${hostPort}" | awk -F "[:]" '{print $1}')
		port=$(echo "${hostPort}" | awk -F "[:]" '{print $2}')
	else
		host=${hostPort}
		port=443
	fi

	local path=$5
	local add=$6

	local subAccount
	subAccount=${currentHost}_$(echo "${id}_currentHost" | md5sum | awk '{print $1}')

	if [[ "${type}" == "vlesstcp" ]]; then

		if [[ "${coreInstallType}" == "1" ]] && echo "${currentInstallProtocolType}" | grep -q 0; then
			echoContent yellow " ---> Common Format (VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}\n"

			echoContent yellow " ---> FormatPlaintext (VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "Agreement Type: VLESS, Hostname: ${host}, Port: ${port}, User ID: ${id}, Secured: XTLS, Transfer Method: TCP, flow: xtls-rprx-direct, Account Name:${email}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}
EOF
			echoContent yellow " ---> QR Code VLESS(VLESS+TCP+TLS/xtls-rprx-direct)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-direct%23${email}\n"

			echoContent skyBlue "----------------------------------------------------------------------------------"

			echoContent yellow " ---> Common Format (VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email/direct/splice}\n"

			echoContent yellow " ---> FormatPlaintext (VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    Agreement Type: VLESS, Hostname: ${host}, Port: ${port}, User ID: ${id}, Secured: XTLS, Transfer Method: TCP, flow:xtls-rprx-splice, Account Name: ${email/direct/splice}\n"
			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email/direct/splice}
EOF
			echoContent yellow " ---> QR Code VLESS(VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-splice%23${email/direct/splice}\n"

		elif [[ "${coreInstallType}" == 2 || "${coreInstallType}" == "3" ]]; then
			echoContent yellow " ---> Common Format (VLESS+TCP+TLS)"
			echoContent green "    vless://${id}@${host}:${port}?security=tls&encryption=none&host=${host}&headerType=none&type=tcp#${email}\n"

			echoContent yellow " ---> FormatPlaintext (VLESS+TCP+TLS/xtls-rprx-splice)"
			echoContent green "    Agreement Type: VLESS, Hostname: ${host}, Port: ${port}, User ID: ${id}, Secured: tls, Transfer Method: tcp, Account Name: ${email/direct/splice}\n"

			cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${host}:${port}?security=tls&encryption=none&host=${host}&headerType=none&type=tcp#${email}
EOF
			echoContent yellow " ---> QR Code VLESS(VLESS+TCP+TLS)"
			echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3a%2f%2f${id}%40${host}%3a${port}%3fsecurity%3dtls%26encryption%3dnone%26host%3d${host}%26headerType%3dnone%26type%3dtcp%23${email}\n"
		fi

	elif [[ "${type}" == "trojanTCPXTLS" ]]; then
		echoContent yellow " ---> Common Format (Trojan+TCP+TLS/xtls-rprx-direct)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}\n"

		echoContent yellow " ---> FormatPlaintext (Trojan+TCP+TLS/xtls-rprx-direct)"
		echoContent green "Agreement Type: Trojan, Hostname: ${host}, Port: ${port}, User ID: ${id}, Secured: xtls, Transfer Method: tcp, flow:xtls-rprx-direct, Account Name: ${email}\n"
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-direct#${email}
EOF
		echoContent yellow " ---> QR Code Trojan(Trojan+TCP+TLS/xtls-rprx-direct)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-direct%23${email}\n"

		echoContent skyBlue "----------------------------------------------------------------------------------"

		echoContent yellow " ---> Common Format (Trojan+TCP+TLS/xtls-rprx-splice)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email/direct/splice}\n"

		echoContent yellow " ---> FormatPlaintext (Trojan+TCP+TLS/xtls-rprx-splice)"
		echoContent green "    Agreement Type: VLESS, Hostname: ${host}, Port: ${port}, User ID: ${id}, Secured: xtls, Transfer Method: tcp, flow:xtls-rprx-splice, Account Name: ${email/direct/splice}\n"
		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&security=xtls&type=tcp&host=${host}&headerType=none&sni=${host}&flow=xtls-rprx-splice#${email/direct/splice}
EOF
		echoContent yellow " ---> QR Code Trojan(Trojan+TCP+TLS/xtls-rprx-splice)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3A%2F%2F${id}%40${host}%3A${port}%3Fencryption%3Dnone%26security%3Dxtls%26type%3Dtcp%26${host}%3D${host}%26headerType%3Dnone%26sni%3D${host}%26flow%3Dxtls-rprx-splice%23${email/direct/splice}\n"

	elif [[ "${type}" == "vmessws" ]]; then
		qrCodeBase64Default=$(echo -n "{\"port\": ${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${host}\",\"type\":\"none\",\"path\":\"/${path}\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${host}\",\"sni\":\"${host}\"}" | base64 -w 0)
		qrCodeBase64Default="${qrCodeBase64Default// /}"

		echoContent yellow " ---> Current json(VMess+WS+TLS)"
		echoContent green "    {\"port\": ${port},\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${host}\",\"type\":\"none\",\"path\":\"${path}\",\"net\":\"ws\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"none\",\"peer\":\"${host}\",\"sni\":\"${host}\"}\n"
		echoContent yellow " ---> Current vmess(VMess+WS+TLS) Link"
		echoContent green "    vmess://${qrCodeBase64Default}\n"
		echoContent yellow " ---> QR Code vmess(VMess+WS+TLS)"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

	elif [[ "${type}" == "vmesstcp" ]]; then

		echoContent red "path:${path}"
		qrCodeBase64Default=$(echo -n "{\"add\":\"${add}\",\"aid\":0,\"host\":\"${host}\",\"id\":\"${id}\",\"net\":\"tcp\",\"path\":\"${path}\",\"port\": ${port},\"ps\":\"${email}\",\"scy\":\"none\",\"sni\":\"${host}\",\"tls\":\"tls\",\"v\":2,\"type\":\"http\",\"allowInsecure\":0,\"peer\":\"${host}\",\"obfs\":\"http\",\"obfsParam\":\"${host}\"}" | base64)
		qrCodeBase64Default="${qrCodeBase64Default// /}"

		echoContent yellow " ---> Current json(VMess+TCP+TLS)"
		echoContent green "    {\"port\":'${port}',\"ps\":\"${email}\",\"tls\":\"tls\",\"id\":\"${id}\",\"aid\":0,\"v\":2,\"host\":\"${host}\",\"type\":\"http\",\"path\":\"${path}\",\"net\":\"http\",\"add\":\"${add}\",\"allowInsecure\":0,\"method\":\"post\",\"peer\":\"${host}\",\"obfs\":\"http\",\"obfsParam\":\"${host}\"}\n"
		echoContent yellow " ---> Current vmess(VMess+TCP+TLS) Link"
		echoContent green "    vmess://${qrCodeBase64Default}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vmess://${qrCodeBase64Default}
EOF
		echoContent yellow " ---> QR Code vmess(VMess+TCP+TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vmess://${qrCodeBase64Default}\n"

	elif [[ "${type}" == "vlessws" ]]; then

		echoContent yellow " ---> Common Format (VLESS+WS+TLS)"
		echoContent green "    vless://${id}@${add}: ${port}?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2f${path}#${email}\n"

		echoContent yellow " ---> FormatPlaintext (VLESS+WS+TLS)"
		echoContent green "    Agreement Type: VLESS, Hostname:${add}, 伪装域名/SNI: ${host}, Port: ${port}, User ID: ${id}, Secured: tls, Transfer Method: ws, 路径:/${path}, Account Name: ${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${add}: ${port}?encryption=none&security=tls&type=ws&host=${host}&sni=${host}&path=%2f${path}#${email}
EOF

		echoContent yellow " ---> QR Code VLESS(VLESS+WS+TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dws%26host%3D${host}%26sni%3D${host}%26path%3D%252f${path}%23${email}"

	elif [[ "${type}" == "vlessgrpc" ]]; then

		echoContent yellow " ---> Common Format (VLESS+gRPC+TLS)"
		echoContent green "    vless://${id}@${add}: ${port}?encryption=none&security=tls&type=grpc&host=${host}&path=${path}&serviceName=${path}&alpn=h2&sni=${host}#${email}\n"

		echoContent yellow " ---> FormatPlaintext (VLESS+gRPC+TLS)"
		echoContent green "    Agreement Type: VLESS, Hostname:${add}, 伪装域名/SNI: ${host}, Port: ${port}, User ID: ${id}, Secured: tls, Transfer Method: gRPC, alpn:h2, serviceName:${path}, Account Name: ${email}\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
vless://${id}@${add}: ${port}?encryption=none&security=tls&type=grpc&host=${host}&path=${path}&serviceName=${path}&alpn=h2&sni=${host}#${email}
EOF
		echoContent yellow " ---> QR Code VLESS(VLESS+gRPC+TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=vless%3A%2F%2F${id}%40${add}%3A${port}%3Fencryption%3Dnone%26security%3Dtls%26type%3Dgrpc%26host%3D${host}%26serviceName%3D${path}%26path%3D${path}%26sni%3D${host}%26alpn%3Dh2%23${email}"

	elif [[ "${type}" == "trojan" ]]; then
		# URLEncode
		echoContent yellow " ---> Trojan(TLS)"
		echoContent green "    trojan://${id}@${host}:${port}?peer=${host}&sni=${host}&alpn=http1.1#${host}_Trojan\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?peer=${host}&sni=${host}&alpn=http1.1#${host}_Trojan
EOF
		echoContent yellow " ---> QR Code Trojan(TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${host}%3a${port}%3fpeer%3d${host}%26sni%3d${host}%26alpn%3Dhttp1.1%23${host}_Trojan\n"

	elif [[ "${type}" == "trojangrpc" ]]; then
		# URLEncode

		echoContent yellow " ---> Trojan gRPC(TLS)"
		echoContent green "    trojan://${id}@${host}:${port}?encryption=none&peer=${host}&security=tls&type=grpc&sni=${host}&alpn=h2&path=${path}&serviceName=${path}#${host}_Trojan_gRPC\n"

		cat <<EOF >>"/etc/v2ray-agent/subscribe_tmp/${subAccount}"
trojan://${id}@${host}:${port}?encryption=none&peer=${host}&security=tls&type=grpc&sni=${host}&alpn=h2&path=${path}&serviceName=${path}#${host}_Trojan_gRPC
EOF
		echoContent yellow " ---> QR Code Trojan gRPC(TLS)"
		echoContent green "    https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=trojan%3a%2f%2f${id}%40${host}%3a${port}%3Fencryption%3Dnone%26security%3Dtls%26peer%3d${host}%26type%3Dgrpc%26sni%3d${host}%26path%3D${path}%26alpn%3D=h2%26serviceName%3D${path}%23${host}_Trojan_gRPC\n"
	fi

}

# Show Account
showAccounts() {
	readInstallType
	readInstallProtocolType
	readConfigHostPathUUID
	echoContent skyBlue "\n $1/${totalProgress} : Showing Accounts"
	local show
	# VLESS TCP
	if [[ -n "${configPath}" ]]; then
		show=1
		if echo "${currentInstallProtocolType}" | grep -q trojan; then
			echoContent skyBlue "===================== Trojan TCP TLS/XTLS-direct/XTLS-splice ======================\n"
			jq .inbounds[0].settings.clients ${configPath}02_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> Account Number: $(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .password)"
				echo
				defaultBase64Code trojanTCPXTLS "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .password)" "${currentHost}:${currentPort}" "${currentHost}"
			done

		else
			echoContent skyBlue "===================== VLESS TCP TLS/XTLS-direct/XTLS-splice ======================\n"
			jq .inbounds[0].settings.clients ${configPath}02_VLESS_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> Account Number: $(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vlesstcp "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${currentHost}"
			done
		fi

		# VLESS WS
		if echo ${currentInstallProtocolType} | grep -q 1; then
			echoContent skyBlue "\n================================ VLESS WS TLS CDN ================================\n"

			jq .inbounds[0].settings.clients ${configPath}03_VLESS_WS_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> Account Number: $(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				local path="${currentPath}ws"
				#				if [[ ${coreInstallType} == "1" ]]; then
				#					echoContent yellow "Xray's 0-RTT path will be behind, it is not compatible with v2ray-based clients, please delete it manually and use it\n"
				#					path="${currentPath}ws"
				#				fi
				defaultBase64Code vlessws "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${path}" "${currentAdd}"
			done
		fi

		# VMess WS
		if echo ${currentInstallProtocolType} | grep -q 3; then
			echoContent skyBlue "\n================================ VMess WS TLS CDN ================================\n"
			local path="${currentPath}vws"
			if [[ ${coreInstallType} == "1" ]]; then
				path="${currentPath}vws"
			fi
			jq .inbounds[0].settings.clients ${configPath}05_VMess_WS_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> Account Number: $(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vmessws "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${path}" "${currentAdd}"
			done
		fi

		# VLESS grpc
		if echo ${currentInstallProtocolType} | grep -q 5; then
			echoContent skyBlue "\n=============================== VLESS gRPC TLS CDN ===============================\n"
			echoContent red "\n --->gRPC (Beta) is in Testing Stage and are not compatible for use with current client. Please ignore if unusable"
			local serviceName
			serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}06_VLESS_gRPC_inbounds.json)
			jq .inbounds[0].settings.clients ${configPath}06_VLESS_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
				echoContent skyBlue "\n ---> Account Number: $(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .id)"
				echo
				defaultBase64Code vlessgrpc "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .id)" "${currentHost}:${currentPort}" "${serviceName}" "${currentAdd}"
			done
		fi
	fi

	# trojan tcp
	if echo ${currentInstallProtocolType} | grep -q 4; then
		echoContent skyBlue "\n==================================  Trojan TLS  ==================================\n"
		jq .inbounds[0].settings.clients ${configPath}04_trojan_TCP_inbounds.json | jq -c '.[]' | while read -r user; do
			echoContent skyBlue "\n ---> Account Number: $(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .password)"
			echo
			defaultBase64Code trojan trojan "$(echo "${user}" | jq -r .password)" "${currentHost}"
		done
	fi

	if echo ${currentInstallProtocolType} | grep -q 2; then
		echoContent skyBlue "\n================================  Trojan gRPC TLS  ================================\n"
		echoContent red "\n --->gRPC (Beta) is in Testing Stage and are not compatible for use with current client. Please ignore if unusable"
		local serviceName=
		serviceName=$(jq -r .inbounds[0].streamSettings.grpcSettings.serviceName ${configPath}04_trojan_gRPC_inbounds.json)
		jq .inbounds[0].settings.clients ${configPath}04_trojan_gRPC_inbounds.json | jq -c '.[]' | while read -r user; do
			echoContent skyBlue "\n ---> Account Number: $(echo "${user}" | jq -r .email)_$(echo "${user}" | jq -r .password)"
			echo
			defaultBase64Code trojangrpc "$(echo "${user}" | jq -r .email)" "$(echo "${user}" | jq -r .password)" "${currentHost}:${currentPort}" "${serviceName}" "${currentAdd}"
		done
	fi

	if [[ -z ${show} ]]; then
		echoContent red " ---> Not Installed"
	fi
}

# NGINX Blog Website Update
updateNginxBlog() {
	echoContent skyBlue "\n $1/${totalProgress} : Changing NGINX Camouflage Website"
	echoContent red "=============================================================="
	echoContent yellow "# To customize, please manually copy template file to /usr/share/nginx/html \n"
	echoContent yellow "1. Guide Page"
	echoContent yellow "2. Game site"
	echoContent yellow "3. Personal Blog 01"
	echoContent yellow "4. Enterprise Station"
	echoContent yellow "5. Unlock Encrypted Music File Templates"
	echoContent yellow "6. mikutap"
	echoContent yellow "7. Enterprise Station 02"
	echoContent yellow "8. Personal Blog 02"
	echoContent yellow "9. 404 Redirect baidu"
	echoContent red "=============================================================="
	read -r -p "Please select (1-9):" selectInstallNginxBlogType

	if [[ "${selectInstallNginxBlogType}" =~ ^[1-9]$ ]]; then
		#		rm -rf /usr/share/nginx/html
		rm -rf /usr/share/nginx/*
		if wget --help | grep -q show-progress; then
			wget -c -q --show-progress -P /usr/share/nginx "https://raw.githubusercontent.com/kashimaruu/multi-script/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip" >/dev/null
		else
			wget -c -P /usr/share/nginx "https://raw.githubusercontent.com/kashimaruu/multi-script/master/fodder/blog/unable/html${selectInstallNginxBlogType}.zip" >/dev/null
		fi

		unzip -o "/usr/share/nginx/html${selectInstallNginxBlogType}.zip" -d /usr/share/nginx/html >/dev/null
		rm -f "/usr/share/nginx/html${selectInstallNginxBlogType}.zip*"
		echoContent green " ---> Successfully replaced NGINX Website"
	else
		echoContent red " ---> Invalid input, Please select again"
		updateNginxBlog
	fi
}

# Add Core Port
addCorePort() {
	echoContent skyBlue "\nFeatures 1/${totalProgress} : Adding New Port"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautionsn"
	echoContent yellow "Support Batch Addition"
	echoContent yellow "Does not affect use of Port 443"
	echoContent yellow "When viewing Account Number, Default Port displayed is 443"
	echoContent yellow "Special Characters are invalid, example below"
	echoContent yellow "Entry example: 2053,2083,2087\n"

	echoContent yellow "1. Add Port"
	echoContent yellow "2. Remove Port"
	echoContent red "=============================================================="
	read -r -p "Please select (1-2): " selectNewPortType
	if [[ "${selectNewPortType}" == "1" ]]; then
		read -r -p "Please enter Port Number: " newPort
		if [[ -n "${newPort}" ]]; then

			while read -r port; do
				cat <<EOF >"${configPath}02_dokodemodoor_inbounds_${port}.json"
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${port},
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "tag": "dokodemo-door-newPort-${port}"
    }
  ]
}
EOF
			done < <(echo "${newPort}" | tr ',' '\n')

			echoContent green " ---> Port ${newPort} added successfully"
			reloadCore
		fi
	elif [[ "${selectNewPortType}" == "2" ]]; then

		find ${configPath} -name "*dokodemodoor*" | awk -F "[c][o][n][f][/]" '{print ""NR""":"$2}'
		read -r -p "Enter Port Number to delete: " portIndex
		local dokoConfig
		dokoConfig=$(find ${configPath} -name "*dokodemodoor*" | awk -F "[c][o][n][f][/]" '{print ""NR""":"$2}' | grep "${portIndex}:")
		if [[ -n "${dokoConfig}" ]]; then
			rm "${configPath}/$(echo "${dokoConfig}" | awk -F "[:]" '{print $2}')"
			reloadCore
		else
			echoContent yellow "\n ---> Port Number Incorrect, please try again"
			addCorePort
		fi
	fi
}

# Uninstall Script
unInstall() {
	read -r -p "Are you sure you want to uninstall the script? [y/n]:" unInstallStatus
	if [[ "${unInstallStatus}" != "y" ]]; then
		echoContent green " ---> Uninstall Aborted"
		menu
		exit 0
	fi

	handleNginx stop
	if [[ -z $(pgrep -f "nginx") ]]; then
		echoContent green " ---> NGINX Stopped Successfully"
	fi

	handleV2Ray stop
	#	handleTrojanGo stop

	if [[ -f "/root/.acme.sh/acme.sh.env" ]] && grep -q 'acme.sh.env' </root/.bashrc; then
		sed -i 's/. "\/root\/.acme.sh\/acme.sh.env"//g' "$(grep '. "/root/.acme.sh/acme.sh.env"' -rl /root/.bashrc)"
	fi
	rm -rf /root/.acme.sh
	echoContent green " ---> Removed acme.sh"
	rm -rf /etc/systemd/system/v2ray.service
	echoContent green " ---> Removed V2Ray, reboot to finish"

	rm -rf /tmp/v2ray-agent-tls/*
	if [[ -d "/etc/v2ray-agent/tls" ]] && [[ -n $(find /etc/v2ray-agent/tls/ -name "*.key") ]] && [[ -n $(find /etc/v2ray-agent/tls/ -name "*.crt") ]]; then
		mv /etc/v2ray-agent/tls /tmp/v2ray-agent-tls
		if [[ -n $(find /tmp/v2ray-agent-tls -name '*.key') ]]; then
			echoContent yellow " ---> Certificate is available in [/tmp/v2ray-agent-tls] for backup"
		fi
	fi

	rm -rf /etc/v2ray-agent
	rm -rf ${nginxConfigPath}alone.conf
	rm -rf /usr/bin/vasma
	rm -rf /usr/sbin/vasma
	echoContent green " ---> Uninstall Shortcut Completed"
	echoContent green " ---> Uninstall V2Ray-Agent Script Completed"
}

# Modify V2Ray CDN Node
updateV2RayCDN() {

	# todo Refactor method
	echoContent skyBlue "\n $1/${totalProgress} : Modifying CDN Node"

	if [[ -n "${currentAdd}" ]]; then
		echoContent red "=============================================================="
		echoContent yellow "1. CNAME www.digitalocean.com"
		echoContent yellow "2. CNAME www.cloudflare.com"
		echoContent yellow "3. CNAME hostmonit.com"
		echoContent yellow "4. Manual Entry"
		echoContent red "=============================================================="
		read -r -p "Please choose: " selectCDNType
		case ${selectCDNType} in
		1)
			setDomain="www.digitalocean.com"
			;;
		2)
			setDomain="www.cloudflare.com"
			;;
		3)
			setDomain="hostmonit.com"
			;;
		4)
			read -r -p "Please enter the IP/Domain Name for CDN: " setDomain
			;;
		esac

		if [[ -n ${setDomain} ]]; then
			if [[ -n "${currentAdd}" ]]; then
				sed -i "s/\"${currentAdd}\"/\"${setDomain}\"/g" "$(grep "${currentAdd}" -rl ${configPath}${frontingType}.json)"
			fi
			if [[ $(jq -r .inbounds[0].settings.clients[0].add ${configPath}${frontingType}.json) == "${setDomain}" ]]; then
				echoContent green " ---> CDN Modified Successfully"
				reloadCore
			else
				echoContent red " ---> Failed to Modify CDN"
			fi
		fi
	else
		echoContent red " ---> Available Types Not Installed"
	fi
}

# manageUser User Management
manageUser() {
	echoContent skyBlue "\n $1/${totalProgress} : Multi-User Management"
	echoContent skyBlue "-----------------------------------------------------"
	echoContent yellow "1. Add User"
	echoContent yellow "2. Delete User"
	echoContent skyBlue "-----------------------------------------------------"
	read -r -p "Please Select (1-2): " manageUserType
	if [[ "${manageUserType}" == "1" ]]; then
		addUser
	elif [[ "${manageUserType}" == "2" ]]; then
		removeUser
	else
		echoContent red " ---> Selection Invalid"
	fi
}

# Custom UUID
customUUID() {
	read -r -p "Do you want to customize UUID? [y/n]:" customUUIDStatus
	echo
	if [[ "${customUUIDStatus}" == "y" ]]; then
		read -r -p "Please enter a valid UUID:" currentCustomUUID
		echo
		if [[ -z "${currentCustomUUID}" ]]; then
			echoContent red " ---> UUID cannot be null"
		else
			jq -r -c '.inbounds[0].settings.clients[].id' ${configPath}${frontingType}.json | while read -r line; do
				if [[ "${line}" == "${currentCustomUUID}" ]]; then
					echo >/tmp/v2ray-agent
				fi
			done
			if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
				echoContent red " ---> UUID already existed"
				rm /tmp/v2ray-agent
				exit 0
			fi
		fi
	fi
}

# Custom Email
customUserEmail() {
	read -r -p "Do you want to customize email ? [y/n]:" customEmailStatus
	echo
	if [[ "${customEmailStatus}" == "y" ]]; then
		read -r -p "Please enter a valid email:" currentCustomEmail
		echo
		if [[ -z "${currentCustomEmail}" ]]; then
			echoContent red " ---> Email cannot be null"
		else
			jq -r -c '.inbounds[0].settings.clients[].email' ${configPath}${frontingType}.json | while read -r line; do
				if [[ "${line}" == "${currentCustomEmail}" ]]; then
					echo >/tmp/v2ray-agent
				fi
			done
			if [[ -f "/tmp/v2ray-agent" && -n $(cat /tmp/v2ray-agent) ]]; then
				echoContent red " ---> Email already existed"
				rm /tmp/v2ray-agent
				exit 0
			fi
		fi
	fi
}

# Add User
addUser() {

	echoContent yellow "After new user registered, subscription must be renewed"
	read -r -p "Enter number of user(s): " userNum
	echo
	if [[ -z ${userNum} || ${userNum} -le 0 ]]; then
		echoContent red " ---> Incorrect Input, please try again"
		exit 0
	fi

	# Generating User
	if [[ "${userNum}" == "1" ]]; then
		customUUID
		customUserEmail
	fi

	while [[ ${userNum} -gt 0 ]]; do
		local users=
		((userNum--)) || true
		if [[ -n "${currentCustomUUID}" ]]; then
			uuid=${currentCustomUUID}
		else
			uuid=$(${ctlPath} uuid)
		fi

		if [[ -n "${currentCustomEmail}" ]]; then
			email=${currentCustomEmail}
		else
			email=${currentHost}_${uuid}
		fi

		# v2ray-core compatible
		users="{\"id\":\"${uuid}\",\"flow\":\"xtls-rprx-direct\",\"email\":\"${email}\",\"alterId\":0}"

		if [[ "${coreInstallType}" == "2" ]]; then
			users="{\"id\":\"${uuid}\",\"email\":\"${email}\",\"alterId\":0}"
		fi

		if echo ${currentInstallProtocolType} | grep -q 0; then
			local vlessUsers="${users//\,\"alterId\":0/}"

			local vlessTcpResult
			vlessTcpResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi

		if echo ${currentInstallProtocolType} | grep -q trojan; then
			local trojanXTLSUsers="${users//\,\"alterId\":0/}"
			trojanXTLSUsers=${trojanXTLSUsers//"id"/"password"}

			local trojanXTLSResult
			trojanXTLSResult=$(jq -r ".inbounds[0].settings.clients += [${trojanXTLSUsers}]" ${configPath}${frontingType}.json)
			echo "${trojanXTLSResult}" | jq . >${configPath}${frontingType}.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessUsers="${users//\,\"alterId\":0/}"
			vlessUsers="${vlessUsers//\"flow\":\"xtls-rprx-direct\"\,/}"
			local vlessWsResult
			vlessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vlessUsers}]" ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWsResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojangRPCUsers="${trojangRPCUsers//\,\"alterId\":0/}"
			trojangRPCUsers=${trojangRPCUsers//"id"/"password"}

			local trojangRPCResult
			trojangRPCResult=$(jq -r ".inbounds[0].settings.clients += [${trojangRPCUsers}]" ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCResult}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"

			local vmessWsResult
			vmessWsResult=$(jq -r ".inbounds[0].settings.clients += [${vmessUsers}]" ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWsResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			vlessGRPCUsers="${vlessGRPCUsers//\,\"alterId\":0/}"

			local vlessGRPCResult
			vlessGRPCResult=$(jq -r ".inbounds[0].settings.clients += [${vlessGRPCUsers}]" ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanUsers="${users//\"flow\":\"xtls-rprx-direct\"\,/}"
			trojanUsers="${trojanUsers//id/password}"
			trojanUsers="${trojanUsers//\,\"alterId\":0/}"

			local trojanTCPResult
			trojanTCPResult=$(jq -r ".inbounds[0].settings.clients += [${trojanUsers}]" ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		fi
	done

	reloadCore
	echoContent green " ---> User Added"
	manageAccount 1
}

# Remove User
removeUser() {

	if echo ${currentInstallProtocolType} | grep -q 0 || echo ${currentInstallProtocolType} | grep -q trojan; then
		jq -r -c .inbounds[0].settings.clients[].email ${configPath}${frontingType}.json | awk '{print NR""":"$0}'
		read -r -p "Please enter user ID to delete [single delete only]: " delUserIndex
		if [[ $(jq -r '.inbounds[0].settings.clients|length' ${configPath}${frontingType}.json) -lt ${delUserIndex} ]]; then
			echoContent red " ---> Invalid user input"
		else
			delUserIndex=$((delUserIndex - 1))
			local vlessTcpResult
			vlessTcpResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}${frontingType}.json)
			echo "${vlessTcpResult}" | jq . >${configPath}${frontingType}.json
		fi
	fi
	if [[ -n "${delUserIndex}" ]]; then
		if echo ${currentInstallProtocolType} | grep -q 1; then
			local vlessWSResult
			vlessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}03_VLESS_WS_inbounds.json)
			echo "${vlessWSResult}" | jq . >${configPath}03_VLESS_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 2; then
			local trojangRPCUsers
			trojangRPCUsers=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_gRPC_inbounds.json)
			echo "${trojangRPCUsers}" | jq . >${configPath}04_trojan_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 3; then
			local vmessWSResult
			vmessWSResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}05_VMess_WS_inbounds.json)
			echo "${vmessWSResult}" | jq . >${configPath}05_VMess_WS_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 5; then
			local vlessGRPCResult
			vlessGRPCResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}06_VLESS_gRPC_inbounds.json)
			echo "${vlessGRPCResult}" | jq . >${configPath}06_VLESS_gRPC_inbounds.json
		fi

		if echo ${currentInstallProtocolType} | grep -q 4; then
			local trojanTCPResult
			trojanTCPResult=$(jq -r 'del(.inbounds[0].settings.clients['${delUserIndex}'])' ${configPath}04_trojan_TCP_inbounds.json)
			echo "${trojanTCPResult}" | jq . >${configPath}04_trojan_TCP_inbounds.json
		fi

		reloadCore
	fi
	manageAccount 1
}
# Update Script
updateV2RayAgent() {
	echoContent skyBlue "\n $1/${totalProgress} : Updating v2ray-agent script"
	rm -rf /etc/v2ray-agent/install.sh
	if wget --help | grep -q show-progress; then
		wget -c -q --show-progress -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/kashimaruu/multi-script/master/install.sh"
	else
		wget -c -q -P /etc/v2ray-agent/ -N --no-check-certificate "https://raw.githubusercontent.com/kashimaruu/multi-script/master/install.sh"
	fi

	sudo chmod 700 /etc/v2ray-agent/install.sh
	local version
	version=$(grep 'Current Version:v' "/etc/v2ray-agent/install.sh" | awk -F "[v]" '{print $2}' | tail -n +2 | head -n 1 | awk -F "[\"]" '{print $1}')

	echoContent green "\n ---> Current version"
	echoContent yellow " ---> Please manually execute [vasma] to open the script"
	echoContent green " ---> Current Version:${version}\n"
	echoContent yellow "If update is successful, please manually execute the following command\n"
	echoContent skyBlue "wget -P /root -N --no-check-certificate https://raw.githubusercontent.com/kashimaruu/multi-script/master/install.sh && chmod 700 /root/install.sh && /root/install.sh"
	echo
	exit 0
}

# Handle Firewall
handleFirewall() {
	if systemctl status ufw 2>/dev/null | grep -q "active (exited)" && [[ "$1" == "stop" ]]; then
		systemctl stop ufw >/dev/null 2>&1
		systemctl disable ufw >/dev/null 2>&1
		echoContent green " ---> UFW Closed Successfully"

	fi

	if systemctl status firewalld 2>/dev/null | grep -q "active (running)" && [[ "$1" == "stop" ]]; then
		systemctl stop firewalld >/dev/null 2>&1
		systemctl disable firewalld >/dev/null 2>&1
		echoContent green " ---> Firewalld shut down sucessfully"
	fi
}

# Install BBR
bbrInstall() {
	echoContent red "\n=============================================================="
	echoContent green "BBR, DD Script from [ylx2016]"
	echoContent yellow "1. Installation Script [Original BBR+FQ] (Recommended)"
	echoContent yellow "2. Return"
	echoContent red "=============================================================="
	read -r -p "Please Select (1-2):" installBBRStatus
	if [[ "${installBBRStatus}" == "1" ]]; then
		wget -N --no-check-certificate "https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcp.sh" && chmod +x tcp.sh && ./tcp.sh
	else
		menu
	fi
}

# Check log
checkLog() {
	if [[ -z ${configPath} ]]; then
		echoContent red " ---> No Installation Directory Detected, Please execute script to install the content"
	fi
	local logStatus=false
	if grep -q "access" ${configPath}00_log.json; then
		logStatus=true
	fi

	echoContent skyBlue "\n $1/${totalProgress} : Viewing Logs"
	echoContent red "\n=============================================================="
	echoContent yellow "# It is recommended to turn on access log on debugging\n"

	if [[ "${logStatus}" == "false" ]]; then
		echoContent yellow "1. Open access log"
	else
		echoContent yellow "1. Close access log"
	fi

	echoContent yellow "2. Monitor Access Log"
	echoContent yellow "3. Monitor Error Log"
	echoContent yellow "4. View Timing Task Log"
	echoContent yellow "5. View Installation Log"
	echoContent yellow "6. Clear log"
	echoContent red "=============================================================="

	read -r -p "Please select (1-6): " selectAccessLogType
	local configPathLog=${configPath//conf\//}

	case ${selectAccessLogType} in
	1)
		if [[ "${logStatus}" == "false" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
  	"access":"${configPathLog}access.log",
    "error": "${configPathLog}error.log",
    "loglevel": "debug"
  }
}
EOF
		elif [[ "${logStatus}" == "true" ]]; then
			cat <<EOF >${configPath}00_log.json
{
  "log": {
    "error": "${configPathLog}error.log",
    "loglevel": "warning"
  }
}
EOF
		fi
		reloadCore
		checkLog 1
		;;
	2)
		tail -f ${configPathLog}access.log
		;;
	3)
		tail -f ${configPathLog}error.log
		;;
	4)
		tail -n 100 /etc/v2ray-agent/crontab_tls.log
		;;
	5)
		tail -n 100 /etc/v2ray-agent/tls/acme.log
		;;
	6)
		echo >${configPathLog}access.log
		echo >${configPathLog}error.log
		;;
	esac
}

# Script shortcut
aliasInstall() {

	if [[ -f "$HOME/install.sh" ]] && [[ -d "/etc/v2ray-agent" ]] && grep <"$HOME/install.sh" -q "Author:kashifabs-ml"; then
		mv "$HOME/install.sh" /etc/v2ray-agent/install.sh
		local vasmaType=
		if [[ -d "/usr/bin/" ]]; then
			if [[ ! -f "/usr/bin/vasma" ]]; then
				ln -s /etc/v2ray-agent/install.sh /usr/bin/vasma
				chmod 700 /usr/bin/vasma
				vasmaType=true
			fi

			rm -rf "$HOME/install.sh"
		elif [[ -d "/usr/sbin" ]]; then
			if [[ ! -f "/usr/sbin/vasma" ]]; then
				ln -s /etc/v2ray-agent/install.sh /usr/sbin/vasma
				chmod 700 /usr/sbin/vasma
				vasmaType=true
			fi
			rm -rf "$HOME/install.sh"
		fi
		if [[ "${vasmaType}" == "true" ]]; then
			echoContent green "Shortcut was created successfully. Use [vasma] to reopen the script"
		fi
	fi
}

# check ipv4, ipv6
checkIPv6() {
	# pingIPv6=$(ping6 -c 1 www.google.com | sed '2{s/[^(]*(//;s/).*//;q;}' | tail -n +2)
	pingIPv6=$(ping6 -c 1 www.google.com | sed -n '1p' | sed 's/.*(//g;s/).*//g')

	if [[ -z "${pingIPv6}" ]]; then
		echoContent red " ---> IPV6 Unsupported"
		exit 0
	fi
}

# ipv6 offload
ipv6Routing() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Config Path Not Installed, Please use script to Install"
		menu
		exit 0
	fi

	checkIPv6
	echoContent skyBlue "\nFeatures 1/${totalProgress} : IPv6 Bypass"
	echoContent red "\n=============================================================="
	echoContent yellow "1. Add Domain Name"
	echoContent yellow "2. Offload IPv6"
	echoContent red "=============================================================="
	read -r -p "Please Select (1-2): " ipv6Status
	if [[ "${ipv6Status}" == "1" ]]; then
		echoContent red "=============================================================="
		echoContent yellow "# Precautions\n"
		echoContent yellow "1. Supported Predefined Domains Rule [https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2. Detailed Documentation [https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3. If kernel fails to start, please check domain name and retry"
		echoContent yellow "4. Special characters are invalid, example below"
		echoContent yellow "5. Every new addded domain will be unusable"
		echoContent yellow "6. example: google,youtube,facebook\n"
		read -r -p "Enter domain name from example: " domainList

		if [[ -f "${configPath}09_routing.json" ]]; then

			unInstallRouting IPv6-out

			routing=$(jq -r ".routing.rules += [{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"IPv6-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >"${configPath}09_routing.json"
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "IPv6-out"
          }
        ]
  }
}
EOF
		fi

		unInstallOutbounds IPv6-out

		outbounds=$(jq -r '.outbounds += [{"protocol":"freedom","settings":{"domainStrategy":"UseIPv6"},"tag":"IPv6-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		echoContent green " ---> IPv6 Added successfully"

	elif [[ "${ipv6Status}" == "2" ]]; then

		unInstallRouting IPv6-out

		unInstallOutbounds IPv6-out

		echoContent green " ---> IPv6 sHunt Uninstalled Successfully"
	else
		echoContent red " ---> Wrong input"
		exit 0
	fi

	reloadCore
}

# BT Download Management
btTools() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Config Path Not Found, Please use Install Script"
		menu
		exit 0
	fi

	echoContent skyBlue "\n 1/${totalProgress} : BT Download Management"
	echoContent red "\n=============================================================="

	if [[ -f ${configPath}09_routing.json ]] && grep -q bittorrent <${configPath}09_routing.json; then
		echoContent yellow "Current Status: disabled"
	else
		echoContent yellow "Current Status: enabled"
	fi

	echoContent yellow "1. Disable"
	echoContent yellow "2. Enable"
	echoContent red "=============================================================="
	read -r -p "Please Select (1-2): " btStatus
	if [[ "${btStatus}" == "1" ]]; then

		if [[ -f "${configPath}09_routing.json" ]]; then

			unInstallRouting blackhole-out

			routing=$(jq -r '.routing.rules += [{"type":"field","outboundTag":"blackhole-out","protocol":["bittorrent"]}]' ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "outboundTag": "blackhole-out",
            "protocol": [ "bittorrent" ]
          }
        ]
  }
}
EOF
		fi

		installSniffing

		unInstallOutbounds blackhole-out

		outbounds=$(jq -r '.outbounds += [{"protocol":"blackhole","tag":"blackhole-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		echoContent green " ---> BT Download Disabled Successfully"

	elif [[ "${btStatus}" == "2" ]]; then

		unInstallSniffing

		unInstallRouting blackhole-out outboundTag

		unInstallOutbounds blackhole-out

		echoContent green " ---> BT Download Enabled Successfully"
	else
		echoContent red " ---> Invalid Input"
		exit 0
	fi

	reloadCore
}

# Uninstall Routing according to tag
unInstallRouting() {
	local tag=$1
	local type=$2

	if [[ -f "${configPath}09_routing.json" ]]; then
		local routing
		if grep -q "${tag}" ${configPath}09_routing.json && grep -q "${type}" ${configPath}09_routing.json; then

			jq -c .routing.rules[] ${configPath}09_routing.json | while read -r line; do
				local index=$((index + 1))
				local delStatus=0
				if [[ "${type}" == "outboundTag" ]] && echo "${line}" | jq .outboundTag | grep -q "${tag}"; then
					delStatus=1
				elif [[ "${type}" == "inboundTag" ]] && echo "${line}" | jq .inboundTag | grep -q "${tag}"; then
					delStatus=1
				fi

				if [[ ${delStatus} == 1 ]]; then
					routing=$(jq -r 'del(.routing.rules['"$(("${index}" - 1))"'])' ${configPath}09_routing.json)
					echo "${routing}" | jq . >${configPath}09_routing.json
				fi
			done
		fi
	fi
}

# Uninstall outbount based on tag
unInstallOutbounds() {
	local tag=$1

	if grep -q "${tag}" ${configPath}10_ipv4_outbounds.json; then
		local ipv6OutIndex
		ipv6OutIndex=$(jq .outbounds[].tag ${configPath}10_ipv4_outbounds.json | awk '{print ""NR""":"$0}' | grep "${tag}" | awk -F "[:]" '{print $1}' | head -1)
		if [[ ${ipv6OutIndex} -gt 0 ]]; then
			routing=$(jq -r 'del(.outbounds['$(("${ipv6OutIndex}" - 1))'])' ${configPath}10_ipv4_outbounds.json)
			echo "${routing}" | jq . >${configPath}10_ipv4_outbounds.json
		fi
	fi

}

# Uninstall Sniffing
unInstallSniffing() {

	find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
		sniffing=$(jq -r 'del(.inbounds[0].sniffing)' "${configPath}${inbound}")
		echo "${sniffing}" | jq . >"${configPath}${inbound}"
	done
}

# Install Sniffing
installSniffing() {

	find ${configPath} -name "*inbounds.json*" | awk -F "[c][o][n][f][/]" '{print $2}' | while read -r inbound; do
		sniffing=$(jq -r '.inbounds[0].sniffing = {"enabled":true,"destOverride":["http","tls"]}' "${configPath}${inbound}")
		echo "${sniffing}" | jq . >"${configPath}${inbound}"
	done
}

# WARP Routing
warpRouting() {
	echoContent skyBlue "\n $1/${totalProgress} : WARP Offload"
	echoContent red "=============================================================="
#	echoContent yellow "# Precautions\n"
#	echoContent yellow "1.官方warp经过几轮测试有bug, 重启会导致warp失效, 并且无法启动, 也有可能CPU使用率暴涨"
#	echoContent yellow "2.不重启机器可正常使用, 如果非要使用官方warp, 建议不重启机器"
#	echoContent yellow "3.有的机器重启后仍正常使用"
#	echoContent yellow "4.重启后无法使用, 也可卸载重新安装"
	# 安装warp
	if [[ -z $(which warp-cli) ]]; then
		echo
		read -r -p "WARP is not Installed, install? [y/n]:" installCloudflareWarpStatus
		if [[ "${installCloudflareWarpStatus}" == "y" ]]; then
			installWarp
		else
			echoContent yellow " ---> Installation aborted"
			exit 0
		fi
	fi

	echoContent red "\n=============================================================="
	echoContent yellow "1. Add Domain Name"
	echoContent yellow "2. Uninstall WARP Offload"
	echoContent red "=============================================================="
	read -r -p "Please Select (1-2): " warpStatus
	if [[ "${warpStatus}" == "1" ]]; then
		echoContent red "=============================================================="
		echoContent yellow "# Precautions\n"
		echoContent yellow "1. Supported Rules of Predefined Domains [https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2. Detailed Documentation [https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3. Only traffic can be distributed to WARP, not IPv4 & IPv6"
		echoContent yellow "4. If the kernel fails to start, please check domain name and add domain name again"
		echoContent yellow "5. Special characters are invalid, follow example below"
		echoContent yellow "6. New entry will be re-added and previous domain will be unavailable"
		echoContent yellow "7. example: google,youtube,facebook\n"
		read -r -p "Please enter the domain name according to example above: " domainList

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting warp-socks-out outboundTag

			routing=$(jq -r ".routing.rules += [{\"type\":\"field\",\"domain\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"warp-socks-out\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json

		else
			cat <<EOF >${configPath}09_routing.json
{
    "routing":{
        "domainStrategy": "IPOnDemand",
        "rules": [
          {
            "type": "field",
            "domain": [
            	"geosite:${domainList//,/\",\"geosite:}"
            ],
            "outboundTag": "warp-socks-out"
          }
        ]
  }
}
EOF
		fi
		unInstallOutbounds warp-socks-out

		local outbounds
		outbounds=$(jq -r '.outbounds += [{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":31303}]},"tag":"warp-socks-out"}]' ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		echoContent green " ---> WARP Added successfully"

	elif [[ "${warpStatus}" == "2" ]]; then

		${removeType} cloudflare-warp >/dev/null 2>&1

		unInstallRouting warp-socks-out outboundTag

		unInstallOutbounds warp-socks-out

		echoContent green " ---> WARP Offloaded successfully"
	else
		echoContent red " ---> Wrong Input"
		exit 0
	fi
	reloadCore
}
# Streaming Toolbox
streamingToolbox() {
	echoContent skyBlue "\nFeatures 1/${totalProgress} : Streaming Toolbox"
	echoContent red "\n=============================================================="
	#	echoContent yellow "1.Netflix检测"
	echoContent yellow "1. Dokodemo Unlock"
	echoContent yellow "2. DNS Unblock Streaming"
	read -r -p "Please select (1-2): " selectType

	case ${selectType} in
	1)
		dokodemoDoorUnblockStreamingMedia
		;;
	2)
		dnsUnlockNetflix
		;;
	esac

}

# Any Door Unlock Streaming
dokodemoDoorUnblockStreamingMedia() {
	echoContent skyBlue "\nFeatures 1/${totalProgress} : Dokodemo Unlock"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions"
	echoContent yellow "For details, please ask author\n"

	echoContent yellow "1. Add Outbound"
	echoContent yellow "2. Add Inbound"
	echoContent yellow "3. Uninstall"
	read -r -p "Please select (1-3): " selectType

	case ${selectType} in
	1)
		setDokodemoDoorUnblockStreamingMediaOutbounds
		;;
	2)
		setDokodemoDoorUnblockStreamingMediaInbounds
		;;
	3)
		removeDokodemoDoorUnblockStreamingMedia
		;;
	esac
}

# Set door to unlock Netflix (outbound)
setDokodemoDoorUnblockStreamingMediaOutbounds() {
	read -r -p "Please Enter IP to unlock the Streaming VPS:" setIP
	echoContent red "=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "1. Supported List of Predefined Domains [https://github.com/v2fly/domain-list-community]"
	echoContent yellow "2. Detailed Documentation [https://www.v2fly.org/config/routing.html]"
	echoContent yellow "3. If the kernel failed to start, retry domain name"
	echoContent yellow "4. Special characters are not allowed, check example below"
	echoContent yellow "5. Previous domain will be unavailable"
	echoContent yellow "6. example: netflix,disney,hulu\n"
	read -r -p "Enter domain name according to example above: " domainList

	if [[ -n "${setIP}" ]]; then

		unInstallOutbounds streamingMedia-80
		unInstallOutbounds streamingMedia-443

		outbounds=$(jq -r ".outbounds += [{\"tag\":\"streamingMedia-80\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22387\"}},{\"tag\":\"streamingMedia-443\",\"protocol\":\"freedom\",\"settings\":{\"domainStrategy\":\"AsIs\",\"redirect\":\"${setIP}:22388\"}}]" ${configPath}10_ipv4_outbounds.json)

		echo "${outbounds}" | jq . >${configPath}10_ipv4_outbounds.json

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting streamingMedia-80 outboundTag
			unInstallRouting streamingMedia-443 outboundTag

			local routing

			routing=$(jq -r ".routing.rules += [{\"type\":\"field\",\"port\":80,\"domain\":[\"ip.sb\",\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"streamingMedia-80\"},{\"type\":\"field\",\"port\":443,\"domain\":[\"ip.sb\",\"geosite:${domainList//,/\",\"geosite:}\"],\"outboundTag\":\"streamingMedia-443\"}]" ${configPath}09_routing.json)

			echo "${routing}" | jq . >${configPath}09_routing.json
		else
			cat <<EOF >${configPath}09_routing.json
{
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "port": 80,
        "domain": [
          "ip.sb",
          "geosite:${domainList//,/\",\"geosite:}"
        ],
        "outboundTag": "streamingMedia-80"
      },
      {
        "type": "field",
        "port": 443,
        "domain": [
          "ip.sb",
          "geosite:${domainList//,/\",\"geosite:}"
        ],
        "outboundTag": "streamingMedia-443"
      }
    ]
  }
}
EOF
		fi
		reloadCore
		echoContent green " ---> Add outbound Unlock Successfully"
		exit 0
	fi
	echoContent red " ---> IP cannot be empty"
}

# Set Dokodemo Netflix【Inbound】
setDokodemoDoorUnblockStreamingMediaInbounds() {

	echoContent skyBlue "\nFeatures 1/${totalProgress} : Add inbound Dokodemo"
	echoContent red "\n=============================================================="
	echoContent yellow "# Precautions\n"
	echoContent yellow "1. Supported Predefined Domains [https://github.com/v2fly/domain-list-community]"
	echoContent yellow "2. Detailed Documentations [https://www.v2fly.org/config/routing.html]"
	echoContent yellow "3. If Kernel Fail to start, please retry the domain again"
	echoContent yellow "4. Special Characters are not allowed, refer example below "
	echoContent yellow "5. Previous domain will be unusable"
	echoContent yellow "6. IP Entry example: 1.1.1.1,1.1.1.2"
	echoContent yellow "7. The following domain name must be consistent with outbound vps"
	echoContent yellow "8. Domain name example: netflix,disney,hulu\n"
	read -r -p "Enter allowed IP to access unlocked VPS: " setIPs
	if [[ -n "${setIPs}" ]]; then
		read -r -p "Enter domain name according to example below: " domainList

		cat <<EOF >${configPath}01_netflix_inbounds.json
{
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": 22387,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 80,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http"
        ]
      },
      "tag": "streamingMedia-80"
    },
    {
      "listen": "0.0.0.0",
      "port": 22388,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "0.0.0.0",
        "port": 443,
        "network": "tcp",
        "followRedirect": false
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "tls"
        ]
      },
      "tag": "streamingMedia-443"
    }
  ]
}
EOF

		cat <<EOF >${configPath}10_ipv4_outbounds.json
{
    "outbounds":[
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv4"
            },
            "tag":"IPv4-out"
        },
        {
            "protocol":"freedom",
            "settings":{
                "domainStrategy":"UseIPv6"
            },
            "tag":"IPv6-out"
        },
        {
            "protocol":"blackhole",
            "tag":"blackhole-out"
        }
    ]
}
EOF

		if [[ -f "${configPath}09_routing.json" ]]; then
			unInstallRouting streamingMedia-80 inboundTag
			unInstallRouting streamingMedia-443 inboundTag

			local routing
			routing=$(jq -r ".routing.rules += [{\"source\":[\"${setIPs//,/\",\"}\"],\"type\":\"field\",\"inboundTag\":[\"streamingMedia-80\",\"streamingMedia-443\"],\"outboundTag\":\"direct\"},{\"domains\":[\"geosite:${domainList//,/\",\"geosite:}\"],\"type\":\"field\",\"inboundTag\":[\"streamingMedia-80\",\"streamingMedia-443\"],\"outboundTag\":\"blackhole-out\"}]" ${configPath}09_routing.json)
			echo "${routing}" | jq . >${configPath}09_routing.json
		else
			cat <<EOF >${configPath}09_routing.json
            {
              "routing": {
                "rules": [
                  {
                    "source": [
                    	"${setIPs//,/\",\"}"
                    ],
                    "type": "field",
                    "inboundTag": [
                      "streamingMedia-80",
                      "streamingMedia-443"
                    ],
                    "outboundTag": "direct"
                  },
                  {
                    "domains": [
                    	"geosite:${domainList//,/\",\"geosite:}"
                    ],
                    "type": "field",
                    "inboundTag": [
                      "streamingMedia-80",
                      "streamingMedia-443"
                    ],
                    "outboundTag": "blackhole-out"
                  }
                ]
              }
            }
EOF

		fi

		reloadCore
		echoContent green " ---> Added Dokodemo Inbound Unlock"
		exit 0
	fi
	echoContent red " ---> IP Cannot be empty"
}

# Remove Dokodemo Netflix
removeDokodemoDoorUnblockStreamingMedia() {

	unInstallOutbounds streamingMedia-80
	unInstallOutbounds streamingMedia-443

	unInstallRouting streamingMedia-80 inboundTag
	unInstallRouting streamingMedia-443 inboundTag

	unInstallRouting streamingMedia-80 outboundTag
	unInstallRouting streamingMedia-443 outboundTag

	rm -rf ${configPath}01_netflix_inbounds.json

	reloadCore
	echoContent green " ---> Uninstalled successfully"
}

# Reload Services
reloadCore() {
	if [[ "${coreInstallType}" == "1" ]]; then
		handleXray stop
		handleXray start
	elif [[ "${coreInstallType}" == "2" || "${coreInstallType}" == "3" ]]; then
		handleV2Ray stop
		handleV2Ray start
	fi
}

# DNS Unblock Netflix
dnsUnlockNetflix() {
	if [[ -z "${configPath}" ]]; then
		echoContent red " ---> Config Path Not Installed, please use script to Install"
		menu
		exit 0
	fi
	echoContent skyBlue "\nFeatures 1/${totalProgress} : Unblock Streaming DNS"
	echoContent red "\n=============================================================="
	echoContent yellow "1. Add"
	echoContent yellow "2. Remove"
	read -r -p "Select (1-2): " selectType

	case ${selectType} in
	1)
		setUnlockDNS
		;;
	2)
		removeUnlockDNS
		;;
	esac
}

# 设置dns
setUnlockDNS() {
	read -r -p "Uninstall DNS settings: " setDNS
	if [[ -n ${setDNS} ]]; then
		echoContent red "=============================================================="
		echoContent yellow "# Precautions\n"
		echoContent yellow "1. Supported Predefined Domains [https://github.com/v2fly/domain-list-community]"
		echoContent yellow "2. Detailed Documentations [https://www.v2fly.org/config/routing.html]"
		echoContent yellow "3. If Kernel Fail to start, please retry the domain again "
		echoContent yellow "4. Special Characters are not allowed, refer example below "
		echoContent yellow "5. Previous domain will be unusable"
		echoContent yellow "6. example: netflix,disney,hulu"
		echoContent yellow "7. Please only enter 1 default scheme including the following"
		echoContent yellow "netflix,bahamut,hulu,hbo,disney,bbc,4chan,fox,abema,dmm,niconico,pixiv,bilibili,viu"
		read -r -p "Enter domain name according to example above: " domainList
		if [[ "${domainList}" == "1" ]]; then
			cat <<EOF >${configPath}11_dns.json
            {
            	"dns": {
            		"servers": [
            			{
            				"address": "${setDNS}",
            				"port": 53,
            				"domains": [
            					"geosite:netflix",
            					"geosite:bahamut",
            					"geosite:hulu",
            					"geosite:hbo",
            					"geosite:disney",
            					"geosite:bbc",
            					"geosite:4chan",
            					"geosite:fox",
            					"geosite:abema",
            					"geosite:dmm",
            					"geosite:niconico",
            					"geosite:pixiv",
            					"geosite:bilibili",
            					"geosite:viu"
            				]
            			},
            		"localhost"
            		]
            	}
            }
EOF
		elif [[ -n "${domainList}" ]]; then
			cat <<EOF >${configPath}11_dns.json
                        {
                        	"dns": {
                        		"servers": [
                        			{
                        				"address": "${setDNS}",
                        				"port": 53,
                        				"domains": [
                        					"geosite:${domainList//,/\",\"geosite:}"
                        				]
                        			},
                        		"localhost"
                        		]
                        	}
                        }
EOF
		fi

		reloadCore

		echoContent yellow "\n ---> If there are still errors occuring, you can try to:"
		echoContent yellow " 1. Restart the VPS"
		echoContent yellow " 2. After removing DNS Unlock, modify DNS settings in [/etc/resolv.conf] and restart VPS\n"
	else
		echoContent red " ---> DNS cannot be null"
	fi
	exit 0
}

# Remove Netflix unblock
removeUnlockDNS() {
	cat <<EOF >${configPath}11_dns.json
{
	"dns": {
		"servers": [
			"localhost"
		]
	}
}
EOF
	reloadCore

	echoContent green " ---> Uninstalled Successfully"

	exit 0
}

# v2ray-core Custom Installation
customV2RayInstall() {
	echoContent skyBlue "\n========================Personalized Installation============================"
	echoContent yellow "VLESS is pre-installed by default, selecting option 0 will ignore other installs"
	echoContent yellow "0. VLESS+TLS/XTLS+TCP"
	echoContent yellow "1. VLESS+TLS+WS[CDN]"
	echoContent yellow "2. Trojan+TLS+gRPC[CDN]"
	echoContent yellow "3. VMess+TLS+WS[CDN]"
	echoContent yellow "4. Trojan"
	echoContent yellow "5. VLESS+TLS+gRPC[CDN]"
	read -r -p "Select [Multiple Choice], [example: 123]: " selectCustomInstallType
	echoContent skyBlue "--------------------------------------------------------------------------"
	if [[ -z ${selectCustomInstallType} ]]; then
		selectCustomInstallType=0
	fi
	if [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp xrayClean
		totalProgress=17
		installTools 1
		# Apply TLS
		initTLSNginxConfig 2
		installTLS 3
		handleNginx stop
		# Random PATH
		if echo ${selectCustomInstallType} | grep -q 1 || echo ${selectCustomInstallType} | grep -q 3 || echo ${selectCustomInstallType} | grep -q 4; then
			randomPathFunction 5
			customCDNIP 6
		fi
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		# 安装V2Ray
		installV2Ray 8
		installV2RayService 9
		initV2RayConfig custom 10
		cleanUp xrayDel
		installCronTLS 14
		handleV2Ray stop
		handleV2Ray start
		# 生成账号
		checkGFWStatue 15
		showAccounts 16
	else
		echoContent red " ---> Invalid Input"
		customV2RayInstall
	fi
}

# Xray-core个性化安装
customXrayInstall() {
	echoContent skyBlue "\n========================Personalized Installation============================"
	echoContent yellow "VLESS is pre-installed by default, selecting option 0 will ignore other installs"
	echoContent yellow "0. VLESS+TLS/XTLS+TCP"
	echoContent yellow "1. VLESS+TLS+WS[CDN]"
	echoContent yellow "2. Trojan+TLS+gRPC[CDN]"
	echoContent yellow "3. VMess+TLS+WS[CDN]"
	echoContent yellow "4. Trojan"
	echoContent yellow "5. VLESS+TLS+gRPC[CDN]"
	read -r -p "Select [Multiple Choice], [example: 123]: " selectCustomInstallType
	echoContent skyBlue "--------------------------------------------------------------------------"
	if [[ -z ${selectCustomInstallType} ]]; then
		echoContent red " ---> Please select properly"
		customXrayInstall
	elif [[ "${selectCustomInstallType}" =~ ^[0-5]+$ ]]; then
		cleanUp v2rayClean
		totalProgress=17
		installTools 1
		# TLS apply
		initTLSNginxConfig 2
		installTLS 3
		handleNginx stop
		# Random PATH
		if echo "${selectCustomInstallType}" | grep -q 1 || echo "${selectCustomInstallType}" | grep -q 2 || echo "${selectCustomInstallType}" | grep -q 3 || echo "${selectCustomInstallType}" | grep -q 5; then
			randomPathFunction 5
			customCDNIP 6
		fi
		nginxBlog 7
		updateRedirectNginxConf
		handleNginx start

		# Install V2Ray
		installXray 8
		installXrayService 9
		initXrayConfig custom 10
		cleanUp v2rayDel

		installCronTLS 14
		handleXray stop
		handleXray start
		# Generate Account
		checkGFWStatue 15
		showAccounts 16
	else
		echoContent red " ---> Invalid Input"
		customXrayInstall
	fi
}

# Select Core Install---v2ray-core、xray-core
selectCoreInstall() {
	echoContent skyBlue "\nFeatures 1/${totalProgress} : Select Core to Install"
	echoContent red "\n=============================================================="
	echoContent yellow "1. Xray-core"
	echoContent yellow "2. v2ray-core"
	echoContent red "=============================================================="
	read -r -p "Select (1-2): " selectCoreType
	case ${selectCoreType} in
	1)
		if [[ "${selectInstallType}" == "2" ]]; then
			customXrayInstall
		else
			xrayCoreInstall
		fi
		;;
	2)
		v2rayCoreVersion=
		if [[ "${selectInstallType}" == "2" ]]; then
			customV2RayInstall
		else
			v2rayCoreInstall
		fi
		;;
	3)
		v2rayCoreVersion=v4.32.1
		if [[ "${selectInstallType}" == "2" ]]; then
			customV2RayInstall
		else
			v2rayCoreInstall
		fi
		;;
	*)
		echoContent red ' ---> Invalid Input'
		selectCoreInstall
		;;
	esac
}

# v2ray-core Install
v2rayCoreInstall() {
	cleanUp xrayClean
	selectCustomInstallType=
	totalProgress=13
	installTools 2
	# Apply tls
	initTLSNginxConfig 3
	installTLS 4
	handleNginx stop
	#	initNginxConfig 5
	randomPathFunction 5
	# Install V2Ray
	installV2Ray 6
	installV2RayService 7
	customCDNIP 8
	initV2RayConfig all 9
	cleanUp xrayDel
	installCronTLS 10
	nginxBlog 11
	updateRedirectNginxConf
	handleV2Ray stop
	sleep 2
	handleV2Ray start
	handleNginx start
	# generate account
	checkGFWStatue 12
	showAccounts 13
}

# xray-core Install
xrayCoreInstall() {
	cleanUp v2rayClean
	selectCustomInstallType=
	totalProgress=13
	installTools 2
	# Apply tls
	initTLSNginxConfig 3
	installTLS 4
	handleNginx stop
	randomPathFunction 5
	# Install Xray
	# handleV2Ray stop
	installXray 6
	installXrayService 7
	customCDNIP 8
	initXrayConfig all 9
	cleanUp v2rayDel
	installCronTLS 10
	nginxBlog 11
	updateRedirectNginxConf
	handleXray stop
	sleep 2
	handleXray start

	handleNginx start
	# Generate Account
	checkGFWStatue 12
	showAccounts 13
}

# Core Version Management Menu
coreVersionManageMenu() {

	if [[ -z "${coreInstallType}" ]]; then
		echoContent red "\n ---> No Installation Directory Found, please execute the script again to install"
		menu
		exit 0
	fi
	if [[ "${coreInstallType}" == "1" ]]; then
		xrayVersionManageMenu 1
	elif [[ "${coreInstallType}" == "2" ]]; then
		v2rayCoreVersion=
		v2rayVersionManageMenu 1

	elif [[ "${coreInstallType}" == "3" ]]; then
		v2rayCoreVersion=v4.32.1
		v2rayVersionManageMenu 1
	fi
}
# Renew TLS
cronRenewTLS() {
	if [[ "${renewTLS}" == "RenewTLS" ]]; then
		renewalTLS
		exit 0
	fi
}
# Account Management
manageAccount() {
	echoContent skyBlue "\nFeatures 1/${totalProgress} : Account Management"
	echoContent red "\n=============================================================="
	echoContent yellow "# Everytime account(s) is changed, please re-check the subscription\n"
	echoContent yellow "1. View Account"
	echoContent yellow "2. View Subscriptions"
	echoContent yellow "3. Add User"
	echoContent yellow "4. Delete User(s)"
	echoContent red "=============================================================="
	read -r -p "Select (1-4): " manageAccountStatus
	if [[ "${manageAccountStatus}" == "1" ]]; then
		showAccounts 1
	elif [[ "${manageAccountStatus}" == "2" ]]; then
		subscribe 1
	elif [[ "${manageAccountStatus}" == "3" ]]; then
		addUser
	elif [[ "${manageAccountStatus}" == "4" ]]; then
		removeUser
	else
		echoContent red " ---> Invalid Input"
	fi
}

# Subscription
subscribe() {
	if [[ -n "${configPath}" ]]; then
		echoContent skyBlue "-------------------------Subscription---------------------------------"
		echoContent yellow "# New subscriptions are generated when viewing"
		echoContent yellow "# Everytime account(s) is changed, please re-check the subscription"
		rm -rf /etc/v2ray-agent/subscribe/*
		rm -rf /etc/v2ray-agent/subscribe_tmp/*
		showAccounts >/dev/null
		mv /etc/v2ray-agent/subscribe_tmp/* /etc/v2ray-agent/subscribe/

		if [[ -n $(ls /etc/v2ray-agent/subscribe/) ]]; then
			find /etc/v2ray-agent/subscribe/* | while read -r email; do
				email=$(echo "${email}" | awk -F "[s][u][b][s][c][r][i][b][e][/]" '{print $2}')
				local base64Result
				base64Result=$(base64 -w 0 "/etc/v2ray-agent/subscribe/${email}")
				echo "${base64Result}" >"/etc/v2ray-agent/subscribe/${email}"
				echoContent skyBlue "--------------------------------------------------------------"
				echoContent yellow "email: $(echo "${email}" | awk -F "[_]" '{print $1}')\n"
				echoContent yellow "url: https://${currentHost}/s/${email}\n"
				echoContent yellow "QR Code: https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=https://${currentHost}/s/${email}\n"
				echo "https://${currentHost}/s/${email}" | qrencode -s 10 -m 1 -t UTF8
				echoContent skyBlue "--------------------------------------------------------------"
			done
		fi
	else
		echoContent red " ---> Not Installed"
	fi
}

# Switching ALPN
switchAlpn() {
	echoContent skyBlue "\nFeatures 1/${totalProgress} : Switch alpn"
	if [[ -z ${currentAlpn} ]]; then
		echoContent red " ---> Unable to find alpn setup, please check for installation"
		exit 0
	fi

	echoContent red "\n=============================================================="
	echoContent green "Current ALPN: ${currentAlpn}"
	echoContent yellow "  1. [http/1.1] trojan is included, some gRPC clients are available【client support manual selection of alpn】"
	echoContent yellow "  2. [h2] gRPC available, some trojan clients included【client support manual selection of alpn】"
	echoContent yellow "  3. If client does not support manual replacement of alpn,"
	echoContent yellow "     please use this features to change the order of alpn on the server"
	echoContent red "=============================================================="

	if [[ "${currentAlpn}" == "http/1.1" ]]; then
		echoContent yellow "1. Toggle alpn h2"
	elif [[ "${currentAlpn}" == "h2" ]]; then
		echoContent yellow "1. Toggle alpn http/1.1"
	else
		echoContent red 'Incompatible to switch alpn'
	fi

	echoContent red "=============================================================="

	read -r -p "Please select (1): " selectSwitchAlpnType
	if [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "http/1.1" ]]; then

		local frontingTypeJSON
		frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.xtlsSettings.alpn = [\"h2\",\"http/1.1\"]" ${configPath}${frontingType}.json)
		echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json

	elif [[ "${selectSwitchAlpnType}" == "1" && "${currentAlpn}" == "h2" ]]; then
		local frontingTypeJSON
		frontingTypeJSON=$(jq -r ".inbounds[0].streamSettings.xtlsSettings.alpn =[\"http/1.1\",\"h2\"]" ${configPath}${frontingType}.json)
		echo "${frontingTypeJSON}" | jq . >${configPath}${frontingType}.json
	else
		echoContent red " ---> Invalid Input"
		exit 0
	fi
	reloadCore
}
# Main menu
menu() {
	cd "$HOME" || exit
	echoContent red "\n=============================================================="
	echoContent green "Author: kashifabs"
	echoContent green "Current Version:v2.5.48"
	echoContent green "Github: https://github.com/kashimaruu/multi-script"
	echoContent green "Auto-Install Script\c"
	showInstallStatus
	echoContent red "\n=============================================================="
	if [[ -n "${coreInstallType}" ]]; then
		echoContent yellow "1. Re-Install"
	else
		echoContent yellow "1. Install"
	fi

	echoContent yellow "2. Install Combination"
	if echo ${currentInstallProtocolType} | grep -q trojan; then
		echoContent yellow "3. Toggle VLESS[XTLS]"
	elif echo ${currentInstallProtocolType} | grep -q 0; then
		echoContent yellow "3. Toggle Trojan[XTLS]"
	fi

	echoContent skyBlue "-------------------------Tools-------------------------------"
	echoContent yellow "4. Account Management"
	echoContent yellow "5. Replace NGINX Camouflage"
	echoContent yellow "6. Update Certificate"
	echoContent yellow "7. Replace CDN Node"
	echoContent yellow "8. IPv6 Offload"
	echoContent yellow "9. WARP Offload"
	echoContent yellow "10. Streaming Tools (Netflix etc.)"
	echoContent yellow "11. Add New Port"
	echoContent yellow "12. BT Download Management"
	echoContent yellow "13. Toggle ALPN"
	echoContent skyBlue "-------------------------Version-----------------------------"
	echoContent yellow "14. Core Management"
	echoContent yellow "15. Update Script"
	echoContent yellow "16. Install BBR, DD Scripts"
	echoContent skyBlue "-------------------------Script------------------------------"
	echoContent yellow "17. View Logs"
	echoContent yellow "18. Uninstall Script"
	echoContent red "============================================================="
	mkdirTools
	aliasInstall
	read -r -p "Please Select (1-18): " selectInstallType
	case ${selectInstallType} in
	1)
		selectCoreInstall
		;;
	2)
		selectCoreInstall
		;;
	3)
		initXrayFrontingConfig 1
		;;
	4)
		manageAccount 1
		;;
	5)
		updateNginxBlog 1
		;;
	6)
		renewalTLS 1
		;;
	7)
		updateV2RayCDN 1
		;;
	8)
		ipv6Routing 1
		;;
	9)
		warpRouting 1
		;;
	10)
		streamingToolbox 1
		;;
	11)
		addCorePort 1
		;;
	12)
		btTools 1
		;;
	13)
		switchAlpn 1
		;;
	14)
		coreVersionManageMenu 1
		;;
	15)
		updateV2RayAgent 1
		;;
	16)
		bbrInstall
		;;
	17)
		checkLog 1
		;;
	18)
		unInstall 1
		;;
	esac
}
cronRenewTLS
menu
