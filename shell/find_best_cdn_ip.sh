#!/usr/bin/env bash
num=5
ip=()
timeout=1000
echoType='echo -e'
trap 'onCtrlC' INT
function onCtrlC () {
    statisticalContent
    exit;
}
# Calculating
statisticalContent(){
    if [[ ! -z `ls /tmp|grep -v grep|grep ping.log` ]]
    then
        echoContent red "============================================="
        echoContent yellow 'Calculating--->'
        # Sorting
        echoContent red "Sorting rule: packet loss rate > fluctuation > average delay, only the best 30 items are displayed"
        echoContent red "Shown in order: [ ip, packet loss, rate, minimum delay, average delay, maximum delay, fluctuation ]"
        cat /tmp/ping.log|sort -t ' ' -k 2n -k 6n -k 4n|head -30
        echoContent red "============================================="
    fi

}
# echo content method
echoContent(){
    case $1 in
        # Red
        "red")
            ${echoType} "\033[31m$2 \033[0m"
        ;;
        # skyBlue
        "skyBlue")
            ${echoType} "\033[36m$2 \033[0m"
        ;;
        #Green
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
        # Yelow
        "yellow")
            ${echoType} "\033[33m$2 \033[0m"
        ;;
    esac
}
# ping tool
pingTool(){
    echo ''>/tmp/ping.log
    echoContent red "============================================="
    echoContent green "Default test 5 times [1000ms-]"
    echoContent red "============================================="
    read -p "Please enter the number of tests for IP [default 5]: " testNum
    if [[ "$testNum" =~ ^[0-9]+$ ]]
    then
        num=${testNum}
    else
        echoContent red 'Use 5'
    fi
    echoContent yellow "Total ${#ip[*]}IP(s)，Testing each IP 2nd-rate ${num} , approx. `expr ${#ip[*]} \* ${num} / 60` minute(s)"
    echoContent yellow "You can press [CTRL + C] to record calculations and statistics"
    for ((i=0;i<${#ip[*]};i++))
    do
        if [[ -z ${ip[$i]} ]]
        then
            continue;
        fi
        pingResult=`ping -c ${num} -W ${timeout} ${ip[$i]}`
        packetLoss=`echo ${pingResult}|awk -F "[%]" '{print $1}'|awk -F "[p][a][c][k][e][t][s][ ][r][e][c][e][i][v][e][d][,][ ]" '{print $2}'`
        roundTrip=`echo ${pingResult}|awk -F "[r][o][u][n][d][-][t][r][i][p]" '{print $2}'|awk '{print $3}'|awk -F "[/]" '{print $1"."$2"."$3"."$4}'|awk -F "[/]" '{print $1$2$3$4}'|awk -F "[.]" '{print $1" "$3" "$5" "$7}'`
        if [[ "${release}" = "ubuntu" ]] || [[ "${release}" = "debian" ]] || [[ "${release}" = "centos" ]]
        then
            packetLoss=`echo ${pingResult}|awk -F "[%]" '{print $1}'|awk -F "[r][e][c][e][i][v][e][d][,][ ]" '{print $2}'`
            roundTrip=`echo ${pingResult}|awk -F "[r][t][t]" '{print $2}'|awk '{print $3}'|awk -F "[/]" '{print $1"."$2"."$3"."$4}'|awk -F "[/]" '{print $1$2$3$4}'|awk -F "[.]" '{print $1" "$3" "$5" "$7}'`
        fi

        ## |awk -F "[/]" '{print $1$2$3}'|awk -F "[.]" '{print $1" "$3" "$5" "$7}'
        if [[ -z ${roundTrip} ]]
        then
            roundTrip="none"
        fi
        echo "IP: ${ip[$i]}, Packet Loss : ${packetLoss}%, min/average/max/fluctuation: ${roundTrip}"
        echo "${ip[$i]} ${packetLoss} ${roundTrip}" >> /tmp/ping.log
    done
    statisticalContent
}
# Search Region
findCountry(){
    if [[ -z  `ls /tmp|grep -v grep|grep ips` ]]
    then
        echoContent red "IP Library is missing, please contact author"
        exit 0;
    fi
    echoContent red "============================================="
    cat /tmp/ips|awk -F "[|]" '{print $1}'|awk  -F "[-]" '{print $3}'|uniq|awk '{print NR":"$0}'
    echoContent red "============================================="
    read -p "Select Numbers Above: " selectType
    if [[ -z `cat /tmp/ips|awk -F "[|]" '{print $1}'|awk  -F "[-]" '{print $3}'|uniq|awk '{print NR":"$0}'|grep -v grep|grep ${selectType}` ]]
    then
        echoContent red 'Incorrect Input, try again'
        findCountry
    fi
    findIPList ${selectType}
}
# Find IP List
findIPList(){
    country=`cat /tmp/ips|awk -F "[|]" '{print $1}'|awk  -F "[-]" '{print $3}'|uniq|awk '{print NR":"$0}'|grep -v grep|grep ${selectType}|sort -t ':' -k 1n|head -1|awk -F "[:]" '{print $2}'`
    # cat /tmp/ips|awk -F "[|]" '{print $1}'|awk  -F "[-]" '{print $3}'|uniq|awk '{print NR":"$0}'|grep -v grep|grep 1|sort -t ':' -k 1n|head -1|awk -F "[:]" '{print $2}'
    echoContent red "============================================="
    cat /tmp/ips|grep -v grep|grep ${country}|awk -F "[|]" '{print $1}'|awk -F "[-]" '{print $1"-"$2}'|awk '{print "["NR"]"":"$0}'
    read -p "Enter IP Number above: " selectType
    if [[ -z ${selectType} ]]
    then
        echoContent red 'Input error, please re-enter!'
        findIPList $1
    fi
    echo ${country}
    # cat /tmp/ips|grep -v grep|grep 中国移动|awk -F "[|]" '{print NR"-"$2}'|grep 174-|head -1 |awk -F "[|]" '{print $2}'
    eval $(cat /tmp/ips|grep -v grep|grep ${country}|awk -F "[|]" '{print NR"-"$2}'|grep ${selectType}-|head -1|awk -F "[-]" '{print $2}'|awk '{split($0,serverNameList," ");for(i in serverNameList) print "ip["i"]="serverNameList[i]}')
    pingTool
}
# Check OS
checkSystem(){
    if [[ "`uname`" = "Darwin" ]]
	then
	    release="Darwin"
	elif [[ ! -z `find /etc -name "redhat-release"` ]] || [[ ! -z `cat /proc/version | grep -i "centos" | grep -v grep ` ]] || [[ ! -z `cat /proc/version | grep -i "red hat" | grep -v grep ` ]] || [[ ! -z `cat /proc/version | grep -i "redhat" | grep -v grep ` ]]
    then
        release="centos"
	elif [[ ! -z `cat /etc/issue | grep -i "ubuntu" | grep -v grep` ]] || [[ ! -z `cat /proc/version | grep -i "ubuntu" | grep -v grep` ]]
	then
		release="ubuntu"
    elif [[ ! -z `cat /etc/issue | grep -i "debian" | grep -v grep` ]] || [[ ! -z `cat /proc/version | grep -i "debian" | grep -v grep` ]]
	then
		release="debian"
    fi
    if [[ -z ${release} ]]
    then
        echoContent red "This machine does not support running the script, please contact author with log below."
        cat /etc/issue
        cat /proc/version
        killSleep > /dev/null 2>&1
        exit 0;
    fi
}
# Download IPS
downloadIPs(){
    if [[ -z `ls /tmp|grep -v grep|grep ips` ]]
    then
        echoContent yellow 'Downloading IP Library'
        wget -q -P /tmp/ https://raw.githubusercontent.com/mack-a/v2ray-agent/dev/fodder/ips/ips
        echoContent yellow 'Download Completed'
    fi
}
downloadIPs
checkSystem
findCountry

