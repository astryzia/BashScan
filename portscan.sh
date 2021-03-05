#!/bin/bash

net="10.10.10."  # You should only need to change this variable and nothing else

default_interface=`route | grep '^default' | grep -o '[^ ]*$'`

pingsweep(){
for ip in {1..254}; do
	if test ! $(which arping); then
		ping -c 1 -W 1 $net$ip | tr \\n " " | awk '/1 received/ {print $2}' &
	else
		ping -c 1 -W 1 $net$ip | tr \\n " " | awk '/1 received/ {print $2}' &
		arping -c 1 -w 1 -I $default_interface $net$ip | tr \\n " " | awk '/1 from/ {print $2}' &
	fi
done;
}

portscan(){
for host in $(cat /tmp/livehosts.txt);
do for port in {20,21,22,80,135,139,443,445,554,3306,3389,8080,8443};
	do (echo >/dev/tcp/$host/$port) >& /dev/null && echo "$host:$port is open" &
        done;
done;
}

host_info(){
        if test ! $(which hostname); then
                localip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'`
		netCIDR=`ip -o -f inet addr show | awk '/scope global/ {print $2, $4}' | cut -d"/" -f2 | head -1`
                network=`echo $localip | cut -d"." -f1,2,3`
                iprange=`echo $network".0/"$netCIDR`
		default_interface=`route | grep '^default' | grep -o '[^ ]*$'`
        else
                localip=`hostname -I | cut -d" " -f1`
		netCIDR=`ip -o -f inet addr show | awk '/scope global/ {print $2, $4}' | cut -d"/" -f2 | head -1`
                network=`echo $localip | cut -d"." -f1,2,3`
                iprange=`echo $network".0/"$netCIDR`
		default_interface=`route | grep '^default' | grep -o '[^ ]*$'`
        fi

getip=`curl -s icanhazip.com`
ipinfo=`curl -sL ipinfo.io/$getip | jq .region,.country | tr -d '"' | tr "\n" "/" | cut -d "/" -f1,2`

echo -e "\nLocal IP:\t\t$localip"
echo -e "Netmask:\t\t$iprange"
echo -e "External IP:\t\t$getip ($ipinfo)"
echo -e "Default Interface:\t$default_interface"
}

host_info

echo -ne "\n[+] Sweeping for live hosts (ICMP + ARP)\n"
pingsweep | sort -V | uniq > /tmp/livehosts.txt
count=`cat /tmp/livehosts.txt | wc -l`

echo -ne "[+] $count hosts found\n[+] Beginning port scan\n\n"
portscan | sort -V | uniq
