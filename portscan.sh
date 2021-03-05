#!/bin/bash

default_interface=`route | grep '^default' | grep -o '[^ ]*$'`
net="10.10.10."

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

echo -ne "\n[+] Sweeping for live hosts (ICMP + ARP)\n"
pingsweep | sort -V | uniq > /tmp/livehosts.txt
count=`cat /tmp/livehosts.txt | wc -l`

echo -ne "[+] $count hosts found\n[+] Beginning port scan\n\n"
portscan | sort -V | uniq
