#!/bin/bash
#---help---
# Usage: PROGNAME [options]
#
# No nmap only bash /dev/tcp go brrrrrrrrrrrrrrrrr
#
# Options:
#   -r --root           Force ARP ping to run even if user doesn't have root privileges.
#
#   -h --help           Show this help message and exit.
#
#   -v --version        Print version and exit.
#
#---help---

readonly PROGNAME='portscan.sh'
readonly VERSION='0.0.1'

help() {
	sed -En '/^#---help---/,/^#---help---/p' "$0" | sed -E "s/PROGNAME/$PROGNAME/" | sed -E 's/^# ?//; 1d;$d;'
	exit ${1:-0}
}

opts=$(getopt -n $PROGNAME -o rhv \
	-l root,help,version \
	-- "$@") || help 1 >&2

eval set -- "$opts"
while [ $# -gt 0 ]; do
	n=2
	case "$1" in
		-r | --root) ROOT_CHECK=false;;
		-h | --help) help 0;;
		-v | --version) echo "$PROGNAME $VERSION"; exit 0;;
		--) shift; break;;
	esac
	shift $n
done

# Default values for the script options
: ${ROOT_CHECK:=true}

if test ! $(which hostname); then
        localip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'`
else
        localip=`hostname -I | cut -d" " -f1`
fi

netCIDR=`ip -o -f inet addr show | awk '/scope global/ {print $2, $4}' | cut -d"/" -f2 | head -1`
network=`echo $localip | cut -d"." -f1,2,3`
iprange=`echo $network".0/"$netCIDR`
default_interface=`route | grep '^default' | grep -o '[^ ]*$'`

if test $(which curl); then
	getip=`curl -s icanhazip.com`
elif test $(which wget); then
	getip=`wget -O- -q icanhazip.com`
fi


echo -e "\nLocal IP:\t\t$localip"
echo -e "Netmask:\t\t$iprange"
echo -e "External IP:\t\t$getip"
echo -e "Default Interface:\t$default_interface"


pingsweep(){
for ip in {1..254}; do
	if test $(which arping); then
		if [ "$ROOT_CHECK" = false ] || [ "$EUID" = 0 ]; then
			arping -c 1 -w 1 -I $default_interface $network.$ip 2>/dev/null | tr \\n " " | awk '/1 from/ {print $2}' &
		fi
	fi
	ping -c 1 -W 1 $network.$ip | tr \\n " " | awk '/1 received/ {print $2}' &
done;
}

portscan(){
for host in $(cat /tmp/livehosts.txt);
do for port in {20,21,22,80,135,139,443,445,554,3306,3389,8080,8443};
	do (echo >/dev/tcp/$host/$port) >& /dev/null && echo "$host:$port is open" &
        done;
done;
}

if [ "$ROOT_CHECK" = true ] && [ "$EUID" != 0 ]; then
	echo -ne "\n[-] ARP ping disabled as root may be required, --help for more information"
fi

echo -ne "\n[+] Sweeping for live hosts (ICMP + ARP)\n"
pingsweep | sort -V | uniq > /tmp/livehosts.txt
count=`cat /tmp/livehosts.txt | wc -l`

echo -ne "[+] $count hosts found\n[+] Beginning port scan\n\n"
portscan | sort -V | uniq
