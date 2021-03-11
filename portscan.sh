#!/bin/bash

readonly PROGNAME='portscan.sh'
readonly VERSION='0.0.1'

usage() {
	echo "Usage: " $PROGNAME " [ -r | --root ]          Force ARP ping to run even if user doesn't have root privileges.
	             [ -p | --ports PORTS ]   Replace default TCP port list with custom range.
	             [ -h | --help ]          Show this help message and exit.
	             [ -v | --version ]       Print version and exit. "
	exit 0
}


PARSED_ARGUMENTS=$(getopt -n $PROGNAME \
	-a \
	-o p:rhv \
	-l ports:,root,help,version \
	-- "$@")
VALID_ARGUMENTS=$?

if [ "$VALID_ARGUMENTS" != "0" ]; then
  usage
fi

eval set -- "$PARSED_ARGUMENTS"
while [ $# -gt 0 ]; do
	case "$1" in
		-p | --ports) ports="$2"                            ; shift 2 ;;
		-r | --root) ROOT_CHECK=false                       ; shift   ;; 
		-h | --help) usage                                  ; exit 0  ;;
		-v | --version) echo "$PROGNAME $VERSION"           ; exit 0  ;;
		--) shift; break;;
    	# If invalid options were passed, then getopt should have reported an error,
    	# which we checked as VALID_ARGUMENTS when getopt was called...
    	*) echo "Unexpected option: $1 - this should not happen."
		usage ;;
	esac
done

# Default values for the script options
: ${ROOT_CHECK:=true}

# extract default network interface name from /proc
#default_interface=$(cat /proc/net/dev | grep -v lo | cut -d$'\n' -f3 | cut -d":" -f1)

# extract default network interface from route
default_interface=`route | grep '^default' | grep -o '[^ ]*$'`

if test $(which ip); then
	localaddr=`ip -o -4 addr show $default_interface | tr -s " " | cut -d" " -f4`
	IFS=/ read localip netCIDR <<< $localaddr
elif test $(which ifconfig); then
    localaddr=`ifconfig $default_interface | grep -Eo '(addr:)?([0-9]*\.){3}[0-9]*'`
    localip=$(cut -d$'\n' -f1 <<< $localaddr)
    netmask=$(cut -d$'\n' -f2 <<< $localaddr)
    # ifconfig doesn't output CIDR, but we can calculate it from the netmask bits
    c=0 x=0$( printf '%o' ${netmask//./ } )
    while [ $x -gt 0 ]; do
      	let c+=$((x%2)) 'x>>=1'
    done
    netCIDR=$c
else
        localip=`hostname -I | cut -d" " -f1`
        # FIXME: in an edge case where neither ifconfig nor iproute2 utils are available
        #        need to get CIDR some other way
fi

## FIXME: these values for network and iprange are only valid for /24 CIDRs.
#         need to update the method if/when custom CIDRs are allowed
network=`echo $localip | cut -d"." -f1,2,3`
iprange=`echo $network".0/"$netCIDR`


if test $(which curl); then
	getip=`curl -s icanhazip.com`
elif test $(which wget); then
	getip=`wget -O- -q icanhazip.com`
elif test $(which dig); then
	getip=`dig +short myip.opendns.com @resolver1.opendns.com`
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
if [[ -z "$ports" ]]; then
	ports=(21 22 25 53 80 110 111 135 139 143 443 445 161 162 554 631 993 995 1030 1032 1033 1038 1433 1521 1723 2049 2100 3306 3339 3389 5432 5900 6379 8080 8443 9050)
elif [[ ! -z $(grep -i , <<< $ports) ]]; then # is this a comman-separated list of ports? 
	IFS=',' read -r -a ports <<< $ports # split comma-separated list into array for processing
elif [[ ! -z $(grep -i - <<< $ports) ]]; then # is this a range of ports?
	IFS='-' read start end <<< $ports
	ports=()
	i=$start
	while [ $i -le $end ]; do
		ports+=($i)
		let i=i+1
	done
fi

for host in $(cat /tmp/livehosts.txt);
do for port in ${ports[@]};
	do (echo >/dev/tcp/$host/$port) >& /dev/null && echo "$host:$port is open" &
        done;
done;
}

if [ "$ROOT_CHECK" = true ] && [ "$EUID" != 0 ]; then
	echo -ne "\n[-] ARP ping disabled as root may be required, --help for more information"
fi

if test ! $(which arping); then
	echo -ne "\n[+] Sweeping for live hosts (ICMP)\n"
elif test $(which arping); then
	echo -ne "\n[+] Sweeping for live hosts (ICMP + ARP)\n"
fi

pingsweep | sort -V | uniq > /tmp/livehosts.txt
count=`cat /tmp/livehosts.txt | wc -l`

echo -ne "[+] $count hosts found\n[+] Beginning port scan\n\n"
portscan | sort -V | uniq
