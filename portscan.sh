#!/bin/bash

readonly PROGNAME='portscan.sh'
readonly VERSION='0.0.5'

########################################
# help/usage 
########################################

usage() {
	clear
	printf "No nmap only bash /dev/tcp go brrrrrrrrrrrrrrrrr
Usage:  %s
	[ -b | --banner ]         Attempt to grab banner during port scanning
	[ -h | --help ]           Show this help message and exit.
	[ -p | --ports <PORTS> ]  Comma-separated list or range of integers up to 65535.
	[ -r | --root ]           Force ARP ping to run even if user doesn't have root privileges.
	[ -t | --top-ports <1+> ] Specify number of top TCP ports to scan (default = 20 )
	[ -T | --timing <0-6> ]   Timing template (default = 4)
	[ -v | --version ]        Print version and exit.
	<x.x.x.x>                 Target IP (optional)\n\n" $PROGNAME
	exit 0
}

########################################
# Import libraries
########################################

. $(pwd)/lib/args.sh
. $(pwd)/lib/validations.sh
. $(pwd)/lib/core.sh
. $(pwd)/lib/definitions.sh
# . $(pwd)/lib/tcp_ports.sh			# Commented out for HOTFIX -- array does not currently work when separated into its 									  own individual library. Placed port list back inside core.sh lib.

########################################
# Scanning functions
########################################

# Check single TARGET for response before port scanning
pingcheck(){
	TARGET=$1
	if [ "$SWEEP_METHOD" == "ICMP + ARP" ]; then
		arping -c 1 -w 1 -I $default_interface $TARGET 2>/dev/null | tr \\n " " | awk '/1 from/ {print $2}' &
	fi
	ping -c 1 -W 1 $TARGET | tr \\n " " | awk '/1 received/ {print $2}' &
}

# Ping multiple hosts
pingsweep(){
	for ip in {1..254}; do
		TARGET="$network.$ip"
		pingcheck "$TARGET"
	done;
}

# Get portscan results from array(s) and format in nmap-ish style
scanreport(){
	IFS=$'\n'
	sorted=($(sort -V <<< "${LIVEPORTS[*]}"))
	unset IFS
	for port in ${sorted[@]}; do
		service=$(cat lib/nmap-services | grep -w "${port}/tcp" | cut -d" " -f1)
		printf "%s\topen\t%s" $port $service
		if [ "$BANNER" = true ]; then
			printf " %s\n" "${BANNERS[$port]}"
		else
			printf "\n"
		fi
	done;
}

# Scan ports
portscan(){
	LIVEPORTS=()
	BANNERS=()
	for port in ${ports[@]}; do
		sleep $DELAY
		(echo >/dev/tcp/$host/$port) >& /dev/null && LIVEPORTS+=($port)
		if [ "$BANNER" = true ]; then
			BANNERS[$port]=$(banners $host $port 2>/dev/null)
		fi
	done;
	count_liveports=${#LIVEPORTS[@]}
}

# Single ping for custom target, otherwise sweep
if [ -n "$TARGET" ]; then
	LIVEHOSTS=($(pingcheck $TARGET | sort -V | uniq ))
else
	LIVEHOSTS=($(pingsweep | sort -V | uniq))
fi

if [ ${#LIVEHOSTS[@]} -ne 0 ]; then
	count=${#LIVEHOSTS[@]}
	if [ "$count" -gt 0 ]; then
		printf "[+] $count hosts found\n[+] Beginning scan of %s total port(s)\n\n" ${#ports[*]}
		portscan | sort -V | uniq
	fi
else
	printf "[+] No responsive hosts found\n\n"
fi

for host in ${LIVEHOSTS[@]}; do
	name=$(revdns $host)
	portscan $host
	printf "Scan report for %s (%s):\n" $name $host
	closed_ports=$((${#ports[@]}-$count_liveports))
	if [ "$closed_ports" -ne 0 ]; then
		printf "Not shown: %s closed port(s)\n" $closed_ports
	fi
	printf "PORT\tSTATE\tSERVICE\n"
	scanreport
	printf "\n"
done;