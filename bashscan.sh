#!/bin/bash

readonly PROGNAME='BashScan'
readonly VERSION='0.0.6'

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
	<x.x.x.x> OR <x.x.x.x-y>  Target IP (optional)\n\n" $PROGNAME
	exit 0
}


########################################
# Argument handling
########################################

PARSED_ARGUMENTS=$(getopt -n $PROGNAME \
	-a \
	-o bhp:rt:T:v \
	-l banner,help,ports:,root,timing:,top-ports:,version \
	-- "$@")
VALID_ARGUMENTS=$?

if [ "$VALID_ARGUMENTS" != "0" ]; then
  usage
fi

eval set -- "$PARSED_ARGUMENTS"
while [ $# -gt 0 ]; do
	case "$1" in
		-b | --banner) BANNER=true                          ; shift 1 ;;
		-p | --ports) ports="$2"                            ; shift 2 ;;
		-t | --top-ports) TOP_PORTS="$2"                    ; shift 2 ;;
		-T | --timing) TIMING="$2"                          ; shift 2 ;;
		-r | --root) ROOT_CHECK=false                       ; shift   ;; 
		-h | --help) usage                                  ; exit 0  ;;
		-v | --version) echo "$PROGNAME $VERSION"           ; exit 0  ;;
		--) shift; break;;
    	# If invalid options were passed, then getopt should have reported an error,
    	# which we checked as VALID_ARGUMENTS when getopt was called...
    	*) printf "Unexpected option: %s - this should not happen." $1
		usage ;;
	esac
done

#######################################
# Validation Functions
########################################

# Test an IP address for validity
# Credit: Mitch Frazier
# Reference: https://www.linuxjournal.com/content/validating-ip-address-bash-script
# Usage:
#      valid_ip IP_ADDRESS
#      if [[ $? -eq 0 ]]; then echo good; else echo bad; fi
#   OR
#      if valid_ip IP_ADDRESS; then echo good; else echo bad; fi
#
valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# Validate timing flag is in range
valid_timing(){
	if ! [ "$1" -eq "$1" ] 2>/dev/null; then
		usage
	elif (( "$1" < 0 || "$1" > 6)); then
		printf $TIMING
		usage
	fi
}

# Validate port inputs:
# Redirects to usage if port value is either not an integer or outside of 1-65535 range
isPort(){
	if ! [ "$1" -eq "$1" ] 2>/dev/null; then
		usage
	elif ! ((0 < "$1" && "$1" < 65536)); then
		usage
	fi
}

########################################
# Default values for the script options
########################################
: ${BANNER:=false}
: ${ROOT_CHECK:=true}
: ${TIMING:=4}
: ${TOP_PORTS:=20}

########################################
# Determine values in prep for scanning
########################################

max_num_processes=$(ulimit -u)
limiting_factor=4
num_processes=$((max_num_processes/limiting_factor))

valid_timing $TIMING

# If a single IP or range of IPs are supplied,
# check that addresses are valid and assign to 
# TARGET/TARGETS for later use
if [[ -n "$@" ]]; then
	TARGET=$@
	# If the input doesn't validate as an IP, 
	# check to see if a range was specified
	if	! valid_ip "$TARGET"; then
		# If there isn't a "-" in the input, something else 
		# is going on; treat as invalid
		if [[ -n "$(grep -i - <<< $@)" ]]; then
			IFS='-' read start end <<< $TARGET
			end=$(echo $start | cut -d"." -f1,2,3).$end
			# If the beginning and ending IPs specified are 
			# valid, assign all addresses in range to TARGETS array
			if valid_ip "$start" && valid_ip "$end"; then	
				TARGETS=()
				i=$(echo $start | cut -d"." -f4)
				end=$(echo $end | cut -d"." -f4)
				if [ $i -lt $end ]; then
					while [ $i -le $end ]; do
						ip=$(echo $start | cut -d"." -f1,2,3).$i
						TARGETS+=($ip)
						let i=i+1
					done
				else
					usage
				fi
			else
				usage
			fi
		else
			usage
		fi
	fi
fi

# determine default network interface
if test $(which route); then
	#Output of `route` should consistently show interface name as last field
	default_interface=$(route | grep '^default' | grep -o '[^ ]*$')
elif test $(which ip); then
	#FIXME: confirm that `ip route` field output is consistent across systems or use a different method
	default_interface=$(ip route show default | cut -d" " -f5) 
else 
	# fallback to reading interface name from /proc
	default_interface=$(cat /proc/net/dev | grep -v lo | cut -d$'\n' -f3 | cut -d":" -f1)
fi

# determine local IP and CIDR for default interface
if test $(which ip); then
	localaddr=$(ip -o -4 addr show $default_interface | tr -s " " | cut -d" " -f4)
	IFS=/ read localip netCIDR <<< $localaddr
elif test $(which ifconfig); then
    localaddr=$(ifconfig $default_interface | grep -Eo '(addr:)?([0-9]*\.){3}[0-9]*')
    localip=$(cut -d$'\n' -f1 <<< $localaddr)
    netmask=$(cut -d$'\n' -f2 <<< $localaddr)
    # ifconfig doesn't output CIDR, but we can calculate it from the netmask bits
    c=0 x=0$( printf '%o' "${netmask//./ }" )
    while [ $x -gt 0 ]; do
      	let c+=$((x%2)) 'x>>=1'
    done
    netCIDR=$c
else
    localip=$(hostname -I | cut -d" " -f1)
    # FIXME: in an edge case where neither ifconfig nor iproute2 utils are available
    #        need to get CIDR some other way
fi

## FIXME: these values for network and iprange are only valid for /24 CIDRs.
#         need to update the method if/when custom CIDRs are allowed
network=$(echo $localip | cut -d"." -f1,2,3)
iprange=$(echo $network".0/"$netCIDR)

# Determine external IP
# Try /dev/tcp method first
httpextip="icanhazip.com"
conn="'GET / HTTP/1.1\r\nhost: ' $httpextip '\r\n\r\n'"
response=$(timeout 0.5s bash -c "exec 3<>/dev/tcp/$httpextip/80; echo -e $conn>&3; cat<&3" | tail -1)

# If the above method fails, then fallback to builtin utils for this
if ! valid_ip response; then
	if test $(which curl); then
		getip=$(curl -s $httpextip) # whatismyip.akamai.com may be a consistently faster option
	elif test $(which wget); then
		getip=$(wget -O- -q $httpextip)
	elif test $(which dig); then
		getip=$(dig +short myip.opendns.com @resolver1.opendns.com)
	elif test $(which telnet); then
		getip=$(telnet telnetmyip.com 2>/dev/null | grep ^\"ip | cut -d"\"" -f4)
	elif test $(which ssh); then
		# Not usually a great idea to disable StrictHostKeyChecking, but
		# in this case, we aren't doing anything sensitive in the connection.
		# Leaving it enabled will prompt for confirming key on first connection,
		# rather than simply returning the output we want
		getip=$(ssh -o StrictHostKeyChecking=no sshmyip.com 2>/dev/null |  grep ^\"ip | cut -d"\"" -f4)
	else
		#We probably have enough methods above to make failure relatively unlikely.
		#So, if we reach this point, there may be no WAN connectivity.
		getip="Failed to determine. Host may not have external connectivity."
	fi
fi

printf "\nLocal IP:\t\t%s\n" $localip
printf "Netmask:\t\t%s\n" $iprange
printf "External IP:\t\t%s\n" $getip
printf "Default Interface:\t%s\n" $default_interface

if [ -n "$TARGET" ]; then
	printf "Target:\t\t\t%s\n" $TARGET
fi

# Port list
# Default: Subset of tcp_ports (list from nmap), as specified in $TOP_PORTS
# Custom:  User input from "-p | --ports" flags, either as a comma-separated list or a range
if [ -z "$ports" ]; then
	# TCP ports from the nmap database ordered by frequency of use, stored in nmap-services:
	# `cat /usr/share/nmap/nmap-services | grep "tcp" | sort -r -k3 | column -t | tr -s " "`
	tcp_ports=($(cat lib/nmap-services | cut -d" " -f2 | cut -d"/" -f1 | tr $'\n' " "))
	ports=(${tcp_ports[@]:0:$TOP_PORTS})
elif [[ -n "$(grep -i , <<< $ports)" ]]; then # is this a comma-separated list of ports? 
	IFS=',' read -r -a ports <<< $ports # split comma-separated list into array for processing
	for port in ${ports[@]}; do
		isPort $port
	done
elif [[ -n "$(grep -i - <<< $ports)" ]]; then # is this a range of ports?
	IFS='-' read start end <<< $ports
	# If all ports in specified range are valid, 
	# populate ports array with the full list
	isPort $start && isPort $end
	ports=()
	i=$start
	while [ $i -le $end ]; do
		ports+=($i)
		let i=i+1
	done
else
	isPort $ports
fi

# Try grabbing banners
banners(){
	host="$1"
	port="$2"
	# Trimmed out all but first line of response to clean up long http replies
	# Also removed trailing \r which is common in http responses
	banner=$(timeout 0.5s bash -c "exec 3<>/dev/tcp/$host/$port; echo "">&3; cat<&3" | grep -iav "mismatch" | cut -d$'\n' -f1 | tr "\\r" " ")
	if ! [ "$banner" = "" ]; then 
		echo "| "$banner 2>/dev/null
	fi
}

# Attempt reverse DNS resolution of target addresses
revdns(){
	ip=$1
	if test $(which dig); then
		name=$(dig +short +answer -x $ip | sed 's/.$//')
	elif test $(which nslookup); then
		name=$(nslookup $ip | cut -d$'\n' -f1 | grep -o '[^ ]*$' | sed 's/.$//')
	elif test $(which host); then
		name=$(host $ip | grep -o '[^ ]*$' | sed 's/.$//')
	fi

	if [ -n "$name" ]; then
		printf $name 2>/dev/null
	else
		printf "NXDOMAIN"
	fi
}

# Determine which pingsweep method(s) will be used
if test $(which arping); then
	if [ "$ROOT_CHECK" = true ] && [ "$EUID" != 0 ]; then
		printf "\n[-] ARP ping disabled as root may be required, [ -h | --help ] for more information"
		SWEEP_METHOD="ICMP"
	else
		SWEEP_METHOD="ICMP/ARP"
	fi
else
	SWEEP_METHOD="ICMP"
fi
printf "\n[+] Sweeping for live hosts (%s%s%s)\n" $SWEEP_METHOD

# Timing options (initially based on nmap Maximum TCP scan delay settings)
# nmap values are in milliseconds - converted here for bash sleep in seconds
case $TIMING in
	0 )	DELAY=300    ;;
	1 )	DELAY=15     ;;
	2 )	DELAY=1      ;;
	3 )	DELAY=.1     ;;
	4 )	DELAY=.010   ;;
	5 )	DELAY=.005   ;;
	6 )	DELAY=0      ;;
esac

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
	if [ -n "$TARGETS" ]; then
		for ip in ${TARGETS[@]}; do
			pingcheck "$ip"
		done;
	else
		for ip in {1..254}; do
			TARGET="$network.$ip"
			pingcheck "$TARGET"
		done;
	fi
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
	scan=""
	BANNERS=()
	for port in ${ports[@]}; do
		# Populate a '#'-delimited string of commands for input into 
		# ParallelExec function to increase performance
		scan+="sleep $DELAY; (echo >/dev/tcp/$host/$port) >& /dev/null#"
		# FIXME: Banner grabbing is still very slow
		if [ "$BANNER" = true ]; then
			BANNERS[$port]=$(banners $host $port 2>/dev/null)
		fi
	done;

	# Caveat: this function really speeds up the scans, but
	# it also somewhat breaks the Timing settings. Need more
	# thought on how best to implement timing in a parallelized 
	# workload. $num_processes is defined in core.sh, based on 
	# `ulimit -u` output, which is the max number of processes
	# a given user can instantiate
	LIVEPORTS=( $(ParallelExec "$num_processes" "$scan"))
	count_liveports=${#LIVEPORTS[@]}
}

########################################
# Peformance function
########################################

# Take a list of commands to run, runs them sequentially with numberOfProcesses commands simultaneously runs
function ParallelExec {
    local numberOfProcesses="${1}" 	# Number of simultaneous commands to run
    local commandsArg="${2}" 		# '#' delimited list of commands

    local pid
    local runningPids=0
    local counter=0
    local commandsArray
    local pidsArray
    local newPidsArray
    local retval
    local pidState
    local commandsArrayPid

    IFS='#' read -r -a commandsArray <<< "$commandsArg"

    while [ $counter -lt "${#commandsArray[@]}" ] || [ ${#pidsArray[@]} -gt 0 ]; do
        while [ $counter -lt "${#commandsArray[@]}" ] && [ ${#pidsArray[@]} -lt $numberOfProcesses ]; do
            eval ${commandsArray[$counter]} &
            pid=$!
            pidsArray+=($pid)
            commandsArrayPid[$pid]="${commandsArray[$counter]}"
            counter=$((counter+1))
        done

        newPidsArray=()
        for pid in "${pidsArray[@]}"; do
            # Handle uninterruptible sleep state or zombies by ommiting them from running process array (How to kill that is already dead ? :)
            if kill -0 $pid > /dev/null 2>&1; then
                pidState=$(ps -p$pid -o state= 2 > /dev/null)
                if [ "$pidState" != "D" ] && [ "$pidState" != "Z" ]; then
                    newPidsArray+=($pid)
                fi
            else
                # pid is dead, get it's exit code from wait command
                wait $pid
                retval=$?
                # this is specific to the portscan function input;
                # an improvement would be to generalize the return
                # for use in parallelizing multiple different inputs
                if [ "$retval" -eq 0 ]; then
                	printf "$(echo ${commandsArrayPid[$pid]} | cut -d"/" -f5 | cut -d")" -f1) "
                fi
            fi
        done
        pidsArray=("${newPidsArray[@]}")

        # Add a trivial sleep time so bash won't eat all CPU
        sleep .05
    done
}

########################################
# Main function
########################################

# Single ping for custom target, otherwise sweep
if [ -n "$TARGET" ] && [ -z "$TARGETS" ]; then
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