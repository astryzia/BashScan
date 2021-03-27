#!/bin/bash

# Capture script invocation for use in file output
invoked="$(printf %q "$BASH_SOURCE")$((($#)) && printf ' %q' "$@")"
START_SCRIPT=$(date +%s%3N)
start_stdout=$(date --date @"$(( $START_SCRIPT / 1000 ))" "+%Y-%m-%d %H:%M:%S %Z")

readonly PROGNAME='BashScan'
readonly VERSION='0.0.6'
readonly URL='https://github.com/astryzia/BashScan'

printf "Starting %s %s ( %s ) at %s\n" "$PROGNAME" "$VERSION" "$URL" "$start_stdout"

########################################
# help/usage 
########################################

usage() {
	clear
	printf "No nmap only bash /dev/tcp go brrrrrrrrrrrrrrrrr
Usage:  %s
	[ -b | --banner ]         Attempt to grab banner during port scanning
	[ -e | --exclude ]        Exclude targets from scan
	[ -h | --help ]           Show this help message and exit.
	[ -o | --open ]           Only show targets with open ports
	[ -p | --ports <PORTS> ]  Comma-separated list or range of integers up to 65535.
	[ -r | --root ]           Force ARP ping to run even if user doesn't have root privileges.
	[ -t | --top-ports <1+> ] Specify number of top TCP ports to scan (default = 20 )
	[ -T | --timing <0-6> ]   Timing template (default = 4)
	[ -v | --version ]        Print version and exit.
	[ -iL <file> ]            Add list of targets from input file
	[ -xL <file> ]            Exclude list of targets from input file
	[ -oN <file> ]            Normal output: similar to interactive output
	[ -oG <file> ]            Grepable output: comma-delimited, each host on a single line
	[ -Pn ]                   No ping; Skip host discovery and go directly to port scanning
	<x.x.x.[x|x-y|x/24]>      Target IP (optional), as single, range, or CIDR\n\n" $PROGNAME
	exit 0
}


########################################
# Argument handling
########################################

PARSED_ARGUMENTS=$(getopt -n $PROGNAME \
	-a \
	-o be:hop:rt:T:v \
	-l banner,exclude:,help,iL:,xL:,oG:,oN:,Pn,open,ports:,root,timing:,top-ports:,version \
	-- "$@")
VALID_ARGUMENTS=$?

if [ "$VALID_ARGUMENTS" != "0" ]; then
  usage
fi

# Aligning flags with nmap syntax where possible to flatten the
# learning curve. Note: the "-a" option above allows use of
# a single dash for "long" options in addition to double dash; 
# since getopt doesn't support a multi-char "short" option, this 
# is one workaround for double letter flags (-iL/-oN/-oG, etc.). 
# In cases where the "short" options for output aren't used 
# (no associated chars in the "-o" string above), we use placeholder
# chars, like "~". 
eval set -- "$PARSED_ARGUMENTS"
while [ $# -gt 0 ]; do
	case "$1" in
		-b  | --banner      ) BANNER=true               ; shift 1 ;;
		-e  | --exclude     ) exclude="$2"              ; shift 2 ;;
		-~  | --iL          ) i_file="$2"               ; shift 2 ;;
		-~  | --xL          ) x_file="$2"               ; shift 2 ;;
		-~  | --oG          ) g_file="$2"               ; shift 2 ;; 
		-~  | --oN          ) n_file="$2"               ; shift 2 ;;
		-~  | --Pn          ) DO_PING=false             ; shift 1 ;;
		-o  | --open        ) OPEN=true                 ; shift 1 ;;
		-p  | --ports       ) ports="$2"                ; shift 2 ;;
		-t  | --top-ports   ) TOP_PORTS="$2"            ; shift 2 ;;
		-T  | --timing      ) TIMING="$2"               ; shift 2 ;;
		-r  | --root        ) ROOT_CHECK=false          ; shift   ;; 
		-h  | --help        ) usage                     ; exit 0  ;;
		-v  | --version     ) echo "$PROGNAME $VERSION"	; exit 0  ;;
		--                  ) shift; break;;
    	# If invalid options were passed, then getopt should have reported an error,
    	# which we checked as VALID_ARGUMENTS when getopt was called...
    	*                   ) printf "Unexpected option: %s - this should not happen." $1
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
valid_ip(){
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
valid_port(){
    # validates integer
	if ! [ "$1" -eq "$1" ] 2>/dev/null; then
		usage
    # tcp/0 is valid
	elif ! ((0 <= "$1" && "$1" <= 65535)); then
		usage
	fi
}
########################################
# Utility functions
########################################

ip2int(){
    local a b c d
    { IFS=. read a b c d; } <<< $1
    echo $(((((((a << 8) | b) << 8) | c) << 8) | d))
}

int2ip(){
    local ui32=$1; shift
    local ip n
    for n in 1 2 3 4; do
        ip=$((ui32 & 0xff))${ip:+.}$ip
        ui32=$((ui32 >> 8))
    done
    echo $ip
}

# Takes as input IP + CIDR (ex: 192.168.1.0/24)
# Converts CIDR to list of IPs
# Limited to /8 max 
cidr2ip() {
	local base=${1%/*}
	local masksize=${1#*/}

	local mask=$(( 0xFFFFFFFF << (32 - $masksize) ))

	[ $masksize -lt 8 ] && { echo "Max range is /8."; exit 1;}
	OIFS=$IFS
	IFS=. read a b c d <<< $base
	IFS=$OIFS

	local ip=$(( ($b << 16) + ($c << 8) + $d ))
	local ipstart=$(( $ip & $mask ))
	local ipend=$(( ($ipstart | ~$mask ) & 0x7FFFFFFF ))

	seq $ipstart $ipend | while read i; do
    	printf "$a.$(( ($i & 0xFF0000) >> 16 )).$(( ($i & 0xFF00) >> 8 )).$(( $i & 0x00FF )) "
	done 
}

# Example: cidr2netmask 24 => 255.255.255.0
cidr2netmask(){
    local mask=$((0xffffffff << (32 - $1))); shift
    int2ip $mask
}

# Example: cidr2network 192.168.19.24 16 => 192.168.0.0
cidr2network(){
    local addr=$(ip2int $1)
    local mask=$((0xffffffff << (32 -$2)))
    int2ip $((addr & mask))
}

# Input: hostname
# Output: IP
resolve_host(){
	local ip 
	local host=$1
	if test $(which dig); then
		ip=$(dig +search +short $host)
	elif test $(which nslookup); then
		ip=$(nslookup -type=A $host | grep -A 1 Name | cut -d$'\n' -f2 | cut -d" " -f2)
	elif test $(which host); then
		ip=$(host -t A $host | grep -iav "not found" | rev | cut -d" " -f1 | rev)
	fi

	printf "$ip"
}

populate_targets(){
# Global target value set in core.sh
# set local to avoid clobbering
local TARGET=$1
local list_type=$2
local valid_targets

# If there is a "-" in input, treat as IP range
# FIXME: currently only handles 4th octet;
#        add support for ranges in all 4 octets
if [[ -n "$(grep -i - <<< $TARGET)" ]]; then
	IFS='-' read start_ip end_oct4 <<< $TARGET
	network=$(echo $start_ip | cut -d"." -f1,2,3)
	end_ip=$network.$end_oct4
	start_oct4=$(echo $start_ip | cut -d"." -f4)
	# If the beginning and ending IPs specified are 
	# valid, assign all addresses in range to TARGETS array
	if valid_ip "$start_ip" && valid_ip "$end_ip"; then	
		if [[ "$start_oct4" -lt "$end_oct4" ]]; then
			for oct4 in $(seq $start_oct4 $end_oct4); do
				valid_targets+=("$network.$oct4")
			done
		else
			if [[ -z "$i_file" ]]; then usage; fi
		fi
	else
		if [[ -z "$i_file" ]]; then usage; fi
	fi
# If there is a "/" in the input, treat as CIDR
elif [[ -n "$(grep -i / <<< $TARGET)" ]]; then
	# Sanity check base IP specified is valid
	if ! valid_ip "${TARGET%/*}"; then
		if [[ -z "$i_file" ]]; then usage; fi
	else
		valid_targets+=("$(cidr2ip $TARGET)")
	fi
# Comma-separated list?
elif  [[ -n "$(grep -i , <<< $TARGET)" ]]; then
	read -d ',' -a comma_targets <<< "$TARGET" 
	for comma_target in ${comma_targets[@]}; do
		if valid_ip $comma_target; then
			valid_targets+=($comma_target)
		fi
	done
else
	# Is this a valid hostname?
	check_hostname=$(resolve_host $TARGET)
	if valid_ip $check_hostname; then
		TARGET="$check_hostname"
	elif valid_ip $TARGET; then
		valid_targets+=("$TARGET")
	# If all checks above fail, treat as invalid input
	else
		if [[ -z "$i_file" ]]; then usage; fi
	fi
fi

# Copy local array to the appropriate glob, 
# depending on whether we're adding or excluding
if [[ "$list_type" == "add" ]]; then
	TARGETS+=("${valid_targets[@]}")
elif [[ "$list_type" == "exclude" ]]; then
	EXCLUSIONS+=("${valid_targets[@]}")
fi
}

########################################
# Scanning functions
########################################

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

# Ping each host in global TARGETS array
pingsweep(){
	for ip in ${TARGETS[@]}; do
		if [ "$SWEEP_METHOD" == "ICMP + ARP" ]; then
			arping -c 1 -w 1 -I $default_interface $ip 2>/dev/null | tr \\n " " | awk '/1 from/ {print $2}' &
		fi
		# Added stderr redirection to catch ping warning for broadcast address
		# Adding "-b" would enable pinging broadcast, but I doubt that's what we want
		ping -c 1 -W 1 $ip 2>/dev/null | tr \\n " " | awk '/1 received/ {print $2}' &
	done
}

# Avg round trip time to target in seconds
# Note: ICMP latency is going to be different than
#       TCP latency, but this is a workable starting point
latency(){
	# Any interval shorter than 200 milliseconds is considered 
	# a "ping flood" and requires root privileges. 
	ms="$(ping -c 3 -i 0.2 $1 | tail -1 | grep rtt | cut -d"/" -f5)"
	if [[ -n "$ms" ]]; then
		printf "0"$( echo "scale=5; (( $ms / 1000 ))" | bc )
	else
		printf ""
	fi
}

# Scan ports
portscan(){
	scan=""
	BANNERS=()
	for port in ${ports[@]}; do
		# Populate a '#'-delimited string of commands for input into 
		# ParallelExec function to increase performance
		scan+="sleep $DELAY; (echo >/dev/tcp/$host/$port) >& /dev/null#"
	done;

	# FIXME: ParallelExec really speeds up the scans, but
	# it also somewhat breaks the Timing settings. Need more
	# thought on how best to implement timing in a parallelized 
	# workload. $num_processes is defined in core.sh, based on 
	# `ulimit -u` output, which is the max number of processes
	# a given user can instantiate
	LIVEPORTS=( $(ParallelExec "$num_processes" "$scan"))
	count_liveports=${#LIVEPORTS[@]}

	# Grab banners only for live ports to save time
	# Not currently parallel - consider adding for perf increase
	if [ "$BANNER" = true ]; then
		for port in ${LIVEPORTS[@]}; do
			BANNERS[$port]=$(banners $host $port 2>/dev/null)
		done;
	fi
}

########################################
# Reporting functions
########################################

grepable_output(){
	closed_ports=$(($num_ports-$count_liveports))
	printf "Host: %s (%s)\t" $name $host
	printf "Ports:"
	IFS=$'\n'
	sorted=($(sort -V <<< "${LIVEPORTS[*]}"))
	unset IFS
	for port in ${sorted[@]}; do
		service=$(cat lib/nmap-services | grep -w "${port}/tcp" | cut -d" " -f1)
		printf " %s/open/%s" $port $service
		# FIXME: Banner reporting needs work
		#if [ "$BANNER" = true ]; then
		#	printf "/%s" "${BANNERS[$port]}"
		#fi
		printf ","
	done;
	printf "\tIgnored State: closed (%s)\n" $closed_ports
}

normal_output(){
	printf "Scan report for %s (%s):\n" $name $host

	# If we have a latency value, host is up
	if [[ -n "$latency" ]]; then
		printf "Host is up (%ss latency)\n" $latency
	# Only report down if we haven't disabled ping
	elif [[ "$DO_PING" = true ]]; then
		printf "Host seems down\n"
	fi

	closed_ports=$(($num_ports-$count_liveports))
	if [ "$closed_ports" -lt "$num_ports" ]; then
		if [ "$closed_ports" -gt 0 ]; then
			printf "Not shown: %s closed %s\n" $closed_ports $(plural $closed_ports port)
		fi
		printf "PORT\tSTATE\tSERVICE\n"
		IFS=$'\n'
		sorted=($(sort -V <<< "${LIVEPORTS[*]}"))
		unset IFS
		for port in ${sorted[@]}; do
			service=$(cat lib/nmap-services | grep -w "${port}/tcp" | cut -d" " -f1)
			printf "%s\topen\t%s" $port $service
			if [ "$BANNER" = true ]; then
				printf " %s" "${BANNERS[$port]}"
			fi
			printf "\n"
		done;
	else
		if [ "$num_ports" -gt 1 ]; then
			printf "All %s scanned %s on %s (%s) are closed\n" $num_ports $(plural $num_ports port) $name $host
		else
			printf "PORT\tSTATE\tSERVICE\n"
			printf "%s\tclosed\t%s\n" ${ports[@]} $(cat lib/nmap-services | grep -w "${ports[@]}/tcp" | cut -d" " -f1)
		fi
	fi
	
	printf "\n"
}

# Handle purality of strings in reporting
plural(){
	num=$1
	text=$2
	if [ "$num" == 1 ]; then
		printf "%s" $text
	else
		printf "%ss" $text
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

########################################
# Peformance function
########################################

# Take a list of commands to run, runs them sequentially with numberOfProcesses commands simultaneously runs
ParallelExec() {
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

main(){
	printf "\nLocal IP:\t\t%s\n" $localip
	printf "Netmask:\t\t%s\n" $iprange
	printf "External IP:\t\t%s\n" $getip
	printf "Default Interface:\t%s\n" $default_interface

	if [ -n "$TARGET" ]; then
		printf "Target:\t\t\t%s\n" "$TARGET"
	fi

	# If user hasn't supplied any targets, handle default
	# case by assigning localip range to TARGETS array
	# NOTE: test for $i_file to avoid rolling into a default
	#       network scan in cases where the input file 
	#       contained no valid/live hosts
	if [[ -z "$TARGETS" ]] && [[ -z "$i_file" ]]; then
		TARGETS+=($(cidr2ip "$localip/$netCIDR"))
	fi

	if [[ "$DO_PING" = true ]]; then
		if [ "$arp_warning" = true ]; then
			printf "\n[-] ARP ping disabled as root may be required, [ -h | --help ] for more information"
		fi
		printf "\n[+] Sweeping for live hosts (%s%s%s)\n" $SWEEP_METHOD

		LIVEHOSTS=($(pingsweep | sort -V | uniq))
	else
		# In this case, we aren't pinging to populate a list
		# of "live" hosts... just copy the TARGETS array to
		# LIVEHOSTS and start port scanning that.
		printf "\n[-] Host discovery disabled\n"
		#printf "[*] Warning: This can potentially be very slow over large ranges of targets/ports\n"
		#printf "[*] Note: Output for hosts with no open ports can be disabled with [ -o | --open ]\n"
		LIVEHOSTS+=("${TARGETS[@]}")
	fi

	num_hosts=${#LIVEHOSTS[@]}

	if [ "$num_hosts" -eq 0 ]; then
		printf "[+] No responsive hosts found\n\n"
	else
		# Adjust stdout verbiage depending on whether host
		# discovery is enabled or disabled
		if [[ "$DO_PING" = true ]]; then
			printf "[+] $num_hosts %s found\n" $(plural $num_hosts host) 
		fi
			printf "[+] Beginning scan of %s %s on %s %s\n\n" $num_ports $(plural $num_ports "port") $num_hosts $(plural $num_hosts "target")
			portscan | sort -V | uniq
		
	fi

	datestart_file=$(date --date @"$(( $START_SCRIPT / 1000 ))" "+%c")
	file_header="$(printf "%s %s scan initiated %s as: %s" $PROGNAME $VERSION "$datestart_file" "$invoked")"

	# File header
	if [[ -n "$n_file" ]]; then
		printf "# %s\n" "$file_header" >> $n_file
	elif [[ -n "$g_file" ]]; then
		printf "# %s\n" "$file_header" >> $g_file
	fi

	for host in ${LIVEHOSTS[@]}; do
		name=$(revdns $host)
		# Usually, the only reason ping will be disabled is because
		# ICMP is being dropped/blocked. In this case, our latency
		# method won't work either, so only attempt latency measure
		# if we can ping. 
		if [[ "$DO_PING" = true ]]; then
			latency="$(latency $host)"
		fi
		portscan $host

		# If we specify -o flag, only print results if one or more
		# ports are found to be open
		if ([[ "$OPEN" = true ]] && [[ "$count_liveports" > 0 ]]) || [[ "$OPEN" = false ]]; then
			normal_output # print to stdout

			# If an output file is specified, also write to that
			# FIXME: very basic output implementation... need handling for:
			#		 file already exists - prompt for overwrite?
			# 		 specified path doesn't exist
			#		 path exists, but we don't have write permissions
			if [[ -n "$n_file" ]]; then
				# FIXME: output assumes tab width of 8 for alignment;
				#		 expand tabs to spaces for consistent display?
				normal_output >> $n_file
			elif [[ -n "$g_file" ]]; then
				# FIXME: banner reporting in grepable format needs work
				grepable_output >> $g_file
			fi
		fi
	done;

	TZ=$(date +%Z)
	END_SCAN=$(date +%s%3N)
	# adding a leading "0" to fix parsing issues for sub-1 second runs
	runtime="0"$( echo "scale=3; ((($END_SCAN - $START_SCRIPT))/1000)" | bc )
	# inconsistent results when timezone is not specified
	runtime_stdout=$(TZ=$TZ date -d @"$runtime" +%H:%M:%S.%3N)
	end_file=$(date -d @"$(( $END_SCAN / 1000 ))" +%c)

	printf "%s done: %s %s scanned in %s\n" $PROGNAME $num_hosts $(plural $num_hosts host) $runtime_stdout
	
	# File footer
	if [[ -n "$n_file" ]]; then
		printf "# %s done at %s -- %s %s scanned in %s" $PROGNAME "$end_file" $num_hosts $(plural $num_hosts host) "$runtime_stdout" >> $n_file
	elif [[ -n "$g_file" ]]; then
		printf "# %s done at %s -- %s %s scanned in %s" $PROGNAME "$end_file" $num_hosts $(plural $num_hosts host) "$runtime_stdout" >> $g_file
	fi
}
########################################
# Default values for the script options
########################################
: ${BANNER:=false}
: ${ROOT_CHECK:=true}
: ${TIMING:=4}
: ${TOP_PORTS:=20}
: ${OPEN:=false}
: ${DO_PING:=true}

########################################
# Determine values in prep for scanning
########################################

# Find max processes the user can instantiate, 
# and set a cap for use in parallel execution;
# `ulimit` should be a bash built-in, so hopefully
# no need to check that it exist or use alternatives 
max_num_processes=$(ulimit -u)
limiting_factor=4 # this is somewhat arbitrary, but seems to work fine
num_processes=$((max_num_processes/limiting_factor))

# Validate the supplied timing option
valid_timing $TIMING

# If there is remaining input not handled by a flag,
# this *should* be either a:
# 		* Hostname
#		* Single IP
# 		* IP Range
# 		* IP + CIDR
# Check validity and populate target list
if [[ -n "$@" ]]; then
	TARGET=$@
	populate_targets $TARGET "add"
fi

# If an input file was specified, pass that list
# into populate_targets function. Here, we want to 
# append to any host(s) provided as inputs on the 
# command line; later, we can add an exclusion flag
# to use either the cli input or the file input to
# remove targets from the list, rather than adding

# Input format: this should gracefully accept:
# * hosts on separate lines
# * comma-delimited or space-delimited list of hosts
# * mixed types of input (single host, lists, ranges, CIDR)
if [[ -n "$i_file" ]]; then
	# Since target file could potentially contain several
	# thousand IPs, just use the file name as the target
	# for reporting 
	TARGET+=" + $i_file"
	OIFS=$IFS
	IFS=$'\n'
	read -d '' -r -a file_targets < $i_file
	IFS=$OIFS
	for file_target in ${file_targets[@]}; do
		if valid_ip "$file_target"; then
			TARGETS+=($file_target)
		else
			populate_targets $file_target "add"
		fi
	done
fi

# After we've added valid targets to our array, 
# check to see if we have any exclusions specified.
# Remove any matching exclusions from the target list.
# We don't *need* to validate the exclusions as IPs, 
# since any that fail to match a host in our target 
# list simply get no further processing. However, 
# passing the exclusions through populate_targets 
# allows us to consistently expand ranges, CIDRs, etc.
# the same way we do for adding targets. 
if [[ -n "$exclude" ]]; then
	populate_targets $exclude "exclude"
fi

# In addition to exclusion via direct input on cli,
# we can accept a list of hosts in file input for 
# exclusion.
if [[ -n "$x_file" ]]; then
	OIFS=$IFS
	IFS=$'\n'
	read -d '' -r -a exclusion_targets < $x_file
	IFS=$OIFS
	for exclusion_target in ${exclusion_targets[@]}; do
		if valid_ip "$exclusion_target"; then
			EXCLUSIONS+=($exclusion_target)
		else
			populate_targets $exclusion_targets "exclude"
		fi
	done
fi

# After exclusions from cli and file inputs are 
# processed, modify the TARGETS array, removing
# any matches
for exclusion in ${EXCLUSIONS[@]}; do
	TARGETS=( ${TARGETS[@]/$exclusion} )
done

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
	network=$(cidr2network $localip $netCIDR)
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
    network=$(cidr2network $localip $netCIDR)
else
    localip=$(hostname -I | cut -d" " -f1)
    # FIXME: in an edge case where neither ifconfig nor iproute2 utils are available
    #        need to get CIDR/netmask some other way
fi

iprange=$(printf %s/%s $network $netCIDR)

# Determine external IP
# Try /dev/tcp method first
httpextip="icanhazip.com"
conn="'GET / HTTP/1.1\r\nhost: ' $httpextip '\r\n\r\n'"
response=$(timeout 0.5s bash -c "exec 3<>/dev/tcp/$httpextip/80; echo -e $conn>&3; cat<&3" | tail -1)

# If the above method fails, then fallback to builtin utils for this
if valid_ip response; then
	getip=$reponse
else
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
		valid_port $port
	done
elif [[ -n "$(grep -i - <<< $ports)" ]]; then # is this a range of ports?
	# Treat "-p-" case as a request for all ports
	if [[ "$ports" == "-" ]]; then
		ports=( $(seq 0 65535) )
	else
		IFS='-' read start_port end_port <<< $ports
		# If all ports in specified range are valid, 
		# populate ports array with the full list
		valid_port $start_port && valid_port $end_port
		ports=( $(seq $start_port $end_port ))
	fi
else
	valid_port $ports
fi

num_ports=${#ports[@]}

# Determine which pingsweep method(s) will be used
if test $(which arping); then
	if [ "$ROOT_CHECK" = true ] && [ "$EUID" != 0 ]; then
		arp_warning=true
		SWEEP_METHOD="ICMP"
	else
		SWEEP_METHOD="ICMP/ARP"
	fi
else
	SWEEP_METHOD="ICMP"
fi

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

main
