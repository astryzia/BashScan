########################################
# Utility functions
########################################

ip2int(){
    local a b c d
    { IFS=. read a b c d; } <<< $1
    echo $(((((((a << 8) | b) << 8) | c) << 8) | d))
}

int2ip(){
    local ui32=$1
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
	local ip=""
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

parse_octet(){
    local octet=$1
    if [[ -n "$(grep -i - <<< $octet)" ]]; then
        IFS='-' read start_octet end_octet <<< $octet
        if (( "$start_octet" < 255 )) && (( "$end_octet" <= 255 )) && [ "$start_octet" -lt "$end_octet" ]; then
            printf "$(seq $start_octet $end_octet)"
        fi
    else
    	# If input isn't range, print if it is an integer
        if [ "$1" -eq "$1" ] 2>/dev/null; then
        	printf "$octet"
        fi
    fi
}

populate_targets(){
# Global target value set in core.sh
# set local to avoid clobbering
local TARGET=$1
local list_type=$2
local valid_targets

# If there is a "-" in input, treat as IP range
if [[ -n "$(grep -i - <<< $TARGET)" ]]; then
	IFS=. read o1 o2 o3 o4 <<< $TARGET
	# There probably isn't a need to scan class d/e 
	# networks, so we could cap the 1st octet at 223;
	# For the sake of simplicity, we use the same 
	# validation check in all 4 octets, with max=255
	oct1=("$(parse_octet $o1)")
	oct2=("$(parse_octet $o2)")
	oct3=("$(parse_octet $o3)")
	oct4=("$(parse_octet $o4)")

	if [[ -z ${oct1[*]} ]] || [[ -z ${oct2[*]} ]] || [[ -z ${oct3[*]} ]] || [[ -z ${oct4[*]} ]]; then
		if [[ -z "$i_file" ]]; then usage; fi
	else
		for a in $oct1; do
			for b in $oct2; do
				for c in $oct3; do
					for d in $oct4; do
						valid_targets+=("$a"."$b"."$c"."$d")
					done
				done
			done
		done
	fi
# If there is a "/" in the input, treat as CIDR
elif [[ -n "$(grep -i / <<< $TARGET)" ]]; then
	# Sanity check base IP specified is valid
	if ! valid_ip "${TARGET%/*}"; then
		if [[ -z "$i_file" ]]; then usage; fi
	else
		valid_targets+=($(cidr2ip $TARGET))
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
		valid_targets+="$check_hostname"
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

	limit="0.5s"
	service=$(cat lib/nmap-services | grep -w "${port}/tcp" | cut -d" " -f1)
    
	# Eventually, this case statement may scale to a 
	# point where a different approach is more readable; 
	# For now, this should work as a poc. 
	case $service in
		# For http services, we usually need to echo in
		# a formatted request in order to get a server
		# banner in response; 
		"http" | "http-proxy" |  "http-alt" )
			conn="'HEAD / HTTP/1.1\r\nhost: ' $host '\r\n\r\n'"
			banner=$(timeout 0.5s bash -c "exec 3<>/dev/tcp/$host/$port; echo -e $conn>&3; cat<&3" | grep -i "server:" | cut -d" " -f2-)
			;;
		# Our script host may not have OpenSSL library available,
		# but handling a TLS connection in pure BASH is a 
		# rather steep hill to climb for now;
		# We can also grab the server cert here and add it 
		# to the output if that is desired.
		"https" | "https-alt" )
			conn="'HEAD / HTTP/1.1\r\nhost: ' $host '\r\n\r\n'"
			banner=$(timeout $limit bash -c "echo -ne $conn | openssl s_client -quiet -connect $host:$port 2>/dev/null" | grep -i "server:" | cut -d" " -f2-)
			;;
		"smtps" | "submission" | "pop3s" )
			conn=""
			banner=$(timeout $limit bash -c "echo -ne $conn | openssl s_client -quiet -connect $host:$port 2>/dev/null" | head -n 1)
			;;
		# DNS servers don't have banners per se, but we can
		# attempt to fingerprint. This is very basic, but can
		# get more complex if we go into more fingerprinting
		"domain" )
			banner=$(dig version.bind CHAOS TXT @$host 2>/dev/null | grep ^version.bind | cut -d$'\t' -f6)
		;;
		*)
			conn=""
			banner=$(timeout $limit bash -c "exec 3<>/dev/tcp/$host/$port; echo -e $conn>&3; cat<&3" | grep -iav "mismatch" | cut -d$'\n' -f1 | tr "\\r" " ")
			;;
	esac

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

	num_targets="${#TARGETS[@]}"

	if [[ "$DO_PING" = true ]]; then
		if [ "$arp_warning" = true ]; then
			printf "\n[-] ARP ping disabled as root may be required, [ -h | --help ] for more information"
		fi
		printf "\n[+] Sweeping %s %s for live hosts (%s%s%s)\n" $num_targets $(plural $num_targets "target") $SWEEP_METHOD

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
