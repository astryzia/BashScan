
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

# Scan ports
portscan(){
	scan=""
	BANNERS=()
	for port in ${ports[@]}; do
		# Populate a '#'-delimited string of commands for input into 
		# ParallelExec function to increase performance
		scan+="sleep $DELAY; (echo >/dev/tcp/$host/$port) >& /dev/null#"
	done;

	# Caveat: this function really speeds up the scans, but
	# it also somewhat breaks the Timing settings. Need more
	# thought on how best to implement timing in a parallelized 
	# workload. $num_processes is defined in core.sh, based on 
	# `ulimit -u` output, which is the max number of processes
	# a given user can instantiate
	LIVEPORTS=( $(ParallelExec "$num_processes" "$scan"))
	count_liveports=${#LIVEPORTS[@]}

	# Do this only for live ports to save time
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

normal_output(){
	printf "Scan report for %s (%s):\n" $name $host
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

main(){
	printf "\nLocal IP:\t\t%s\n" $localip
	printf "Netmask:\t\t%s\n" $iprange
	printf "External IP:\t\t%s\n" $getip
	printf "Default Interface:\t%s\n" $default_interface

	if [ -n "$TARGET" ]; then
		printf "Target:\t\t\t%s\n" $TARGET
	fi

	if [ "$arp_warning" = true ]; then
		printf "\n[-] ARP ping disabled as root may be required, [ -h | --help ] for more information"
	fi

	printf "\n[+] Sweeping for live hosts (%s%s%s)\n" $SWEEP_METHOD

	# Single ping for custom target, otherwise sweep
	if [ -n "$TARGET" ] && [ -z "$TARGETS" ]; then
		LIVEHOSTS=($(pingcheck $TARGET | sort -V | uniq ))
	else
		LIVEHOSTS=($(pingsweep | sort -V | uniq))
	fi

	num_hosts=${#LIVEHOSTS[@]}

	if [ "$num_hosts" -gt 0 ]; then
		printf "[+] $num_hosts %s found\n[+] Beginning scan of %s total %s\n\n" $(plural $num_hosts host) $num_ports $(plural $num_ports port)
		portscan | sort -V | uniq
	else
		printf "[+] No responsive hosts found\n\n"
	fi

	datestart_file=$(date --date @"$(( $START / 1000000000 ))" "+%c")
	file_header="$(printf "%s %s scan initiated %s as: %s" $PROGNAME $VERSION "$datestart_file" "$invoked")"

	# File header
	if [[ -n "$n_file" ]]; then
		printf "# %s\n" "$file_header" >> $n_file
	elif [[ -n "$g_file" ]]; then
		printf "# %s\n" "$file_header" >> $g_file
	fi

	for host in ${LIVEHOSTS[@]}; do
		name=$(revdns $host)
		portscan $host
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
	done;

	TZ=$(date +%Z)
	END=$(date +%s%N)
	runtime=$(( $END - $START ))
	# inconsistent results when timezone is not specified
	runtime_stdout=$(TZ=$TZ date -d @"$(( runtime / 1000000000 ))" +%T)
	end_file=$(date -d @"$(( $END / 1000000000 ))" +%c)

	printf "%s done: %s %s scanned in %s\n" $PROGNAME $num_hosts $(plural $num_hosts host) $runtime_stdout
	
	# File footer
	if [[ -n "$n_file" ]]; then
		printf "# %s done at %s -- %s %s scanned in %s" $PROGNAME "$end_file" $num_hosts $(plural $num_hosts host) "$runtime_stdout" >> $n_file
	elif [[ -n "$g_file" ]]; then
		printf "# %s done at %s -- %s %s scanned in %s" $PROGNAME "$end_file" $num_hosts $(plural $num_hosts host) "$runtime_stdout" >> $g_file
	fi
}