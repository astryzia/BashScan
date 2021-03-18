
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