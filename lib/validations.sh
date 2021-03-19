
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
    # validates integer
	if ! [ "$1" -eq "$1" ] 2>/dev/null; then
		usage
    # tcp/0 is valid
	elif ! ((0 <= "$1" && "$1" <= 65535)); then
		usage
	fi
}
