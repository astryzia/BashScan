#!/bin/bash

########################################
# color/stylization 
########################################

reset="\e[0m"

# colors
cyan="\e[96m"
magenta="\e[95m"
red="\e[91m"
green="\e[92m"
blue="\e[94m"

# styles
bold="\e[1m"
dim="\e[2m"
inverted="\e[7m"
underline="\e[4m"
blink="\e[5m"

########################################
# dependencies
########################################

if test ! $(which bc); then
	echo $grn "* Installing dependencies" $white
	sudo apt -y -qq install bc arping > /dev/null 2>&1;
fi

########################################
# init
########################################

# Capture script invocation for use in file output
invoked="$(printf %q "$BASH_SOURCE")$((($#)) && printf ' %q' "$@")"
START_SCRIPT=$(date +%s%3N)
start_stdout=$(date --date @"$(( $START_SCRIPT / 1000 ))" "+%Y-%m-%d %H:%M:%S %Z")

readonly PROGNAME='BashScan'
readonly VERSION='version 0.1'
readonly URL='https://github.com/astryzia/BashScan'

readonly SPLASH="
██████   █████  ███████ ██   ██ ███████  ██████  █████  ███    ██ 
██   ██ ██   ██ ██      ██   ██ ██      ██      ██   ██ ████   ██ 
██████  ███████ ███████ ███████ ███████ ██      ███████ ██ ██  ██ 
██   ██ ██   ██      ██ ██   ██      ██ ██      ██   ██ ██  ██ ██ 
██████  ██   ██ ███████ ██   ██ ███████  ██████ ██   ██ ██   ████ 
"

printf $cyan"\n\t\t\t\t\t\t      "$dim"%s"$reset$magenta"%s\t\t\t     "$dim$cyan"%s\n"$reset "$VERSION" "$SPLASH" "$URL"
printf $inverted"\n    %s    \n"$reset "$start_stdout"
#printf $cyan$bold"\nStarting %s %s (%s) at %s\n"$reset "$PROGNAME" "$VERSION" "$URL" "$start_stdout"

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

. lib/args.sh
. lib/validations.sh
. lib/functions.sh
. lib/core.sh
