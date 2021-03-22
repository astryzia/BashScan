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
	[ -h | --help ]           Show this help message and exit.
	[ -o | --open ]           Only show targets with open ports
	[ -p | --ports <PORTS> ]  Comma-separated list or range of integers up to 65535.
	[ -r | --root ]           Force ARP ping to run even if user doesn't have root privileges.
	[ -t | --top-ports <1+> ] Specify number of top TCP ports to scan (default = 20 )
	[ -T | --timing <0-6> ]   Timing template (default = 4)
	[ -v | --version ]        Print version and exit.
	[ -oN <file.txt> ]        Normal output: similar to interactive output
	[ -oG <file.txt> ]        Grepable output: comma-delimited, each host on a single line
	<x.x.x.[x|x-y|x/24]>      Target IP (optional), as single, range, or CIDR\n\n" $PROGNAME
	exit 0
}

. lib/args.sh
. lib/validations.sh
. lib/functions.sh
. lib/core.sh
