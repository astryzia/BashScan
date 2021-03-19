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
	[ -oN <file.txt> ]        Normal output: similar to interactive output
	[ -oG <file.txt> ]        Grepable output: comma-delimited, each host on a single line
	<x.x.x.x> OR <x.x.x.x-y>  Target IP (optional)\n\n" $PROGNAME
	exit 0
}

. lib/args.sh
. lib/validations.sh
. lib/core.sh
. lib/functions.sh
