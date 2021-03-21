
########################################
# Argument handling
########################################

PARSED_ARGUMENTS=$(getopt -n $PROGNAME \
	-a \
	-o bhp:rt:T:v \
	-l banner,help,oG:,oN:,ports:,root,timing:,top-ports:,version \
	-- "$@")
VALID_ARGUMENTS=$?

if [ "$VALID_ARGUMENTS" != "0" ]; then
  usage
fi

# for file output options, we mimic the familiar format of nmap, 
# using -oG, -oN, etc; note: the "-a" option above allows use of
# a single dash for "long" options in addition to double dash; 
# since getopt doesn't support a multi-char "short" option, this 
# is one workaround. also, the "short" options for output aren't
# used (no associated chars in the "-o" string above), but getopt 
# doesn't work if nothing is present in the short fields for the 
# case statement, so we use placeholders "~" here
eval set -- "$PARSED_ARGUMENTS"
while [ $# -gt 0 ]; do
	case "$1" in
		-b  | --banner      ) BANNER=true               ; shift 1 ;;
		-~  | --oG			) g_file="$2"				; shift 2 ;; 
		-~ 	| --oN			) n_file="$2"				; shift 2 ;;
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
