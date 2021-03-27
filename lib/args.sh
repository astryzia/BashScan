
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
