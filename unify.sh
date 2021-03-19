#!/bin/bash

#######################################
## Combine all scripts into monolith
#######################################

cat run.sh | grep -wEv ". lib/args.sh|. lib/functions.sh|. lib/validations.sh| .lib/core.sh|. lib/core.sh|main" > bashscan.sh
cat lib/args.sh >> bashscan.sh
cat lib/validations.sh >> bashscan.sh
cat lib/core.sh >> bashscan.sh
cat lib/functions.sh >> bashscan.sh

printf "\n\nmain" >> bashscan.sh

chmod +x bashscan.sh