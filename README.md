# bash-portscanner

Simple portscanner in pure bash utilizing /dev/tcp.

Uses both ping and arping (if available) to sweep the network for live hosts, generates a list stored in /tmp/, and loops through the list for ports specified within the script.

This backgrounds each task, so be mindful of system hardware when checking a large number of ports.

Only supports /24 CIDR but easy to add more coverage if desired.
