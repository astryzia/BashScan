<h1 align=center>
  <img src="https://i.imgur.com/VDwBdNH.png" alt="BashScan">
  <br/>
</h1>

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/astryzia/BashScan/issues)
[![Follow on Twitter](https://img.shields.io/twitter/follow/0xValkyrie.svg?logo=twitter)](https://twitter.com/0xValkyrie)

# BashScan

BashScan is a port scanner built to utilize /dev/tcp for network and service discovery on systems that have limitations or are otherwise unable to use alternative scanning solutions such as nmap.

# Installation

For users with more environmental flexibility, simply clone the repository and execute `run.sh`.

**HTTPS** `git clone https://github.com/astryzia/BashScan.git`

**SSH** `git clone git@github.com:astryzia/BashScan.git`

`chmod +x *.sh lib/*.sh`

On more limited systems, the `bashscan.sh` script can be downloaded and ran as a monolithic all-in-one solution. Included in the repository is a script named `unify.sh` that will combine all libraries and functions into the independent `bashscan.sh` script for those who make tweaks and/or port the script elsewhere for use.

# How to use

**Examples**

`./run.sh -r -p 22,80,443,3306,3389 -b`

`./run.sh -r --top-ports 1000 -T 6 -b`

`./run.sh --root --timing 6 --banner -p 22 10.0.0.1`

`./run.sh --root --timing 6 --banner -p 22 10.0.0.1-100`

Alternatively, using the monolithic script

`./bashscan.sh -r -p 22,80,443,3306,3389 -b`

`./bashscan.sh -r --top-ports 1000 -T 6 -b`

`./bashscan.sh --root --timing 6 --banner -p 22 10.0.0.1`

`./bashscan.sh --root --timing 6 --banner -p 22 10.0.0.1-100`

**Options**

`-h | --help` Displays help message with usage options

`-b | --banner` Attempt to grab banners during port scanning

`-p | --ports <PORTS>` Comma-separaated list or range of integers up to 65535

`-r | --root` Force ARP ping to run even if user doesn't have root privileges

`-t | --top-ports <1+>` Specify number of top TCP ports to scan (default = 20)

`-T | --timing <0-6>` Timing template (default = 4)

`-v | --version` Print version

**Dockerized example**
To build the dockerized image run `make build` or `make all` to build and run the BashScan image. Examples to interact with the container:

`./docker_bashscan.sh -r -p 22,80,443,3306,3389 -b`

`make run -r -p 22,80,443,3306,3389 -b`

# Contributors

The list of contributors can be found [here](https://github.com/astryzia/BashScan/graphs/contributors). Thank you for everything!
