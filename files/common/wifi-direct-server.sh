#!/bin/sh
program="wfd-manager"
target=`/bin/ps -eo comm|/bin/grep ${program}`

start_wifi_direct()
{
	if [ "X${target}" == "X" ]; then
		echo "${program} is not running"
		echo "Launching ${program}"
		/usr/bin/${program}&
		/bin/sleep 1
	else
		echo "${program} is already running"
	fi
}

stop_wifi_direct()
{
	if [ "X${target}" == "X" ]; then
		echo "${program} is not running"
	else
		echo "${program} is running.. Killing it"
		/usr/bin/pkill -x ${program}
	fi
}

status_wifi_direct()
{
	if [ "X${target}" == "X" ]; then
		echo "${program} is not running"
	else
		echo "${program} is already running"
	fi
}

case $1 in
"start")
start_wifi_direct
;;
"stop")
stop_wifi_direct
;;
"status")
status_wifi_direct
;;
*)
/bin/echo wifi-direct-server.sh [start] [stop] [status]
exit 1
;;
esac
