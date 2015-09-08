#!/bin/sh

start()
{
#	HARDWARE_MODEL=`/bin/grep Hardware /proc/cpuinfo | /bin/awk "{print \\$3}"`
#	/bin/echo "Hardware Model=${HARDWARE_MODEL}"

	if [ -e /opt/etc/p2p_supp.conf ]; then
		echo "File exist: /opt/etc/p2p_supp.conf"
	else
		echo "File not exist. Reinstall: /opt/etc/p2p_supp.conf"
		 /bin/cp /usr/etc/wifi-direct/p2p_supp.conf /opt/etc/
	fi
	/usr/sbin/p2p_supplicant -t -B -ddd -Dnl80211 -iwlan0 -c/opt/etc/p2p_supp.conf -f/opt/usr/data/network/p2p_supplicant.log
}

stop()
{
#	HARDWARE_MODEL=`/bin/grep Hardware /proc/cpuinfo | /bin/awk "{print \\$3}"`
#	/bin/echo "Hardware Model=${HARDWARE_MODEL}"

	/usr/bin/killall p2p_supplicant
}

case $1 in
"start")
start
;;
"stop")
stop
;;
*)
/bin/echo p2p_supp.sh [start] [stop]
exit 1
;;
esac
