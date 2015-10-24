#!/bin/sh

PROGRAM="/usr/sbin/wpa_supplicant"

start()
{
	HARDWARE_MODEL=`/bin/grep Hardware /proc/cpuinfo | /bin/awk "{print \\$3}"`
	/bin/echo "Hardware Model=${HARDWARE_MODEL}"

	if [ -e /opt/etc/p2p_supp.conf ]; then
		echo "File exist: /opt/etc/p2p_supp.conf"
	else
		echo "File not exist. Reinstall: /opt/etc/p2p_supp.conf"
		 /bin/cp /usr/etc/wifi-direct/p2p_supp.conf /opt/etc/
	fi
	## For Hawk-P Platform, Hardware model is Samsung
	if [ $HARDWARE_MODEL = "Samsung" ];then
		/usr/sbin/wpa_supplicant -t -B -ddd -Dnl80211 -ip2p0 -c/opt/etc/p2p_supp.conf -g/var/run/wpa_global  -f/opt/usr/data/network/wpa_supplicant.log
	 else
		/usr/sbin/wpa_supplicant -t -B -C/var/run/wpa_supplicant -ddd -Dnl80211 -iwlan0 -c/opt/etc/p2p_supp.conf -f/opt/usr/data/network/wpa_supplicant.log
	fi
 }

start_p2p0()
{
	if [ -e /opt/etc/p2p_supp.conf ]; then
		echo "File exist: /opt/etc/p2p_supp.conf"
	else
		echo "File not exist. Reinstall: /opt/etc/p2p_supp.conf"
		 /bin/cp /usr/etc/wifi-direct/p2p_supp.conf /opt/etc/
	fi
	/usr/sbin/wpa_supplicant -t -B -ddd -Dnl80211 -ip2p0 -c/opt/etc/p2p_supp.conf -f/opt/usr/data/network/wpa_supplicant.log
}

start_dbus()
{
	program=${PROGRAM}
	run=`/bin/ps -eo comm|/bin/grep ${program}`
	if [ "X${run}" == "X" ]; then
		echo "${program} is not running"
		if [ -e /opt/etc/p2p_supp.conf ]; then
			echo "File exist: /opt/etc/p2p_supp.conf"
		else
			echo "File not exist. Reinstall: /opt/etc/p2p_supp.conf"
			 /bin/cp /usr/etc/wifi-direct/p2p_supp.conf /opt/etc/
		fi
		/usr/sbin/wpa_supplicant -t -B -u -d -f/opt/usr/data/network/wpa_supplicant.log
	else
		echo "${program} is already running"
	fi
}

stop()
{
	/usr/bin/pkill -x wpa_supplicant
}

case $1 in
"start")
start
;;
"start_p2p0")
start_p2p0
;;
"start_dbus")
start_dbus
;;
"stop")
stop
;;
*)
/bin/echo p2p_supp.sh [start] [start_p2p0] [start_dbus] [stop]
exit 1
;;
esac
