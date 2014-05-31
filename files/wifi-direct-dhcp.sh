#!/bin/sh
INTERFACE_PREFIX="p2p"
TARGET="REDWOOD"
DEFAULT_IP="192.168.49.1"

val=`uname -a | grep PQ | wc -l`
if [ "${val}" -eq "1" ]; then
	TARGET="PQ"
fi

val=`uname -a | grep U1HD | wc -l`
if [ "${val}" -eq "1" ]; then
	INTERFACE_PREFIX="wl0"
	TARGET="U1HD"
fi

val=`uname -a | grep U1SLP | wc -l`
if [ "${val}" -eq "1" ]; then
	INTERFACE_PREFIX="wl0"
	TARGET="U1SLP"
fi

val=`uname -a | grep i686  | wc -l`
if [ "${val}" -eq "1" ]; then
	INTERFACE_PREFIX="eth"
	TARGET="EMUL"
fi

interface=`ifconfig|grep ^${INTERFACE_PREFIX}|cut -d" " -f1`
echo "Target is ${TARGET} and interface ${INTERFACE_PREFIX}: ${interface}."

start_dhcp_server()
{
        if [ "X${interface}" == "X" ]; then
                echo "interface(${INTERFACE_PREFIX}) is not up"
		return 0
        fi

	ifconfig ${interface} ${DEFAULT_IP} up
	udhcpd /usr/etc/wifi-direct/dhcpd.${INTERFACE_PREFIX}.conf -f &

	route=`cat /usr/etc/wifi-direct/dhcpd.${INTERFACE_PREFIX}.conf | grep router | awk '{print $3}'`
	if [ -z $route ]; then
		route="192.168.49.1"
	fi
	subnet=`cat /usr/etc/wifi-direct/dhcpd.${INTERFACE_PREFIX}.conf | grep subnet | awk '{print $3}'`

	if [ -z $subnet ]; then
		subnet="255.255.255.0"
	fi

	vconftool set -t string memory/private/wifi_direct_manager/p2p_ifname ${interface} -f
	vconftool set -t string memory/private/wifi_direct_manager/p2p_local_ip ${DEFAULT_IP} -f
	vconftool set -t string memory/private/wifi_direct_manager/p2p_subnet_mask ${subnet} -f
	vconftool set -t string memory/private/wifi_direct_manager/p2p_gateway ${route} -f
}

start_dhcp_client()
{
        if [ "X${interface}" == "X" ]; then
                echo "interface(${INTERFACE_PREFIX}) is not up"
		return 0
        fi
	/usr/bin/udhcpc -i $interface -s /usr/etc/wifi-direct/udhcp_script.non-autoip &
}


stop_dhcp()
{
	vconftool set -t string memory/private/wifi_direct_manager/p2p_ifname "" -f
	vconftool set -t string memory/private/wifi_direct_manager/p2p_local_ip "" -f
	vconftool set -t string memory/private/wifi_direct_manager/p2p_subnet_mask "" -f
	vconftool set -t string memory/private/wifi_direct_manager/p2p_gateway "" -f

	killall udhcpc
	killall udhcpd
#	ifconfig ${interface} 0.0.0.0
}

is_running()
{
	program=$1
	run=`ps -eo comm|grep ${program}`
	if [ "X${run}" == "X" ]; then
		echo "${program} is not running"
	else
		echo "${program} is already running"
	fi
}

status_dhcp()
{
	is_running udhcpc 
	is_running udhcpd 
}


case $1 in
"server")
stop_dhcp
start_dhcp_server
;;
"client")
stop_dhcp
start_dhcp_client
;;
"stop")
stop_dhcp
;;
"status")
status_dhcp
;;
*)
/bin/echo wifi-direct-dhcp.sh [server] [client] [stop] [status]
exit 1
;;
esac

