#!/bin/sh
# Dump DHCP lease data: MAC IP Time
/usr/bin/dumpleases | /bin/awk '$1!="Mac" {print $1, $2, $3}' > /tmp/dhcp-client-table

#Update vconf value to notify wifi-direct
/usr/bin/vconftool set -t int memory/private/wifi_direct_manager/dhcp_ip_lease 1 -f
#cat /tmp/dhcp-client-table
