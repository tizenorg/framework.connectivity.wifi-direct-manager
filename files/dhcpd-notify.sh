#!/bin/sh
# Dump DHCP lease data: MAC IP Time
dumpleases | awk '$1!="Mac" {print $1, $2, $3}' > /tmp/dhcp-client-table

#Update vconf value to notify wifi-direct
vconftool set -t int memory/private/wifi_direct_manager/dhcp_ip_lease 1 -f
#cat /tmp/dhcp-client-table
