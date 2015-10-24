Name:		wifi-direct-manager
Summary:	Wi-Fi Direct manger
Version:	1.2.118
Release:	1
Group:		System/Network
License:	Apache-2.0
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(capi-network-wifi-direct)
BuildRequires:	pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(vconf)
BuildRequires:  pkgconfig(libnl-2.0)
BuildRequires:	pkgconfig(dbus-1)
BuildRequires:	pkgconfig(security-server)
BuildRequires:	pkgconfig(capi-appfw-application)
BuildRequires:	cmake
BuildRequires:	model-build-features
Requires:	net-tools
Requires:	sys-assert
Requires:	tizen-coreutils
Requires:	toybox-symlinks-dhcpd
Requires:	toybox-symlinks-dhcp
Requires(post):	/usr/bin/vconftool

%description
Wi-Fi Direct manager

%package -n wifi-direct-plugin-wpasupplicant
Summary:	wifi drect plugin for wpa supplicant
Group:		System/Network
Requires:	%{name} = %{version}-%{release}

%description -n wifi-direct-plugin-wpasupplicant
wifi drect plugin for wpa supplicant

%prep
%setup -q

%build

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"

%ifarch %{arm}
export ARCH=arm
%else

%if 0%{?simulator}
export ARCH=emul
%else
export ARCH=i586
%endif

%endif

cmake -DCMAKE_INSTALL_PREFIX=%{_prefix} -DARCHITECTURE=$ARCH \
%if 0%{?model_build_feature_wlan_concurrent_mode}
	-DTIZEN_WLAN_CONCURRENT_ENABLE=1 \
%endif
%if ! 0%{?model_build_feature_network_tethering_disable}
	-DTIZEN_TETHERING_ENABLE=0 \
%endif
%if "%{?tizen_profile_name}" == "wearable"
	-DTIZEN_FEATURE_SERVICE_DISCOVERY=0 \
	-DTIZEN_FEATURE_WIFI_DISPLAY=0 \
%else
%if "%{?tizen_profile_name}" == "mobile"
%if "%{?tizen_target_name}" == "Z300H"
	-DTIZEN_WLAN_BOARD_SPRD=1 \
%endif
	-DTIZEN_FEATURE_SERVICE_DISCOVERY=1 \
	-DTIZEN_WLAN_CONCURRENT_ENABLE=1 \
	-DTIZEN_FEATURE_WIFI_DISPLAY=1 \
	-DTIZEN_FEATURE_DEFAULT_CONNECTION_AGENT=1 \
	-DCTRL_IFACE_DBUS=1 \
	-DTIZEN_MOBILE=1 \
%else
%if "%{?tizen_profile_name}" == "tv"
	-DTIZEN_FEATURE_SERVICE_DISCOVERY=1 \
	-DTIZEN_WLAN_CONCURRENT_ENABLE=1 \
	-DTIZEN_FEATURE_WIFI_DISPLAY=1 \
	-DCTRL_IFACE_DBUS=1 \
	-DTIZEN_TV=1 \
%endif
%endif
%endif


make %{?_smp_mflags}


%install
rm -rf %{buildroot}

%make_install
#%__strip %{buildroot}%{_libdir}/wifi-direct-plugin-wpasupplicant.so
#%__strip %{buildroot}%{_bindir}/wfd-manager

#License
mkdir -p %{buildroot}%{_datadir}/license
cp %{_builddir}/%{buildsubdir}/LICENSE %{buildroot}%{_datadir}/license/%{name}
cp %{_builddir}/%{buildsubdir}/LICENSE %{buildroot}%{_datadir}/license/wifi-direct-plugin-wpasupplicant

%post
chmod 644 /usr/etc/wifi-direct/dhcpd.p2p.conf
chmod 755 /usr/bin/dhcpd-notify.sh
chmod 755 /usr/etc/wifi-direct/udhcp_script.non-autoip
chmod 755 /usr/bin/wifi-direct-server.sh
chmod 755 /usr/bin/wifi-direct-dhcp.sh
chmod 755 /usr/sbin/p2p_supp.sh

vconftool set -t int memory/wifi_direct/state 0 -u 5000 -i -s system::vconf_network
vconftool set -t int memory/private/wifi_direct_manager/dhcp_ip_lease 0 -i -s wifi_direct_manager
vconftool set -t string memory/private/wifi_direct_manager/dhcpc_server_ip 0.0.0.0 -u 5000 -i
vconftool set -t string memory/private/wifi_direct_manager/p2p_local_ip 0.0.0.0 -u 5000 -i
vconftool set -t string memory/private/wifi_direct_manager/p2p_subnet_mask 0.0.0.0 -u 5000 -i
vconftool set -t string memory/private/wifi_direct_manager/p2p_gateway 0.0.0.0 -u 5000 -i
vconftool set -t string memory/private/wifi_direct_manager/p2p_ifname 0.0.0.0 -u 5000 -i

%if "%{?tizen_profile_name}" == "tv"
	if [ ! -d /opt/var/lib/misc ]; then
		mkdir -p /opt/var/lib/misc
	fi

	touch /opt/var/lib/misc/dhcpd.leases
	chmod 666 /opt/var/lib/misc/dhcpd.leases
%else
	if [ ! -d /var/lib/misc ]; then
		mkdir -p /var/lib/misc
	fi

	touch /var/lib/misc/dhcpd.leases
	chmod 666 /var/lib/misc/dhcpd.leases
%endif

%postun


%files
%manifest wifi-direct-manager.manifest
%defattr(-,root,root,-)
%{_bindir}/wfd-manager
/usr/etc/wifi-direct/dhcpd.p2p.conf
/usr/etc/wifi-direct/udhcp_script.non-autoip
/usr/etc/wifi-direct/p2p_supp.conf
/opt/etc/p2p_supp.conf
/usr/etc/wifi-direct/ccode.conf
/opt/etc/persistent-peer
%{_bindir}/dhcpd-notify.sh
%{_bindir}/wifi-direct-server.sh
%{_bindir}/wifi-direct-dhcp.sh
%{_sbindir}/p2p_supp.sh
%attr(755,-,-) %{_bindir}/dhcpd-notify.sh
%attr(755,-,-) %{_bindir}/wifi-direct-server.sh
%attr(755,-,-) %{_bindir}/wifi-direct-dhcp.sh
%attr(755,-,-) /usr/etc/wifi-direct/udhcp_script.non-autoip
%attr(755,-,-) %{_sbindir}/p2p_supp.sh
%attr(644,-,-) %{_datadir}/license/%{name}

%files -n wifi-direct-plugin-wpasupplicant
%manifest wifi-direct-plugin-wpasupplicant.manifest
%defattr(-,root,root,-)
%{_libdir}/wifi-direct-plugin-wpasupplicant.so
%attr(644,-,-) %{_datadir}/license/wifi-direct-plugin-wpasupplicant
