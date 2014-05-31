CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(wfd-manager C)

# Global setting
SET(VERSION 0.0)

# Build type : Release
IF("${CMAKE_BUILD_TYPE}" STREQUAL "")
	SET(CMAKE_BUILD_TYPE "Release")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "")
MESSAGE("Build type: ${CMAKE_BUILD_TYPE}")

# Set required packages
INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED wifi-direct vconf glib-2.0 dbus-1 dbus-glib-1 gthread-2.0 dlog capi-appfw-application)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag} -g -DUSE_DLOG")
ENDFOREACH(flag)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/src/include
		${CMAKE_SOURCE_DIR}/oem/include)


SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")

#FIND_PROGRAM(UNAME NAMES uname)
#EXEC_PROGRAM("${UNAME}" ARGS "-m" OUTPUT_VARIABLE "ARCH")
SET(ARCH "${ARCHITECTURE}")
IF("${ARCH}" STREQUAL "arm")
	ADD_DEFINITIONS("-DTARGET")
	MESSAGE("add -DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")

# Linker flags
#SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")


#EXEC_PROGRAM("${UNAME}" ARGS "-m" OUTPUT_VARIABLE "ARCH")
message("${ARCH}")
IF("${ARCH}" MATCHES "^arm.*|.*86.*")
	SET(SRCS
                wifi-direct-main.c
                wifi-direct-utils.c
                wifi-direct-stub.c
                wifi-direct-state.c
                wifi-direct-dhcp.c
                wifi-direct-client-handler.c
                wifi-direct-event-handler.c
                ${CMAKE_SOURCE_DIR}/oem/wifi-direct-oem.c
	)
	MESSAGE("Build for Target")

	ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})

	TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS} -ldl)

	# pkgconfig file
	SET(PREFIX ${CMAKE_INSTALL_PREFIX})

	# Install
	INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd.p2p.conf DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd.wl0.conf DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd.eth.conf DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/udhcp_script.non-autoip DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/p2p_suppl.conf DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd-notify.sh DESTINATION bin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/wifi-direct-server.sh DESTINATION bin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/wifi-direct-dhcp.sh DESTINATION bin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/p2p_supp.sh DESTINATION sbin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/p2p_supplicant DESTINATION sbin)

ELSE()
	SET(SRCS
                wifi-direct-main.c
                wifi-direct-utils.c
                wifi-direct-stub.c
                wifi-direct-state.c
                wifi-direct-dhcp.c
                wifi-direct-client-handler.c
                wifi-direct-event-handler.c
                ${CMAKE_SOURCE_DIR}/oem/wifi-direct-oem.c
	)
	MESSAGE("Build for Emulator")

	ADD_EXECUTABLE(${PROJECT_NAME} ${SRCS})
	TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${pkgs_LDFLAGS} -ldl)

	# pkgconfig file
	SET(PREFIX ${CMAKE_INSTALL_PREFIX})

	# Install
	INSTALL(TARGETS ${PROJECT_NAME} DESTINATION bin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd.p2p.conf DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd.wl0.conf DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd.eth.conf DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/udhcp_script.non-autoip DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/p2p_suppl.conf DESTINATION etc/wifi-direct)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/dhcpd-notify.sh DESTINATION bin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/wifi-direct-server.sh DESTINATION bin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/wifi-direct-dhcp.sh DESTINATION bin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/p2p_supp.sh DESTINATION sbin)
	INSTALL(FILES ${CMAKE_SOURCE_DIR}/files/p2p_supplicant DESTINATION sbin)
	
ENDIF()

