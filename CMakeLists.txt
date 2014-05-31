CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(wifi-direct-manager C)

#SET(PREFIX $(CMAKE_INSTALL_PREFIX))
SET(prefix "/usr")
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include")

ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(plugin/wpasupplicant)
