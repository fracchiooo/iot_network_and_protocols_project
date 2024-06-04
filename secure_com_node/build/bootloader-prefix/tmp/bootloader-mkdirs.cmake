# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/fracchio/esp/esp-idf/components/bootloader/subproject"
  "/home/fracchio/Scrivania/iot_network_and_protocols_project/secure_com_node/build/bootloader"
  "/home/fracchio/Scrivania/iot_network_and_protocols_project/secure_com_node/build/bootloader-prefix"
  "/home/fracchio/Scrivania/iot_network_and_protocols_project/secure_com_node/build/bootloader-prefix/tmp"
  "/home/fracchio/Scrivania/iot_network_and_protocols_project/secure_com_node/build/bootloader-prefix/src/bootloader-stamp"
  "/home/fracchio/Scrivania/iot_network_and_protocols_project/secure_com_node/build/bootloader-prefix/src"
  "/home/fracchio/Scrivania/iot_network_and_protocols_project/secure_com_node/build/bootloader-prefix/src/bootloader-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/fracchio/Scrivania/iot_network_and_protocols_project/secure_com_node/build/bootloader-prefix/src/bootloader-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/fracchio/Scrivania/iot_network_and_protocols_project/secure_com_node/build/bootloader-prefix/src/bootloader-stamp${cfgdir}") # cfgdir has leading slash
endif()
