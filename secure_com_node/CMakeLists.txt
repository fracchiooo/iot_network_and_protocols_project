# For more information about build system see
# https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/build-system.html
# The following five lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(secure_com_node)


target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "components/mqtt_wrapper/broker.crt" TEXT)
target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "components/mqtt_wrapper/client.cert.pem" TEXT)
target_add_binary_data(${CMAKE_PROJECT_NAME}.elf "components/mqtt_wrapper/client.key.pem" TEXT)

