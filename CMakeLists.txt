cmake_minimum_required(VERSION 3.10)

set (CMAKE_CONFIGURATION_TYPES "Debug;Release")

project(http_demo)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../lwip)

set(LWIP_DEFINITIONS LWIP_DEBUG=1)

include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)

set(LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_DIR}/contrib"
    "${LWIP_DIR}/contrib/ports/unix/port/include"
    ${CMAKE_CURRENT_SOURCE_DIR}
)

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_DIR}/contrib/ports/unix/Filelists.cmake)

add_executable(http_demo http_demo.c)
target_compile_definitions(http_demo PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_include_directories(http_demo PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
target_link_libraries(http_demo ${LWIP_SANITIZER_LIBS} lwipcore lwipcontribportunix lwipallapps lwipmbedtls)
