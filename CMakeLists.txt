cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(tcp_project C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

add_executable(pico_tcp_multicore_server
            pico_tcp_multicore_server.c
            )

pico_enable_stdio_usb(pico_tcp_multicore_server 1)
pico_enable_stdio_uart(pico_tcp_multicore_server 0)

pico_add_extra_outputs(pico_tcp_multicore_server)

target_link_libraries(pico_tcp_multicore_server pico_cyw43_arch_lwip_threadsafe_background pico_stdlib pico_multicore)