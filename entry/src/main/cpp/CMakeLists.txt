cmake_minimum_required(VERSION 3.4.0)
project(wg_tunnel_napi)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")

# Everything that touches a packet lives in this library: the Noise handshake,
# the AEAD, the replay window and the TUN/UDP poll loop.
add_library(wg_tunnel SHARED
    wg_napi.cpp
    wg/tunnel.c
    wg/noise.c
    wg/packet.c
    wg/curve25519.c
    wg/blake2s.c
    wg/chacha20poly1305.c
)
target_include_directories(wg_tunnel PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(wg_tunnel PUBLIC ace_napi.z hilog_ndk.z)
