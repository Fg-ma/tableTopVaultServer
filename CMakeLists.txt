cmake_minimum_required(VERSION 3.14)
project(VaultServer)

set(CMAKE_CXX_STANDARD 17)

# Include directories for headers
include_directories(
    ${CMAKE_SOURCE_DIR}/lib/uWebSockets/src
    ${CMAKE_SOURCE_DIR}/lib/uWebSockets/uSockets/src
    ${CMAKE_SOURCE_DIR}/lib/uWebSockets/deps/libuv/include
)

# Add executable with server.cpp only
add_executable(server server.cpp)

# Link the static uSockets library
target_link_libraries(server
    ${CMAKE_SOURCE_DIR}/lib/uWebSockets/uSockets/libuSockets.a
    pthread
    z
    ssl
    crypto
)
