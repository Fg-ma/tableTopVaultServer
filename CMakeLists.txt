cmake_minimum_required(VERSION 3.14)
project(VaultServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)

# Collect uWebSockets sources
file(GLOB_RECURSE UWS_SRC
    ${CMAKE_SOURCE_DIR}/lib/uWebSockets/src/*.cpp
)

# Build VaultServer by compiling your server + uWebSockets .cpp files
add_executable(${PROJECT_NAME}
  server.cpp
  ${UWS_SRC}
)

# Tell uWebSockets headers to actually compile in the SSL codepaths
target_compile_definitions(${PROJECT_NAME} PRIVATE
  UWS_ENABLE_SSL=1
  UWS_ENABLE_TRACE=1
)

# Include directories for headers
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/uWebSockets/src
    ${CMAKE_SOURCE_DIR}/lib/uWebSockets/uSockets/src
    ${CMAKE_SOURCE_DIR}/lib/uWebSockets/deps/libuv/include
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/uWebSockets/uSockets/uSockets.a
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    Threads::Threads
    CURL::libcurl
)
