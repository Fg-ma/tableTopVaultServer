cmake_minimum_required(VERSION 3.14)
project(VaultServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Find dependencies
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
include_directories(${SODIUM_INCLUDE_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS})


include(FetchContent)

FetchContent_Declare(
  yaml_cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG master
)
FetchContent_MakeAvailable(yaml_cpp)

find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
  include(FetchContent)
  FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP true
  )
  FetchContent_MakeAvailable(json)
endif()


include(FetchContent)

FetchContent_Declare(
  json_validator
  GIT_REPOSITORY https://github.com/pboettch/json-schema-validator.git
  GIT_TAG main
)
FetchContent_MakeAvailable(json_validator)

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
    nlohmann_json::nlohmann_json
    nlohmann_json_schema_validator
    yaml-cpp
    ${SODIUM_LIBRARIES}
)

# CLI helper to request a token from the vault daemon
add_executable(vault_requests vault_requests.cpp)
target_link_libraries(vault_requests
    PRIVATE
      ${Boost_LIBRARIES}
      ${SODIUM_LIBRARIES}
      nlohmann_json::nlohmann_json
      OpenSSL::SSL
      OpenSSL::Crypto
      yaml-cpp
)
target_include_directories(vault_requests
    PRIVATE
      ${SODIUM_INCLUDE_DIRS}
)

install(TARGETS vault_requests RUNTIME DESTINATION bin)

add_executable(vault vault.cpp)

target_link_libraries(vault
    PRIVATE
      Threads::Threads
      CURL::libcurl
)

target_include_directories(vault
    PRIVATE
      ${CURL_INCLUDE_DIRS}
)
