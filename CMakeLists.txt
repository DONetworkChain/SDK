cmake_minimum_required(VERSION 3.0 )

project(don_sdk VERSION 0.1.0)

option(BUILD_WASM_LIBS "Build WebAssembly library" OFF)
option(BUILD_JAVA_LIBS "Build java library" OFF)
option(BUILD_SHARED_LIBS "Build shared library" ON)
option(BUILD_TEST "Build Test" OFF)
option(CLEAN_BUILD "Remove Depend" OFF)

include(cmake/OptionCheck.cmake)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (CLEAN_BUILD)
    execute_process(COMMAND rm -rf ${CMAKE_SOURCE_DIR}/protobuf ${CMAKE_SOURCE_DIR}/openssl)
    set(CLEAN_BUILD OFF CACHE BOOL "Remove Depend" FORCE)
endif ()

if(CMAKE_HOST_UNIX)
    execute_process(COMMAND sh ${CMAKE_SOURCE_DIR}/make_depend.sh ${CMAKE_CURRENT_BINARY_DIR} ${BUILD_WASM_LIBS})
endif()

if(CMAKE_HOST_UNIX)
    set(ExternalDependenciesDirectory ${CMAKE_SOURCE_DIR}/lib/linux)
elseif(CMAKE_HOST_WIN32)
    set(ExternalDependenciesDirectory ${CMAKE_SOURCE_DIR}/lib/windows)
else()
    message("Unknown platform")
endif()

if (BUILD_SHARED_LIBS)
    set(BuildSharedOrStatic "SHARED")
else()
    set(BuildSharedOrStatic "STATIC")
endif()


# Other libraries
find_library(CRYPTOPP_LIBRARY NAMES cryptopp libcryptopp PATHS ${ExternalDependenciesDirectory} NO_DEFAULT_PATH REQUIRED NO_CMAKE_FIND_ROOT_PATH)
find_library(SSL_LIBRARY_PATH NAMES ssl libssl PATHS ${ExternalDependenciesDirectory} NO_DEFAULT_PATH REQUIRED NO_CMAKE_FIND_ROOT_PATH)
find_library(CRYPT_LIBRARY_PATH NAMES crypto libcrypto PATHS ${ExternalDependenciesDirectory} NO_DEFAULT_PATH REQUIRED NO_CMAKE_FIND_ROOT_PATH)
find_library(PROTOBUF_LIBRARY_PATH NAMES protobuf libprotobuf PATHS ${ExternalDependenciesDirectory} NO_DEFAULT_PATH REQUIRED NO_CMAKE_FIND_ROOT_PATH)

set(ExternalDependencies ${SSL_LIBRARY_PATH} ${CRYPT_LIBRARY_PATH} ${PROTOBUF_LIBRARY_PATH} ${CRYPTOPP_LIBRARY} -lpthread -ldl)

add_subdirectory(src)

add_subdirectory(rpc_test)
if (BUILD_TEST)
    add_subdirectory(test)
endif ()

