cmake_minimum_required(VERSION 3.0)

# Contains the directory, assuming that src is the path relative to the project root
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/envelop
    ${CMAKE_SOURCE_DIR}/src/proto
    ${CMAKE_SOURCE_DIR}/src/sig
    ${CMAKE_SOURCE_DIR}/cryptopp
    ${ExternalDependenciesDirectory}/include
)
# Add an executable file
add_executable(rpc_test main.cpp)

# Links to the main project library and its dependencies
target_link_libraries(rpc_test PRIVATE ${PROJECT_NAME} ${ExternalDependencies})

# Set the target properties, such as the output directory
set_target_properties(rpc_test
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin
    OUTPUT_NAME "rpc_test_executable"
)# Define versions or other macros
target_compile_definitions(rpc_test PRIVATE RPC_TEST_VERSION=${PROJECT_VERSION})
