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
add_executable(addr_test main.cpp)

# Links to the main project library and its dependencies
target_link_libraries(addr_test PRIVATE ${PROJECT_NAME} ${ExternalDependencies})

# Set the target properties, such as the output directory
set_target_properties(addr_test
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin
    OUTPUT_NAME "addr_test_executable"
)# Define versions or other macros
target_compile_definitions(addr_test PRIVATE ADDR_TEST_VERSION=${PROJECT_VERSION})
