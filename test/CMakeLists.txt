include(FetchContent)
FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG main
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
add_executable(unit_tests
        interfaceTest.cpp
        )
target_link_libraries(unit_tests PRIVATE ${PROJECT_NAME} gtest_main)

if (MSVC)
    add_custom_command(TARGET unit_tests PRE_LINK 
        COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> $<TARGET_FILE_DIR:unit_tests>
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${ExternalDependenciesDirectory} $<TARGET_FILE_DIR:unit_tests>
        )
endif()

include(GoogleTest)
gtest_discover_tests(unit_tests)