add_library(jni SHARED
        jni_tools.cpp
        com_example_jni_sig.cpp
        )

target_include_directories(jni PUBLIC . PRIVATE ${JNI_INCLUDE_DIRS} ${ExternalDependenciesDirectory}/include)
target_link_libraries(jni PRIVATE envelop proto sig ${PROJECT_NAME} ${ExternalDependencies})

if (CMAKE_HOST_UNIX)
    target_link_libraries(jni PRIVATE pthread dl)
endif()

set_target_properties(
        jni
        PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib
        ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib
        OUTPUT_NAME ${PROJECT_NAME}_jni_v${PROJECT_VERSION}
)

