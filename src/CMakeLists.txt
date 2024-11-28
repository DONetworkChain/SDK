add_subdirectory(envelop)
add_subdirectory(proto)
add_subdirectory(sig)

add_library(${PROJECT_NAME} ${BuildSharedOrStatic}
        interface.cpp
        )
        
target_include_directories(${PROJECT_NAME} PUBLIC . PRIVATE ${ExternalDependenciesDirectory}/include)
target_link_libraries(${PROJECT_NAME} PRIVATE envelop proto sig ${ExternalDependencies})

set_target_properties(
        ${PROJECT_NAME}
        PROPERTIES
        POSITION_INDEPENDENT_CODE ON
        LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib
        ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib
        RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib
        OUTPUT_NAME ${PROJECT_NAME}_v${PROJECT_VERSION}
)

if (MSVC)
    set_target_properties(
            ${PROJECT_NAME}
            PROPERTIES
            WINDOWS_EXPORT_ALL_SYMBOLS ON
    )
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE DON_SDK_VERSION=${PROJECT_VERSION})

if(BUILD_JAVA_LIBS)
    add_subdirectory(jni)
endif()

if (BUILD_WASM_LIBS)
    set(wasmLibName don_sdk_wasm_v${PROJECT_VERSION})
    include(${CMAKE_SOURCE_DIR}/cmake/ListProcess.cmake)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND emcc -O2 -s WASM=1  -s MODULARIZE=1  -s ENVIRONMENT="web" -s EXPORTED_RUNTIME_METHODS=[${exported_runtime_methods}] -s EXPORTED_FUNCTIONS=[${exported_functions}] ${ExternalDependencies} $<TARGET_FILE:${PROJECT_NAME}> -o ${wasmLibName}.js
            COMMAND sed 's|<script src="/"></script>|<script src="/${wasmLibName}.js"></script>|g' ${CMAKE_SOURCE_DIR}/assets/index.html > ./index.html
            COMMAND [ ! -d "${PROJECT_BINARY_DIR}/lib" ] && mkdir "${PROJECT_BINARY_DIR}/lib" || true
            COMMAND mv ${wasmLibName}.js ${wasmLibName}.wasm index.html ${PROJECT_BINARY_DIR}/lib
            COMMENT "building wasm library......"
            )

endif()