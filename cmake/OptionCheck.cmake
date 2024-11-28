if (BUILD_WASM_LIBS AND (NOT CMAKE_HOST_UNIX))
    set(BUILD_WASM_LIBS OFF CACHE BOOL "Build WebAssembly library" FORCE)
    message(FATAL_ERROR "building wasm library only support unix-like platform")
endif()

find_program(EMCC_FOUND emcc)
if (BUILD_WASM_LIBS AND (NOT EMCC_FOUND))
    unset(EMCC_FOUND CACHE)
    set(BUILD_WASM_LIBS OFF CACHE BOOL "Build WebAssembly library" FORCE)
    message(FATAL_ERROR "emcc not found!")
endif ()

if (EMCC_FOUND)
    execute_process(
            COMMAND emcc --version
            OUTPUT_VARIABLE EMCC_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    string(REGEX MATCH "[0-9]+\\.[0-9]+\\.[0-9]+" EMCC_VERSION "${EMCC_VERSION}")
    if(EMCC_VERSION VERSION_LESS "3.1.51")
        message(AUTHOR_WARNING "emcc version is lower than 3.1.51, which may cause Emscripten linking issues. \
        if your wasm application is running normally, you can ignore this warning.")
    endif()
endif ()

if (BUILD_TEST AND BUILD_WASM_LIBS)
    set(BUILD_TEST OFF CACHE BOOL "Build Test" FORCE)
    set(BUILD_WASM_LIBS OFF CACHE BOOL "Build WebAssembly library" FORCE)
    message(FATAL_ERROR "not support test when building wasm lib")
endif()

if(BUILD_TEST AND BUILD_JAVA_LIBS)
    set(BUILD_TEST OFF CACHE BOOL "Build Test" FORCE)
    set(BUILD_JAVA_LIBS OFF CACHE BOOL "Build java library" FORCE)
    message(FATAL_ERROR "not support test when building java lib")
endif()

if(BUILD_WASM_LIBS AND BUILD_JAVA_LIBS)
    set(BUILD_WASM_LIBS OFF CACHE BOOL "Build WebAssembly library" FORCE)
    set(BUILD_JAVA_LIBS OFF CACHE BOOL "Build java library" FORCE)
    message(FATAL_ERROR "not support building java lib and wasm lib at the same time")
endif()

if(BUILD_JAVA_LIBS AND CMAKE_HOST_UNIX)
    find_package(JNI REQUIRED)
endif()