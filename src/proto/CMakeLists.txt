add_library(proto OBJECT
        ca_protomsg.pb.cc
        sign.pb.cc
        transaction.pb.cc
        )

target_include_directories(proto PUBLIC . ${ExternalDependenciesDirectory}/include)
set_target_properties(proto PROPERTIES POSITION_INDEPENDENT_CODE ON)
if(CMAKE_HOST_WIN32)
    target_compile_definitions(proto PUBLIC PROTOBUF_USE_DLLS)
endif()