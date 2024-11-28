add_library(sig OBJECT
        sig.cpp
        sigTx.cpp
        )

target_include_directories(sig PUBLIC .)
target_link_libraries(sig PRIVATE envelop proto)
set_target_properties(sig PROPERTIES POSITION_INDEPENDENT_CODE ON)