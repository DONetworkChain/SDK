add_library(envelop OBJECT
        base58.cpp
        base64.cpp
        bip39.cpp
        Envelop.cpp
        hexcode.cpp
        ripemd160.cpp
        RSA_TEXT.cpp
        sha2.cpp
        new_tx.cpp
        util2.cpp
        evmc.cpp
        keccak256.cpp
        )

include_directories(${CMAKE_SOURCE_DIR}/cryptopp)
target_include_directories(envelop PUBLIC . PRIVATE ${ExternalDependenciesDirectory}/include)
set_target_properties(envelop PROPERTIES POSITION_INDEPENDENT_CODE ON)
