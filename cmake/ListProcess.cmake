set(WASM_EXPORTED_RUNTIME_METHODS cwrap getValue ccall)
list(TRANSFORM WASM_EXPORTED_RUNTIME_METHODS PREPEND ')
list(TRANSFORM WASM_EXPORTED_RUNTIME_METHODS APPEND ')
string(REPLACE ";" "," exported_runtime_methods "${WASM_EXPORTED_RUNTIME_METHODS}")

set(WASM_EXPORTED_FUNCTIONS
        import_base64_prikey_handler
        export_new_prikey_base64
        export_new_seed
        import_prikey_handler_from_hex
        import_prikey_handler_from_seed
        export_new_prikey_to_hex
        export_mnemonic_from_seed
        import_seed_from_mnemonic
        get_addr
        get_pubstr_base64
        sig_tx
        sig_contract_tx
        free_prikey_handler
        malloc
        sign
        verif_by_public_str
        get_version
        txJsonSign
        )

list(TRANSFORM WASM_EXPORTED_FUNCTIONS PREPEND '_)
list(TRANSFORM WASM_EXPORTED_FUNCTIONS APPEND ')
string(REPLACE ";" "," exported_functions "${WASM_EXPORTED_FUNCTIONS}")