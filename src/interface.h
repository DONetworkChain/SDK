#include <stdint.h>
#ifdef __cplusplus
extern "C"
{

#endif

    const char *get_version();

    long long import_base64_prikey_handler(const char *buf, int buf_size);

    char *export_new_prikey_base64();

    char *export_new_seed();

    long long import_prikey_handler_from_hex(const char *str);

    long long import_prikey_handler_from_seed(char *seed);

    char *export_new_prikey_to_hex(long long pkey);

    char *export_mnemonic_from_seed(const char *seed);

    char *import_seed_from_mnemonic(const char *mnemonic);

    char *get_addr(long long pkey);

    char *get_pubstr_base64(long long pkey);

    char *sig_tx(const char *message, int msize, long long pkey);
    char *sig_contract_tx(const char *message, int msize, long long pkey);
    void free_prikey_handler(long long pkey);

    char* txJsonSign(const char* txjson, void *pkey);

    /**
     * @brief
     *
     * @param       message
     * @param       mesage_size
     * @param       pkey
     * @return      char*
     */
    char *sign(const char *message, int mesage_size, long long pkey);

    /**
     * @brief
     *
     * @param       pubstr
     * @param       pubsize
     * @param       message
     * @param       messagesize
     * @param       signature
     * @param       signature_size
     * @return      int
     */
    int verif_by_public_str(const char *pubstr, int pubsize, const char *message, int messagesize, const char *signature, int signature_size);

    [[deprecated("Sign is no longer recommended. sign is suggested as a replacement")]]
    bool Sign(long long pkey, const char *message, int mesage_size, char **signature, int *signature_size);

    [[deprecated("VerifByPublicStr is no longer recommended. verif_by_public_str is suggested as a replacement")]]
    bool VerifByPublicStr(const char *pubstr, int pubsize, const char *message, int messagesize, const char *signature, int signature_size);

#ifdef __cplusplus
}
#endif