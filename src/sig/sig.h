
#ifndef __SIG_H_
#define __SIG_H_
#include <string>
static int PrimeSeedNum = 16;
static int DerivedSeedNum = 32;
extern "C"
{

    /**
     * @brief Import the private key
     *
     * @param buf  Private key memory address
     * @param buf_size  The length of the private key
     * @return void* EVP_PKEY
     */
    void *ImportEVP_PKEY(const unsigned char *buf, int buf_size);

    /**
     * @brief Generate a private key
     *
     * @param buf Private key secondary pointer
     * @param size  The length of the private key
     * @return true
     * @return false
     */

    bool ExportEVP_PKEY(unsigned char **buf, int *size);

    /**
     * @brief signature
     *
     * @param pkey ImportEVP_PKEY return value
     * @param message  The information to sign
     * @param size_message Information length
     * @param signature  Sign the result
     * @param size_signature Signature length
     * @return true
     * @return false
     */

    bool sig_(const void *pkey, const unsigned char *message, int size_message,
              unsigned char **signature, int *size_signature);

    /**
     * @brief Signature verification
     *
     * @param pkey ImportEVP_PKEY return value
     * @param message Information to be verified
     * @param size_message Information length
     * @param signature signature
     * @param size_signature Signature length
     * @return true
     * @return false
     */
    bool verf_(const void *pkey, const unsigned char *message, int size_message,
               unsigned char *signature, int size_signature);

    /**
     * @brief Import the private key from HexStr
     *
     * @param str
     * @return void*
     */
    void *ImportFromHexStr(const char *str);

    /**
     * @brief The private key is exported to HexStr
     *
     * @param pkey
     * @param buf
     * @param size
     * @return true
     * @return false
     */
    bool ExportToHexStr(const void *pkey, char **buf, int *size);

    /**
     * @brief Export mnemonics
     *
     * @param pkey
     * @param buf
     * @param size
     * @return true
     * @return false
     */
    bool ExportMnemonic(const uint8_t *seed, char **buf, int *size);

    /**
     * @brief Import mnemonics
     *
     * @param mnemonic
     * @return void*
     */
    void *ImportFromMnemonic(const char *mnemonic);

    void getAddr_c(const void *pkey, char **buf, int *size);

    void getPriStr_c(const void *pkey, char **buf, int *size);

    void getPubStr_c(const void *pkey, char **buf, int *size);

    void free_pkey(const void *pkey);

    /**
     * @brief       Generate Random Seed By OpenSSL
     *
     * @param       inputSeed
     * @return      uint8_t*
     */
    uint8_t *generate_random_seed(uint8_t *inputSeed);

    /**
     * @brief       generate EVP_PKEY
     *
     * @param       inputSeed
     * @return      char*
     */
    void *generate_EVP_PKEY_by_seed(uint8_t *inputSeed);

    /**
     * @brief       sha256hash
     *
     * @param       input
     * @param       input_len
     * @param       output
     */
    void sha256_hash(const uint8_t *input, size_t input_len, uint8_t *output);

    // void string_to_hex_array(const std::string& str, uint8_t* hex_array, size_t array_size);
    void string_to_hex_array(const char *str, size_t str_len, uint8_t *hex_array, size_t array_size);

    void *ImportSeed(const char *buf, int buf_size);

    bool ExportSeed(unsigned char **buf, int *size);

    void *GetPkeyBySeed(const unsigned char *buf, int buf_size);

    uint8_t *convertCharToUint8(const char *input, size_t length);

    char *convertUint8ToChar(const uint8_t *input, size_t length);

    void importAddrByPrivateKey(const char *prikey, size_t length, char *addr, size_t addr_size);

    void importBase58ByPrivateKey(const char *prikey, size_t length, char *base58, size_t base58_size);

    int isPrivateKeySame(const char *prikey, size_t length, const char *Base58);
}

#endif