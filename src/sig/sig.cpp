#include "sig.h"
#include "base58.h"
#include "bip39.h"
#include "debug.h"
#include "openssl/buffer.h"
#include "openssl/types.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <utility>
#include <memory.h>
#include "hexcode.h"
#include "keccak256.h"
#include <string>
#include <algorithm>
#include <iostream>
#include "sigTx.h"
#include "crypto/rand.h"
#include "base64.h"

bool sig(const void *pkey, const std::string &message, std::string &value);

bool verf(const void *pkey, const std::string &message, std::string &signature);

extern "C"
{

  EVP_PKEY *createEVP_KEY()
  {
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == nullptr)
    {
      EVP_PKEY_CTX_free(ctx);
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      std::cout << "keygen init fail" << std::endl;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
      EVP_PKEY_CTX_free(ctx);
      std::cout << "keygen fail\n"
                << std::endl;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
  }

  void *ImportEVP_PKEY(const unsigned char *buf, int buf_size)
  {
    EVP_PKEY *pkey = nullptr;
    BIO *bio = BIO_new_mem_buf((const void *)buf, buf_size);
    if (bio == nullptr)
    {
      errorL("BIO_new_mem_buf error!");
      BIO_free(bio);
      return nullptr;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    if (!pkey)
    {
      errorL("PEM_read_bio_PrivateKey error!");
      return nullptr;
    }
    BIO_free(bio);
    return (void *)pkey;
  }
  bool ExportEVP_PKEY(unsigned char **buf, int *size)
  {
    EVP_PKEY *pkey = createEVP_KEY();

    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == nullptr)
    {
      errorL("BIO_new_mem_buf error!");
      BIO_free(bio);
      return false;
    }
    if (1 != PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL))
    {
      errorL("PEM_write_bio_PrivateKey error!");
      BIO_free(bio);
      return false;
    }

    BUF_MEM *bptr;

    BIO_get_mem_ptr(bio, &bptr);
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);

    char *buffer_ = (char *)malloc(bptr->length);

    memcpy(buffer_, bptr->data, bptr->length);

    *buf = (unsigned char *)buffer_;
    *size = (int)bptr->length;

    BUF_MEM_free(bptr);
    return true;
  }

  bool sig_(const void *pkey, const unsigned char *message, int size_message, unsigned char **signature, int *size_signature)
  {
    std::string me((char *)message, size_message);
    std::string val;
    bool ret;
    ret = sig(pkey, me, val);
    unsigned char *rv = (unsigned char *)malloc(val.size());
    if (rv == nullptr)
    {
      free(rv);
      return false;
    }

    memcpy(rv, val.c_str(), val.size());
    *size_signature = val.size();
    *signature = rv;
    return true;
  }

  bool verf_(const void *pkey, const unsigned char *message, int size_message, unsigned char *signature, int size_signature)
  {
    std::string me((char *)message, size_message);
    std::string val((char *)signature, size_signature);
    bool ret;
    ret = verf(pkey, me, val);
    // unsigned char * rv=(unsigned char *)malloc(val.size());
    if (ret == false)
    {
      return false;
    }

    return true;
  }
}

bool sig(const void *pkey, const std::string &message_, std::string &value)
{
  EVP_PKEY *key = (EVP_PKEY *)pkey;

  EVP_MD_CTX *mdctx = NULL;
  const unsigned char *message = (const unsigned char *)message_.c_str();
  int message_size = message_.size();
  if (!(mdctx = EVP_MD_CTX_new()))
  {
    errorL("EVP_MD_CTX_new error!");
    return false;
  }
  if (pkey == NULL)
  {
    errorL("pkey is nullptr!");
    return false;
  }

  unsigned char *signuture = nullptr;
  // Initialise the DigestSign operation
  if (1 != EVP_DigestSignInit(mdctx, NULL, NULL, NULL, key))
  {
    return false;
  }

  size_t tmpMLen = 0;
  if (1 != EVP_DigestSign(mdctx, NULL, &tmpMLen, (const unsigned char *)message,
                          message_size))
  {
    return false;
  }

  signuture = (unsigned char *)OPENSSL_malloc(tmpMLen);

  if (1 != EVP_DigestSign(mdctx, signuture, &tmpMLen,
                          (const unsigned char *)message, message_size))
  {
    return false;
  }

  std::string hashString((char *)signuture, tmpMLen);
  value = std::move(hashString);

  OPENSSL_free(signuture);
  EVP_MD_CTX_free(mdctx);
  return true;
}

bool verf(const void *pkey, const std::string &message,
          std::string &signature)
{

  EVP_PKEY *key = (EVP_PKEY *)pkey;
  if (key == nullptr)
  {
    errorL("key is nullptr!");
    return false;
  }
  EVP_MD_CTX *mdctx = NULL;
  const char *msg = message.c_str();
  unsigned char *sig = (unsigned char *)signature.data();
  size_t slen = signature.size();
  size_t msg_len = strlen(msg);

  if (!(mdctx = EVP_MD_CTX_new()))
  {
    errorL("EVP_MD_CTX_new error");
    return false;
  }

  /* Initialize `key` with a public key */
  if (1 != EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, key))
  {
    EVP_MD_CTX_free(mdctx);
    errorL("EVP_DigestVerifyInit error");
    return false;
  }

  if (1 !=
      EVP_DigestVerify(mdctx, sig, slen, (const unsigned char *)msg, msg_len))
  {
    EVP_MD_CTX_free(mdctx);
    errorL("EVP_DigestVerify error");
    return false;
  }

  EVP_MD_CTX_free(mdctx);
  return true;
}

std::string getAddr(const void *pkey)
{
  EVP_PKEY *pkey_t = (EVP_PKEY *)pkey;
  unsigned char *pkey_der = NULL;
  int publen = i2d_PUBKEY(pkey_t, &pkey_der);
  std::string pubStr;
  for (int i = 0; i < publen; ++i)
  {
    pubStr += pkey_der[i];
  }
  return GenerateAddr(pubStr);
}

std::string getPriStr(const void *pkey)
{
  EVP_PKEY *pkey_t = (EVP_PKEY *)pkey;

  size_t len = 80;
  char pkey_data[80] = {0};
  if (EVP_PKEY_get_raw_private_key(pkey_t, (unsigned char *)pkey_data, &len) == 0)
  {
    return "error";
  }

  std::string data(pkey_data, len);
  return data;
}

std::string getPubStr(const void *pkey)
{
  EVP_PKEY *pkey_t = (EVP_PKEY *)pkey;
  unsigned char *pkey_der = NULL;
  int publen = i2d_PUBKEY(pkey_t, &pkey_der);
  std::string pubStr;
  for (int i = 0; i < publen; ++i)
  {
    pubStr += pkey_der[i];
  }
  return pubStr;
}

void *ImportFromHexStr(const char *str)
{
  std::string privateKeyHex(str);
  std::string priStr_ = Hex2Str(privateKeyHex);
  unsigned char *buf_ptr = (unsigned char *)priStr_.data();
  const unsigned char *pk_str = buf_ptr;

  EVP_PKEY *pkey_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, pk_str, priStr_.size());
  if (pkey_ == nullptr)
  {
    return nullptr;
  }

  return pkey_;
}

bool ExportToHexStr(const void *pkey, char **buf, int *size)
{
  std::string pri = getPriStr(pkey);
  if (pri == "error")
  {
    return false;
  }
  std::string strPriHex = Str2Hex(pri);
  char *buffer = (char *)malloc(strPriHex.size() + 1);
  buffer[strPriHex.size()] = 0;
  memcpy(buffer, strPriHex.c_str(), strPriHex.size());
  *buf = buffer;
  *size = strPriHex.size();
  return true;
}

bool ExportMnemonic(const uint8_t *seed, char **buf, int *size)
{
  // std::string priStr=getPriStr(pkey);
  // char * buffer=(char *)malloc(1024);
  // mnemonic_from_data((const uint8_t*)priStr.data(), priStr.size(), buffer, 1024);
  //*buf=buffer;
  //*size=1024;
  // return true;
  char *buffer = (char *)malloc(1024);
  mnemonic_from_data(seed, PrimeSeedNum, buffer, 1024);
  *buf = buffer;
  *size = 1024;
  return true;
}

void *ImportFromMnemonic(const char *mnemonic)
{
  char out[33] = {0};
  int outLen = 0;
  if (mnemonic_check((char *)mnemonic, out, &outLen) == 0)
  {
    return nullptr;
  }
  char mnemonic_hex[65] = {0};
  encode_hex(mnemonic_hex, out, outLen);

  uint8_t *seed = (uint8_t *)malloc(sizeof(uint8_t) * 16);
  string_to_hex_array(mnemonic_hex, 65, seed, PrimeSeedNum);

  return seed;
}

void getAddr_c(const void *pkey, char **buf, int *size)
{
  std::string addr = getAddr(pkey);
  char *buffer = (char *)malloc(addr.size() + 1);
  buffer[addr.size()] = 0;
  memcpy(buffer, addr.c_str(), addr.size());
  *buf = buffer;
  *size = addr.size();
}

void getPriStr_c(const void *pkey, char **buf, int *size)
{
  std::string pristr = getPriStr(pkey);
  char *buffer = (char *)malloc(pristr.size() + 1);
  buffer[pristr.size()] = 0;
  memcpy(buffer, pristr.c_str(), pristr.size());
  *buf = buffer;
  *size = pristr.size();
}

void getPubStr_c(const void *pkey, char **buf, int *size)
{
  std::string pubstr = getPubStr(pkey);
  char *buffer = (char *)malloc(pubstr.size() + 1);
  buffer[pubstr.size()] = 0;
  memcpy(buffer, pubstr.c_str(), pubstr.size());
  *buf = buffer;
  *size = pubstr.size();
}

void free_pkey(const void *pkey)
{
  EVP_PKEY *pkey_t = (EVP_PKEY *)pkey;
  EVP_PKEY_free(pkey_t);
}

void sha256_hash(const uint8_t *input, size_t input_len, uint8_t *output)
{
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, input, input_len);
  SHA256_Final(output, &ctx);
}

uint8_t *generate_random_seed(uint8_t *inputSeed)
{

  RAND_bytes(inputSeed, PrimeSeedNum);
  // test input seed
  // int is;
  //  for (int i = 0; i < PrimeSeedNum; i++) {
  //    is = inputSeed[i];
  //      std::cout << std::hex <<(int)is <<"-";
  //  }
  return inputSeed;
}

void *generate_EVP_PKEY_by_seed(uint8_t *inputSeed)
{
  EVP_PKEY *pkeyPtr;
  uint8_t outputArr[SHA256_DIGEST_LENGTH];
  sha256_hash(inputSeed, PrimeSeedNum, outputArr);
  pkeyPtr = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, outputArr, DerivedSeedNum);

  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(bio, pkeyPtr, NULL, NULL, 0, NULL, NULL);

  char *pemData = nullptr;
  long pemDataSize = BIO_get_mem_data(bio, &pemData);

  // Copy the pem data to the new buffer
  char *pemDataCopy = new char[pemDataSize];
  memcpy(pemDataCopy, pemData, pemDataSize);

  // Release resources
  BIO_free(bio);
  EVP_PKEY_free(pkeyPtr);

  return pemDataCopy;
}

// void string_to_hex_array(const std::string& str, uint8_t* hex_array, size_t array_size) {
//     size_t str_len = str.length();
//     size_t copy_len = std::min(str_len / 2, array_size);
//
//     for (size_t i = 0, j = 0; i < copy_len; i++, j += 2) {
//         std::string byte_str = str.substr(j, 2);
//         hex_array[i] = (uint8_t)(strtol(byte_str.c_str(), nullptr, 16));
//     }
// }

void string_to_hex_array(const char *str, size_t str_len, uint8_t *hex_array, size_t array_size)
{
  size_t copy_len = (str_len / 2 < array_size) ? str_len / 2 : array_size;

  for (size_t i = 0, j = 0; i < copy_len; i++, j += 2)
  {
    char byte_str[3] = {str[j], str[j + 1], '\0'};
    hex_array[i] = (uint8_t)strtol(byte_str, NULL, 16);
  }
}
// import seed uint8_t
void *ImportSeed(const char *buf, int buf_size)
{
  // Allocates memory space to store a uint8t array
  uint8_t *seed = (uint8_t *)(malloc(buf_size * sizeof(uint8_t)));
  if (seed == nullptr)
  {
    // memory allocation failure
    return nullptr;
  }

  // Copy the data from buf into the seed array
  memcpy(seed, buf, buf_size);

  // Returns a pointer to the seed array
  return (void *)(seed);
}

bool ExportSeed(unsigned char **buf, int *size)
{
  uint8_t *seedGet = (uint8_t *)(malloc(PrimeSeedNum * sizeof(uint8_t)));
  if (seedGet == nullptr)
  {
    // Memory allocation failure
    return false;
  }

  if (!generate_random_seed(seedGet))
  {
    free(seedGet);
    return false;
  }
  // Converts uint8_t* to an unsigned char*
  *buf = (unsigned char *)(seedGet);

  *size = PrimeSeedNum;

  return true;
}

void *GetPkeyBySeed(const unsigned char *buf, int buf_size)
{
  // Allocates memory space to store a uint8t array
  uint8_t *seed = (uint8_t *)(malloc(buf_size * sizeof(uint8_t)));
  if (seed == nullptr)
  {
    // memory allocation failure
    return nullptr;
  }

  // Copy the data from buf into the seed array
  memcpy(seed, buf, buf_size);

  uint8_t outputArr[SHA256_DIGEST_LENGTH];

  sha256_hash(seed, PrimeSeedNum, outputArr);

  EVP_PKEY *pkey_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, outputArr, 32);
  if (pkey_ == nullptr)
  {
    return nullptr;
  }

  return (void *)pkey_;
}

int hex_to_int(char c)
{
  if (isdigit(c))
  {
    return c - '0';
  }
  else if (tolower(c) >= 'a' && tolower(c) <= 'f')
  {
    return tolower(c) - 'a' + 10;
  }
  else
  {
    return -1;
  }
}

uint8_t *convertCharToUint8(const char *input, size_t length)
{
  if (length % 2 != 0 || length == 0)
  {
    return NULL;
  }
  size_t arr_length = length / 2;
  uint8_t *arr = (uint8_t *)malloc(arr_length * sizeof(uint8_t));
  if (arr == NULL)
  {
    return NULL;
  }

  for (size_t i = 0; i < arr_length; i++)
  {
    char high = input[i * 2];
    char low = input[i * 2 + 1];

    if (!isxdigit(high) || !isxdigit(low))
    {
      free(arr);
      return NULL;
    }

    arr[i] = (uint8_t)((hex_to_int(high) << 4) | hex_to_int(low));
  }

  return arr;
}

// Converts a uint8_t array to a char* array
char *convertUint8ToChar(const uint8_t *input, size_t length)
{
  char *output = (char *)malloc((length + 1) * sizeof(char));
  memcpy(output, input, length);
  output[length] = '\0'; // Adds the null character at the end of the string
  return output;
}

char *getPubStr_base64(const void *pkey, char *buf, int size)
{
  Base64 base_;
  std::string ret = base_.Encode((const unsigned char *)buf, size);
  // Allocate enough memory to store the converted string, including the null character at the end
  char *output = new char[ret.length() + 1];
  std::strcpy(output, ret.c_str());
  return output;
}

void importAddrByPrivateKey(const char *prikey, size_t length, char *addr, size_t addr_size)
{
  // get input
  void *hexPriKeyHandler = ImportFromHexStr(prikey);
  // transinput addr to prikey
  std::string addr_str = getAddr(hexPriKeyHandler);
  char *addr_c = new char[addr_str.length() + 1];

  std::strcpy(addr_c, addr_str.c_str());
  if (addr && length <= addr_size)
  {
    std::memcpy(addr, addr_str.c_str(), length);
    addr[length - 1] = '\0';
  }
}
void importBase58ByPrivateKey(const char *prikey, size_t length, char *base58, size_t base58_size)
{
  // get input
  std::string privateKeyHex(prikey);
  std::string priStr_ = Hex2Str(privateKeyHex);
  std::string pubStr_;
  unsigned char *buf_ptr = (unsigned char *)priStr_.data();
  const unsigned char *pk_str = buf_ptr;

  EVP_PKEY *pkey_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, pk_str, priStr_.size());
  if (pkey_ == nullptr)
  {
    return;
  }

  std::string pubStr = getPubStr(pkey_);
  char buf[2048] = {0};
  size_t buf_len = sizeof(buf);
  unsigned char md160[RIPEMD160_DIGEST_LENGTH];
  bu_Hash160(md160, pubStr.data(), pubStr.size());
  if (b58check_enc(buf, &buf_len, 0, md160, RIPEMD160_DIGEST_LENGTH) != true)
  {
    return;
  }
  if (base58 && length <= base58_size)
  {
    std::memcpy(base58, buf, buf_len);
    base58[length - 1] = '\0';
  }
  EVP_PKEY_free(pkey_);
}

int isPrivateKeySame(const char *prikey, size_t length, const char *Base58)
{
  char tmpBase58[2048] = {0};
  importBase58ByPrivateKey(prikey, length, tmpBase58, 2048);
  if (strcmp(tmpBase58, Base58) != 0)
  {
    std::cout << "Base58 error" << std::endl;
    return -1;
  }

  char tmpAddr[2048];
  importAddrByPrivateKey(prikey, length, tmpAddr, 2048);
  if (tmpAddr == nullptr || tmpAddr[0] == '\0')
  {
    std::cout << "New Addr error";
    return -2;
  }
  return 0;
}
