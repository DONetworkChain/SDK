
#ifndef __SIG_TX__
#define __SIG_TX__
#include "../proto/transaction.pb.h"
#include <string>

std::string txSign(CTransaction &tx, void *pkey);

//for rpc java
std::string txJsonSign(std::string &txjson, void *pkey);

//for rpc apple
//const char* txJsonSignA(const char* txjson, void *pkey);

std::string toSig(const std::string &data, void *pkey);

std::string ToChecksumAddress(const std::string &address);

std::string GenerateAddr(const std::string &publicKey);

std::string hexToBinary(const std::string &hexString);

int hexCharToDecimal(char c);

unsigned char *parseHexString(const char *hexString, size_t *arraySize);

char *uint8_to_hex_str_with_delim(const uint8_t *data, size_t len);
#endif