#include "util2.h"
#include <openssl/sha.h>
#include <openssl/evp.h>

void bu_Hash(unsigned char *md256, const void *data, size_t data_len)
{
    unsigned char md1[SHA256_DIGEST_LENGTH];

  //  sha256_Raw(data, data_len, md1);
    SHA256((const unsigned char *)data, data_len, md1);
    SHA256(md1, SHA256_DIGEST_LENGTH, md256);
}

void bu_Hash4(unsigned char *md32, const void *data, size_t data_len)
{   
    unsigned char md256[SHA256_DIGEST_LENGTH];
    
    bu_Hash(md256, data, data_len); 
    memcpy(md32, md256, 4);
} 

void bu_Hash160(unsigned char *md160, const void *data, size_t data_len)
{
    unsigned char md1[SHA256_DIGEST_LENGTH];

    SHA256((const unsigned char*)data, data_len, md1);
    ripemd160(md1, SHA256_DIGEST_LENGTH, md160);
}


