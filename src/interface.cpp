#include "interface.h"
#include "debug.h"
#include "google/protobuf/util/json_util.h"
#include "sig.h"
#include "sigTx.h"
#include <cstring>
#include "base64.h"
#include "evmc.h"
#include "openssl/types.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "Mac.h"
#include "transaction.pb.h"
#include "tx.h"
#include "new_tx.h"
#include <iomanip>

const char *get_version()
{
#ifdef DON_SDK_VERSION
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
    return const_cast<char *>(STR(DON_SDK_VERSION));
#undef STR_HELPER
#undef STR
#else
    return const_cast<char *>("unknow version");
#endif
}

long long import_base64_prikey_handler(const char *buf, int buf_size)
{
    std::string dbase = FromBase64(buf, buf_size);
    return (long long)ImportEVP_PKEY((const unsigned char *)dbase.c_str(), dbase.size());
}


char *export_new_prikey_base64()
{
    unsigned char *buf = NULL;
    int size_ = 0;
    ExportEVP_PKEY(&buf, &size_);
    char *buffer = toBase64((const char *)buf, size_);

    return (char *)buffer;
}

char *export_new_seed()
{
    unsigned char *buf = NULL;
    int size_ = 0;
    ExportSeed(&buf, &size_);

    char *char_data = uint8_to_hex_str_with_delim(buf, size_);

    //char *buffer = toBase64(char_data, strlen(char_data));
    return (char *)char_data;
}

long long import_prikey_handler_from_hex(const char *str)
{
    return (long long)ImportFromHexStr(str);
}

long long import_prikey_handler_from_seed(char *seed)
{
    // test seed output
    size_t arraySize;
    unsigned char *byteArray = parseHexString(seed, &arraySize);

    return (long long)GetPkeyBySeed(byteArray, 16);
}

char *export_new_prikey_to_hex(long long pkey)
{
    char *buf = NULL;
    int size_ = 0;
    ExportToHexStr((const void *)pkey, &buf, &size_);
    return buf;
}

char *export_mnemonic_from_seed(const char *seed)
{
    char *buf = NULL;
    int size = 0;
    size_t arraySize;
    unsigned char *byteArray = parseHexString(seed, &arraySize);
    ExportMnemonic(byteArray, &buf, &size);
    if (buf == NULL)
    {
        return NULL; // Return NULL if ExportMnemonic fails
    }
    return buf;
}

char *import_seed_from_mnemonic(const char *mnemonic)
{
    return uint8_to_hex_str_with_delim((uint8_t *)ImportFromMnemonic(mnemonic), 16);
}

char *get_addr(long long pkey)
{
    char *buf = NULL;
    int size_ = 0;
    getAddr_c((const void *)pkey, &buf, &size_);
    return buf;
}

char *get_pubstr_base64(long long pkey)
{
    char *buf = NULL;
    int size_ = 0;
    // getPubStr_c((const void *)pkey, &buf,&size_);
    std::string ret = getPubStr((const void *)pkey);
    Base64 base_;
    std::string res = base_.Encode((const unsigned char *)ret.c_str(), ret.size());
    buf = (char *)malloc(res.size() + 1);
    buf[res.size()] = 0;
    memcpy(buf, res.c_str(), res.size());
    //        std::cout << "pub: " ;
    //        std::string p(buf, res.size()+1);
    //        for (char c : ret) {
    //            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << " ";
    //        }
    //        std::cout << std::endl;
    //        std::cout << "pub:" << res.size() + 1 <<std::endl;
    return buf;
}

char *sig_tx(const char *message, int msize, long long pkey)
{
    std::string msg(message, msize);
    std::string res = toSig(msg, (void *)pkey);
    char *buf = (char *)malloc(res.size() + 1);
    buf[res.size()] = 0;
    memcpy(buf, res.c_str(), res.size());
    return buf;
}

void free_prikey_handler(long long pkey)
{
    free_pkey((const void *)pkey);
}




char * sig_contract_tx(const char *message ,int msize, long long pkey){
     std::string msg(message,msize);
     contractAck ack;
     ack._paseFromJson(msg);

     CTransaction tx;
     google::protobuf::util::JsonStringToMessage(ack.txJson, &tx);
     txSign(tx, (void *)pkey);
     std::string re;
     google::protobuf::util::MessageToJsonString(tx,&re);
     ack.txJson=re;

    std::string res=ack._paseToString();
    char * buffer=new char[res.size()+1];
    buffer[res.size()]=0;
    memcpy(buffer,res.c_str(),res.size());
    return buffer;
}

char *sign(const char *message, int mesage_size, long long pkey)
{
    char *signature = NULL;
    int sign_size = 0;
    if (!Sign(pkey, message, mesage_size, &signature, &sign_size))
    {
        std::cout << "sign fail" << std::endl;
        return NULL;
    }
    std::string ret(signature, sign_size);
    Base64 base_;
    std::string res = base_.Encode((const unsigned char *)ret.c_str(), ret.size());
    char *buf = (char *)malloc(res.size() + 1);
    buf[res.size()] = 0;
    memcpy(buf, res.c_str(), res.size());
    return buf;
}

int verif_by_public_str(const char *pubstr, int pubsize, const char *message, int messagesize, const char *signature, int signature_size)
{
    std::string pub = FromBase64(pubstr, pubsize);
    std::string sig = FromBase64(signature, signature_size);
    if (VerifByPublicStr(pub.c_str(), pub.size(), message, messagesize, sig.c_str(), sig.size()))
    {
        return 0;
    }
    return -1;
}

bool VerifByPublicStr(const char *pubstr, int pubsize, const char *message, int messagesize, const char *signature, int signature_size)
{
    //    std::string a(message, messagesize);
    //    std::cout << "message: " << a <<std::endl;
    //    std::string b(signature, signature_size);
    //    std::cout << "sign: ";
    //
    //    for (char c : b) {
    //        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << " ";
    //    }
    //    std::cout << std::endl;
    //    std::string p(pubstr, pubsize);
    //    std::cout << "pub: " ;
    //    for (char c : p) {
    //        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << " ";
    //    }
    //    std::cout << std::endl;
    const unsigned char *s = (const unsigned char *)pubstr;
    EVP_PKEY *peerPubKey = d2i_PUBKEY(NULL, &s, pubsize);

    EVP_MD_CTX *mdctx = NULL;
    const char *msg = message;
    unsigned char *sig = (unsigned char *)signature;
    size_t slen = signature_size;
    size_t msgLen = messagesize;

    if (!(mdctx = EVP_MD_CTX_new()))
    {
        return false;
    }
    if (1 != EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, peerPubKey))
    {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(peerPubKey);
        return false;
    }

    if (1 != EVP_DigestVerify(mdctx, sig, slen, (const unsigned char *)msg, msgLen))
    {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(peerPubKey);
        return false;
    }
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(peerPubKey);
    return true;
}

bool Sign(long long pkey, const char *message, int mesage_size, char **signature, int *signature_size)
{
    //    std::string a(message, mesage_size);
    //    std::cout << "message: " << a <<std::endl;
    EVP_MD_CTX *mdctx = NULL;
    const char *sig_name = message;

    unsigned char *sigValue = NULL;
    size_t sig_len = mesage_size;

    // Create the Message Digest Context
    if (!(mdctx = EVP_MD_CTX_new()))
    {
        return false;
    }

    if ((EVP_PKEY *)pkey == NULL)
    {
        return false;
    }

    // Initialise the DigestSign operation
    if (1 != EVP_DigestSignInit(mdctx, NULL, NULL, NULL, (EVP_PKEY *)pkey))
    {
        return false;
    }

    size_t tmpMLen = 0;
    if (1 != EVP_DigestSign(mdctx, NULL, &tmpMLen, (const unsigned char *)sig_name, sig_len))
    {
        return false;
    }

    sigValue = (unsigned char *)OPENSSL_malloc(tmpMLen);

    if (1 != EVP_DigestSign(mdctx, sigValue, &tmpMLen, (const unsigned char *)sig_name, sig_len))
    {
        return false;
    }

    std::string hashString((char *)sigValue, tmpMLen);
    //
    char *buffer_ = (char*)malloc(tmpMLen * sizeof(char));
    memcpy(buffer_, hashString.c_str(), tmpMLen);
    *signature = buffer_;
    *signature_size = tmpMLen;
    OPENSSL_free(sigValue);
    EVP_MD_CTX_free(mdctx);
    //    std::string b(*signature, *signature_size);
    //    std::cout << "sign: ";
    //    for (char c : b) {
    //        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << " ";
    //    }
    //    std::cout << std::endl;
    return true;
}

char* txJsonSign(const char* txjson, void *pkey)
{
    std::string tmptxjson(txjson);
    std::string tmpretrun = txJsonSign(tmptxjson, pkey);

    size_t len = tmpretrun.length();
    
    char* c_str =(char*)malloc((len + 1)* sizeof(char));
    

    tmpretrun.copy(c_str, len, 0);

    c_str[len] = '\0';
    
    return c_str;
}