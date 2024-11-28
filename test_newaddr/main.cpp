
#include "../src/envelop/base64.h"
#include "../src/envelop/debug.h"
#include "../src/sig/sig.h"
#include "../src/envelop/tx.h"
#include "../src/envelop/new_tx.h"
#include "../src/sig/Mac.h"
#include "../src/envelop/keccak256.h"
#include "../src/envelop/httplib.h"
#include "../src/envelop/hexcode.h"
#include "../src/interface.h"
#include "../src/envelop/json.hpp"
#include <cstdlib>
#include <exception>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <tuple>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include "openssl/rand.h"
#include <charconv>
#include "../src/sig/sigTx.h"
void test()
{
    //const char* input = "Hello, world!";
    //char* output = Keccak256(input);
    //std::cout << "Keccak256 hash of '" << input << "' is: " << output << std::endl;
    //free(output);
}

// void test1()
// {
//     const std::string pkey_str = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUdBSXVoSkQ0eWlwakJZYTYvL2Z4N0VuYU92cmRBVWlMZDQ1a1JXcm53aHcKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=";
//     long long pkey = import_base64_prikey_handler(pkey_str.c_str(),pkey_str.size());
//     char * hexPriKey = export_new_prikey_to_hex(pkey);
//     long long hexPriKeyHandler = import_prikey_handler_from_hex(hexPriKey);
//     char * addr = get_addr(pkey);
//     char * resultAddr = get_addr(hexPriKeyHandler);
//     std::cout<<"addr:"<< addr <<std::endl;
//     std::cout<<"resultAddr:"<< resultAddr <<std::endl;
//     free_prikey_handler(hexPriKeyHandler);
// }

// void test2()
// {
//     const std::string pkey_str = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSU5VVnZoczNXOWlNTmMvTlhaNUZhcnB2Z2lzTVpxTDR1S0RTSFNQQVlkNTQKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=";
//     long long pkey = import_base64_prikey_handler(pkey_str.c_str(),pkey_str.size());
//     char * hexPriKey = export_new_prikey_to_hex(pkey);
//     long long hexPriKeyHandler = import_prikey_handler_from_hex(hexPriKey);
//     char * addr = get_addr(pkey);
//     char * resultAddr = get_addr(hexPriKeyHandler);
//     std::cout<<"addr:"<< addr <<std::endl;
//     std::cout<<"resultAddr:"<< resultAddr <<std::endl;
//     free_prikey_handler(hexPriKeyHandler);
// }

int main(){
    // test();
    // test1();
    // std::cout<<"------------------"<<std::endl;
    // test2();
    // _pubStr:302a300506032b6570032100e3f2943c4d5dc2742edc92d8fa14f88a81e52ff6ca138da559cb4e03f39f2388
    // _addr:2e8f8F3A13b994bC2C2D36E4a5F78f90C0c49ffD
    std::cout<<"------------------"<<std::endl;
    const std::string pubStr = "302a300506032b6570032100e3f2943c4d5dc2742edc92d8fa14f88a81e52ff6ca138da559cb4e03f39f2388";
    // addr:2e8f8F3A13b994bC2C2D36E4a5F78f90C0c49ffD
    // resultAddr:2e8f8F3A13b994bC2C2D36E4a5F78f90C0c49ffD
    std::string addr2 = GenerateAddr(hexToBinary(pubStr));
    std::cout<<"addr2:"<< addr2 << std::endl;

    
    //get seed 
    //get pkey
    //get getaddr

}

