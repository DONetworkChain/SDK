#pragma once
#include "base64.h"
#include <string>
#include <vector>
class Base64
{
    std::string _base64_table;
    std::vector<uint8_t> _base64_tablevec;
    static const char base64_pad = '='; public:
    Base64()
    {
        _base64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; 
        _base64_tablevec = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };
    }
   
public:
    std::string Encode(const unsigned char* str, int bytes);
    std::string Decode(const char* str, int bytes);
    std::vector<uint8_t> EncodeVec(const uint8_t * array,int bytes);
    std::vector<uint8_t> DecodeVec(const uint8_t * array,int bytes);
};


char * toBase64(const char * src,int size);

char * toBase64(const std::string & str);

std::string FromBase64(const char * str,int size);

std::string FromBase64(const std::string & str);
