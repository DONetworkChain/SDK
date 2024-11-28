#include "sigTx.h"
#include "base64.h"
#include "google/protobuf/util/json_util.h"
#include "base58.h"
#include "sig.h"
#include "debug.h"
#include "../envelop/new_tx.h"
#include <set>
#include "Mac.h"
#include "keccak256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iomanip>

std::string txSign(CTransaction &tx, void *pkey)
{
    std::set<std::string> Miset;
    Base64 base_;
    auto txUtxo = tx.mutable_utxo();
    int index = 0;
    auto vin = txUtxo->mutable_vin();
    for (auto &owner : txUtxo->owner())
    {

		Miset.insert(owner);
		auto vin_t = vin->Mutable(index);
        if(!vin_t->contractaddr().empty()){
			index++;
            continue;
        }
		std::string serVinHash = getsha256hash(vin_t->SerializeAsString());
		std::string signature;
		std::string pub;
		unsigned char* signature_c = nullptr;
		int size;
		
		bool ret=sig_(pkey, (const unsigned char*)serVinHash.c_str(), serVinHash.size(), &signature_c, &size);
		signature = std::string((const char *)signature_c, size);
		free(signature_c);
		pub = getPubStr(pkey);
		std::string addr = GenerateAddr(pub);
		debugL("addr %s", addr);


        // debugL("pub_======:" << base_.Encode((const unsigned char *)pub.c_str(), pub.size()));
        // debugL("sig_======:" << base_.Encode((const unsigned char *)signature.c_str(), signature.size()));

        if (ret == false)
        {
            debugL("sign fail ");
        }

		CSign* vinSign = vin_t->mutable_vinsign();
		vinSign->set_sign(signature);
		vinSign->set_pub(pub);
		index++;
	}

	

	for (auto& owner : Miset) {
		CTxUtxo* txUtxo = tx.mutable_utxo();
		CTxUtxo copyTxUtxo = *txUtxo;
		copyTxUtxo.clear_multisign();
		std::string serTxUtxo = getsha256hash(copyTxUtxo.SerializeAsString());
		std::string signature;
		std::string pub;
		unsigned char* signature_c = nullptr;
		int size;

		bool ret = sig_(pkey, (const unsigned char*)serTxUtxo.c_str(), serTxUtxo.size(), &signature_c, &size);
		signature = std::string((const char*)signature_c, size);
		free(signature_c);
		pub = getPubStr(pkey);

		//debugL("pub_++++++:" << base_.Encode((const unsigned char *)pub.c_str(), pub.size()));
		//debugL("sig_++++++:" << base_.Encode((const unsigned char *)signature.c_str(), signature.size()));

		if (ret == false) {
			debugL("sign fail ");
		}
		CSign* multiSign = txUtxo->add_multisign();
		multiSign->set_sign(signature);
		multiSign->set_pub(pub);
	}
	return "0";
}


std::string toSig(const std::string& data,void * pkey) {
	txAck ack;
	ack._paseFromJson(data);
	CTransaction tx_t;
	google::protobuf::util::Status status = google::protobuf::util::JsonStringToMessage(ack.txJson, &tx_t);

	txSign(tx_t,pkey);

	std::string txJsonString;
	status = google::protobuf::util::MessageToJsonString(tx_t, &txJsonString);
	ack.txJson = txJsonString;
	return ack._paseToString();
}



std::string hexToBinary(const std::string &hexString)
{
    std::string binaryString;

    for (size_t i = 0; i < hexString.length(); i += 2)
    {
        std::string hexByte = hexString.substr(i, 2);
        try
        {
            int decimalValue = std::stoi(hexByte, nullptr, 16);
            binaryString += static_cast<char>(decimalValue);
        }
        catch (const std::invalid_argument &)
        {
            std::cout << "hextoBinary error";
            return "";
        }
    }

    return binaryString;
}

std::string ToChecksumAddress(const std::string &address)
{
    std::string addressNoPrefix = address.substr(0, 2) == "0x" ? address.substr(2) : address;
    std::transform(addressNoPrefix.begin(), addressNoPrefix.end(), addressNoPrefix.begin(), ::tolower);

    // const uint8_t* data = reinterpret_cast<const uint8_t*>(addressNoPrefix.c_str());
    std::string hash = Keccak256(addressNoPrefix);

    std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);

    for (size_t i = 0; i < addressNoPrefix.size(); ++i)
    {
        if (hash[i] >= '8' && addressNoPrefix[i] >= 'a' && addressNoPrefix[i] <= 'f')
        {
            addressNoPrefix[i] = toupper(addressNoPrefix[i]);
        }
    }
    addressNoPrefix = "0x" + addressNoPrefix;
    return addressNoPrefix;
}

std::string GenerateAddr(const std::string &publicKey)
{
    std::string hash = Keccak256(publicKey);

    std::string addr = hash.substr(hash.length() - 40);
    return ToChecksumAddress(addr);
}

int hexCharToDecimal(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    else if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    else if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    else
    {
        throw std::invalid_argument("Invalid hex character");
    }
}

unsigned char *parseHexString(const char *hexString, size_t *arraySize)
{
    size_t length = strlen(hexString);
    size_t byteCount = 0;
    unsigned char* byteArray = NULL;

    // First calculate the size of the byte array to be allocated
    for (size_t i = 0; i < length; i += 2)
    {
        byteCount++;
    }

    // Allocates memory space and parses hexadecimal bytes one by one
    byteArray = (unsigned char*)malloc(byteCount * sizeof(unsigned char));
    size_t j = 0;
    for (size_t i = 0; i < length; i += 2)
    {
        char hexByte[3] = { hexString[i], hexString[i + 1], '\0' };
        byteArray[j++] = (unsigned char)strtol(hexByte, NULL, 16);
    }

    *arraySize = byteCount;
    return byteArray;
}

char *uint8_to_hex_str_with_delim(const uint8_t *data, size_t len)
{
    char *hex_str = (char *)malloc((len * 2) + 1); // Each byte requires 2 hexadecimal numbers + 1 separator
    hex_str[0] = '\0';                             // Initialize to an empty string

    for (size_t i = 0; i < len; i++)
    {
        sprintf(hex_str + strlen(hex_str), "%02x", data[i]);
    }

    return hex_str;
}

std::string txJsonSign(std::string &txjson, void *pkey)
{
	CTransaction tx_t;
	google::protobuf::util::Status status = google::protobuf::util::JsonStringToMessage(txjson, &tx_t);

	txSign(tx_t,pkey);

	std::string txJsonString;
	status = google::protobuf::util::MessageToJsonString(tx_t, &txJsonString);
	txjson = txJsonString;
	return txjson;
}
