#include "../src/envelop/base64.h"
#include "../src/envelop/debug.h"
#include "../src/sig/sig.h"
#include "../src/envelop/tx.h"
#include "../src/envelop/new_tx.h"
#include "../src/sig/Mac.h"
#include "../src/envelop/keccak256.h"
#include "../src/envelop/httplib.h"
#include "../src/interface.h"
#include "../src/envelop/json.hpp"
#include <cstdlib>
#include <exception>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <tuple>

#include "../src/envelop/hexcode.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include "openssl/rand.h"
#include <charconv>
#include "../src/sig/sigTx.h"
#include "../src/envelop/Envelop.h"

std::string readAllFile(const std::string &path)
{
    std::ifstream fin(path);       // filename: xly2016I.txt
    std::stringstream buffer;      // stringstream object
    buffer << fin.rdbuf();         // read file content in stringstream object
    std::string str(buffer.str()); // store file content in a string
    return str;
}

std::string RpcGet(const std::string &req, const std::string &rpc_api)
{

    httplib::Headers headers = {
        {"content-type", "application/json"}};

    httplib::Client cli("192.168.1.35", 11190);
    httplib::Result res = cli.Post(rpc_api, headers,req, "application/json");

    if (res.error() != httplib::Error::Success)
    {
        return Sutil::Format("error:%s", (int)res.error());
    }

    return res->body;
}

std::string DoContractNext(const std::string &req, long long pkey, const std::string &rpc_api)
{
    httplib::Headers headers = {
        {"content-type", "application/json"}};

    httplib::Client cli("192.168.1.55", 20620);
    httplib::Result res = cli.Post(rpc_api, headers,req, "application/json");

    if (res.error() != httplib::Error::Success)
    {
        return Sutil::Format("error:%s", (int)res.error());
    }

    std::string m_boy=res->body;

    debugL("ack body:%s",res->body);

    char *tx_body=sig_contract_tx(m_boy.c_str(),m_boy.size(), (long long)pkey);
    std::string tx_t(tx_body);
    debugL("sign body:%s",tx_body);
    auto retv= cli.Post("/SendContractMessage",headers,tx_t,"application/json");
    delete[] tx_body;
    if (retv.error() != httplib::Error::Success)
    {
        return Sutil::Format("error:%s", (int)retv.error());
    }
   return retv->body;
}
std::string DoNext(const std::string &req, long long pkey, const std::string &rpc_api)
{

    httplib::Headers headers = {
        {"content-type", "application/json"}};

    httplib::Client cli("192.168.1.35", 11190);
    httplib::Result res = cli.Post(rpc_api, headers,req, "application/json");

    if (res.error() != httplib::Error::Success)
    {
        return Sutil::Format("error:%s", (int)res.error());
    }

    std::string m_boy=res->body;
    debugL("ack body:%s",res->body);

    char *tx_body=sig_tx(m_boy.c_str(),m_boy.size(), (long long)pkey);
    std::string tx_t(tx_body);
    debugL("sign body:%s",tx_body);
    auto retv= cli.Post("/SendMessage",headers,tx_t,"application/json");
    free(tx_body) ;
    if (retv.error() != httplib::Error::Success)
    {
        return Sutil::Format("error:%s", (int)retv.error());
    }

    return res->body;
}

void transtion(long long pkey)
{
    tx_req req;
    req.fromAddr={"cED97dA085527Fe7e1772CA59Aa1e64A78143128"};
    req.toAddr={{"06BA76F46631d4F344d1344303895001F1E3Af29","13.5"}};
    req.isFindUtxo = false;
    req.txInfo = "";
    debugL("req body :%s",req._paseToString());
    auto res=DoNext(req._paseToString(), pkey, "/GetTransaction");
}

void stake(long long pkey)
{
    getStakeReq req;
    req.stakeAmount="1000";
    req.fromAddr="69b34b7538DeB6913f2b9f59Cbc8610059442e5A";
    req.PledgeType="0";
    req.commissionRate = "5";
    req.isFindUtxo = false;
    req.txInfo = "";

    auto res=DoNext(req._paseToString(), pkey, "/GetStakeTransaction");
    debugL("req: %s", res);
    
}

void unstake(long long pkey){
    getUnStakeReq req;
    req.fromAddr="69b34b7538DeB6913f2b9f59Cbc8610059442e5A";
    req.utxoHash="b088fde1b1b270399134a7027408b2ef270d7f00859f306f9cb006e46de77e18";
    req.isFindUtxo = false;
    req.txInfo = "";
    auto res=DoNext(req._paseToString(), pkey, "/GetUnStakeTransaction");
    debugL("req: %s", res);
}

void invest(long long pkey){
    getInvestReq req;
    req.investAmount="10000";
    req.fromAddr="69b34b7538DeB6913f2b9f59Cbc8610059442e5A";
    req.toAddr="69b34b7538DeB6913f2b9f59Cbc8610059442e5A";
    req.investType="0";
    req.isFindUtxo = false;
    req.txInfo = "";
    
    auto res=DoNext(req._paseToString(), pkey, "/GetInvestTransaction");
    debugL("req: %s", res);
}


void uninvest(long long pkey){
    getDisinvestreq req;
    req.fromAddr="69b34b7538DeB6913f2b9f59Cbc8610059442e5A";
    req.toAddr="69b34b7538DeB6913f2b9f59Cbc8610059442e5A";
    req.utxoHash="3941c0cc427c3053222b9d1f32a2882a564e1ed3c45bcf59a48dc08c6eceb6e3";
    req.isFindUtxo = false;
    req.txInfo = "";
    auto res=DoNext(req._paseToString(), pkey, "/GetDisInvestTransaction");
    debugL("req: %s", res);
}


void deploy(long long pkey){
    deploy_contract_req req;
    req.contract="608060405234801561001057600080fd5b506108b3806100206000396000f3fe608060405234801561001057600080fd5b50600436106100575760003560e01c80630483a7f61461005c5780631629614e1461008c57806327e235e3146100a85780637ad9ad7c146100d8578063afc58189146100f4575b600080fd5b610076600480360381019061007191906105a8565b610110565b60405161008391906106d7565b60405180910390f35b6100a660048036038101906100a19190610615565b610128565b005b6100c260048036038101906100bd91906105a8565b6102a7565b6040516100cf91906106d7565b60405180910390f35b6100f260048036038101906100ed91906105d5565b6102bf565b005b61010e60048036038101906101099190610615565b61037d565b005b60016020528060005260406000206000915090505481565b80806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205410156101aa576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101a1906106b7565b60405180910390fd5b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546101f89190610759565b9250508190555081600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825461024e9190610703565b925050819055503373ffffffffffffffffffffffffffffffffffffffff167f3a14c6aa3e15c61c97825b026647b989a91e18aa33b689769475a298922480428360405161029b91906106d7565b60405180910390a25050565b60006020528060005260406000206000915090505481565b806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825461030d9190610703565b925050819055508173ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f322d0c4befd4c2dd440740b711488a1638fd7d8eeb25f9dacede84083db428c98360405161037191906106d7565b60405180910390a35050565b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541415610400576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103f790610697565b60405180910390fd5b80600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015610482576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161047990610697565b60405180910390fd5b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546104d09190610703565b9250508190555080600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546105269190610759565b925050819055503373ffffffffffffffffffffffffffffffffffffffff167f867b353f032680758428983522443995b88120a470e436b962c6a9d0d8940af78260405161057391906106d7565b60405180910390a250565b60008135905061058d8161084f565b92915050565b6000813590506105a281610866565b92915050565b6000602082840312156105be576105bd6107f8565b5b60006105cc8482850161057e565b91505092915050565b600080604083850312156105ec576105eb6107f8565b5b60006105fa8582860161057e565b925050602061060b85828601610593565b9150509250929050565b60006020828403121561062b5761062a6107f8565b5b600061063984828501610593565b91505092915050565b600061064f6011836106f2565b915061065a826107fd565b602082019050919050565b60006106726014836106f2565b915061067d82610826565b602082019050919050565b610691816107bf565b82525050565b600060208201905081810360008301526106b081610642565b9050919050565b600060208201905081810360008301526106d081610665565b9050919050565b60006020820190506106ec6000830184610688565b92915050565b600082825260208201905092915050565b600061070e826107bf565b9150610719836107bf565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561074e5761074d6107c9565b5b828201905092915050565b6000610764826107bf565b915061076f836107bf565b925082821015610782576107816107c9565b5b828203905092915050565b60006107988261079f565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600080fd5b7f4e6f206c6f636b65642062616c616e6365000000000000000000000000000000600082015250565b7f496e73756666696369656e742062616c616e6365000000000000000000000000600082015250565b6108588161078d565b811461086357600080fd5b50565b61086f816107bf565b811461087a57600080fd5b5056fea264697066735822122067e67aed3152cf78a07c4f8842540cf5803e421699b10fbf8f66c015550b0ed464736f6c63430008070033";
    req.nContractType="0";
    req.addr="cED97dA085527Fe7e1772CA59Aa1e64A78143128";
    req.info="[]";
    req.data="";
    char * pubs=get_pubstr_base64(pkey);
    req.pubstr=std::string(pubs);
    req.isFindUtxo = false;
    req.txInfo = "info";
    debugL("req body :%s",req._paseToString());
    auto res=DoContractNext(req._paseToString(), pkey, "/GetDeployContractTransaction");
    // debugL(res);
}

void call(long long pkey)
{
    call_contract_req req;
    req.id = "123";
    req.addr="cED97dA085527Fe7e1772CA59Aa1e64A78143128";
    req.args="0x7ad9ad7c000000000000000000000000ff3778ca36a2936390c06d8b0457f5b8e408389c0000000000000000000000000000000000000000000000000000000000002710";
    req.deployer="cED97dA085527Fe7e1772CA59Aa1e64A78143128";
    req.deployutxo="0x8a02413da127b48318a7ed12a46a4f68b83cdc6c21f937d7e6c99393d64112b0";
    req.contractAddress = "0x7350399179EC2B0702008aE8b43a0579AA699Eb1";

    req.money="0";
    req.tip="0";
    req.istochain="true";
    req.isFindUtxo = false;
    char * pubs=get_pubstr_base64(pkey);
    req.pubstr=std::string(pubs);
    req.txInfo = "info";
    debugL("req body :%s",req._paseToString());
    auto res=DoContractNext(req._paseToString(), pkey, "/GetCallContractTransaction");
    // debugL(res);
}


void bonus(long long pkey){
    getBonusReq req;
    req.Addr="9234e37d86AE7De3Dd0Ac57AF815b54551873504";
    req.isFindUtxo = false;
    req.txInfo = "";
    auto res=DoNext(req._paseToString(), pkey, "/GetBounsTransaction");
    debugL("req: %s", res);
}


int main(){

    std::string base58;
    std::cout << "input your addr >:" << std::endl;
    std::cin >> base58;

    const std::string priFileFormat = "./cert/" + base58;
    const char *priPath = priFileFormat.c_str();
    printf("fileName:%s", priPath);
    std::cout << std::endl;
    
    
    BIO* priBioFile = BIO_new_file(priPath, "r");
    if (!priBioFile)
    {
        BIO_free(priBioFile);
        printf("Error: priBioFile err\n");
    }

    uint8_t seedGetRead[PrimeSeedNum];
    std::stringstream ss(std::string(reinterpret_cast<char *>(seedGetRead), PrimeSeedNum * 3 - 1)); // Subtract 1 because the last character does not require a separator
    std::string hexPart;
    int bytesRead = BIO_read(priBioFile, seedGetRead, PrimeSeedNum);
    if (bytesRead != PrimeSeedNum)
    {
        printf("Error: BIO_read err\n");
        BIO_free(priBioFile);
    }
    uint8_t* seedFull= seedGetRead;

    char *buf = NULL;
    int size = 0;


    uint8_t outputArr[SHA256_DIGEST_LENGTH];
    sha256_hash(seedGetRead, PrimeSeedNum, outputArr);

    uint8_t a;
    std::cout << ""<<std::setbase(10);

    EVP_PKEY *pkeyPtr;
    pkeyPtr = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, outputArr, DerivedSeedNum);
    if (!pkeyPtr)
    {
        std::cerr << "Failed to create OpenSSL private key from seed." << std::endl;
    }

    unsigned char *pkey_der = NULL;
    int publen = i2d_PUBKEY(pkeyPtr, &pkey_der);
    std::string pubStr;
    for (int i = 0; i < publen; ++i)
    {
        pubStr += pkey_der[i];
    }

    
    std::string ret = GenerateAddr(hexToBinary(Str2Hex(pubStr)));
    infoL(ret);
    std::cout << "base58:" << ret << std::endl;
    infoL("addr:%s",ret);

   

    while (true)
	{
		std::cout << std::endl << std::endl;
		std::cout << "1.Transaction" << std::endl;
		std::cout << "2.Stake" << std::endl;
		std::cout << "3.Unstake" << std::endl;
		std::cout << "4.Delegate" << std::endl;
		std::cout << "5.Withdraw" << std::endl;
		std::cout << "6.Get Bonus"  << std::endl;
        std::cout << "7.PrintAccountInfo" << std::endl;
		std::cout << "8.Deploy contract"  << std::endl;
		std::cout << "9.Call contract"  << std::endl;
		std::cout << "0.Exit" << std::endl;

		std::string strKey;
		std::cout << "Please input your choice: "<< std::endl;
		std::cin >> strKey;	    
		std::regex pattern("^[0-9]|([1][0])|(99)|(100)$");
		if(!std::regex_match(strKey, pattern))
        {
            std::cout << "Invalid input." << std::endl;
            continue;
        }
        int key = std::stoi(strKey);
		switch (key)
		{			
			case 0:
				std::cout << "Exiting, bye!" << std::endl;
				exit(0);
                return 0;
			case 1:
                transtion((long long)pkeyPtr);
				break;
			case 2:
				stake((long long)pkeyPtr);
				break;
			case 3:
				unstake((long long)pkeyPtr);
				break;
			case 4:
				invest((long long)pkeyPtr);
                break;
			case 5:
				uninvest((long long)pkeyPtr);
                break;
			case 6:
				bonus((long long)pkeyPtr);
                break;
      		case 8:
				deploy((long long)pkeyPtr);
				break;
			case 9:
				call((long long)pkeyPtr);
				break;
			default:
                std::cout << "Invalid input." << std::endl;
                continue;
		}
		sleep(1);
	}
    return 0;
}