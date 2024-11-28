#ifndef _RPC_TX_
#define _RPC_TX_
#include <string>
#include <vector>
#include <map>
#include "base64.h"
#include "json.hpp"


#define REQ(name)\
	struct name{\
	nlohmann::json _paseToJsonObj(const std::string & json_str);\
	std::string _paseFromJson(const std::string& json);\
	std::string _paseToString();\
	std::string id;\
	std::string method;\
	std::string jsonrpc;\
	std::string params;

#define ACK(name)\
	struct name{\
	std::string _paseFromJson(const std::string& json);\
	std::string _paseToString();\
	std::string id;\
	std::string method;\
	std::string jsonrpc;\
	std::string code;\
	std::string message;\
	std::string result;
#define END };



REQ(the_top)
std::string identity; 
std::string height;
END

REQ(balance_req)
std::string addr;
END

ACK(balance_ack)
std::string addr;
std::string balance;
END


REQ(contract_info)
std::string name;
std::string language;
std::string languageVersion;
std::string standard;
std::string logo;
std::string source;
std::string ABI;
std::string userDoc;
std::string developerDoc;
std::string compilerVersion;
std::string compilerOptions;
std::string srcMap;
std::string srcMapRuntime;
std::string metadata;
std::string other;
END



REQ(deploy_contract_req)
std::string addr;
std::string nContractType;
std::string info;
std::string contract;
std::string data;
std::string pubstr;
bool isFindUtxo;
std::string txInfo;
END





REQ(deploy_utxo_req)
std::string addr;
END


ACK(deploy_utxo_ack)
std::vector<std::string> utxos;
END



REQ(call_contract_req)
std::string addr;
std::string deployer;
std::string deployutxo;
std::string args;
std::string pubstr;
std::string tip;
std::string money;
std::string istochain;
std::string contractAddress;
bool isFindUtxo;
std::string txInfo;
END


ACK(call_contract_ack)

};



REQ(deployers_req)
END

ACK(deployers_ack)
std::vector<std::string> deployers;
END



REQ(tx_req)
std::vector<std::string> fromAddr;
std::map<std::string, std::string> toAddr;
bool isFindUtxo;
std::string txInfo;
END




// ACK(tx_ack)
// std::string txJson;
// std::string height;
// std::string vrfJson;
// std::string txType;
// std::string time;
// std::string gas;
// std::string commissionRate;
// END

// ACK(contract_ack)
// std::string contractJs;
// std::string txJs;
// END



REQ(getStakeReq)
std::string fromAddr;
std::string stakeAmount;
std::string PledgeType;
std::string commissionRate;
bool isFindUtxo;
std::string txInfo;
END


REQ(getUnStakeReq)
std::string fromAddr;
std::string utxoHash;
bool isFindUtxo;
std::string txInfo;
END

REQ(getInvestReq)
std::string fromAddr;
std::string toAddr;
std::string investAmount;
std::string investType;
bool isFindUtxo;
std::string txInfo;
END

REQ(getDisinvestreq)
std::string fromAddr;
std::string toAddr;
std::string utxoHash;
bool isFindUtxo;
std::string txInfo;
END

REQ(get_declare_req)
std::string fromAddr;
std::string toAddr;
std::string amount;
std::string multiSignPub;
std::vector<std::string> signAddrList;
std::string signThreshold;
END

REQ(getBonusReq)
std::string Addr;
bool isFindUtxo;
std::string txInfo;
END

REQ(get_stakeutxo_req)
std::string fromAddr;
END

ACK(get_stakeutxo_ack)
std::map<std::string,uint64_t> utxos;
END

// ACK(rpc_ack)
// std::string txhash;
// END


REQ(rsa_code)
std::string isEcode;
std::string strEncTxt;
std::string cipher_text;
std::string sign_message;
std::string strpub;
END

ACK(rsa_pubstr_ack)
std::string rsa_pubstr;
END

REQ(get_disinvestutxo_req)
std::string fromAddr;
std::string toAddr;
END


ACK(get_disinvestutxo_ack)
std::vector<std::string> utxos;
END


REQ(confirm_transaction_req)
std::string txhash;
std::string height;
END

ACK(confirm_transaction_ack)
std::string txhash;
std::string percent;
std::string sendsize;
std::string receivedsize;
std::string tx;
END

REQ(get_restinverst_req)
std::string addr;
END

ACK(get_restinverst_ack)
std::string addr;
std::string amount;
END



REQ(get_tx_info_req)
std::string txhash;
END

ACK(get_tx_info_ack)
std::string tx;
uint64_t blockheight;
std::string blockhash;
END


REQ(getAllbonusInfoReq)
END

ACK(getAllbonusInfoAck)
std::string info;
END

REQ(get_all_stake_node_list_req)
END

ACK(get_all_stake_node_list_ack)
std::string list;
END

REQ(getblocknumberReq)
END

ACK(getblocknumberAck)
std::string top;
END

REQ(getweb3clientversionReq)
END

ACK(getweb3clientversionAck)
std::string netVersion;
std::string clientVersion;
END

REQ(balanceReq)
std::string addr;
END

ACK(balanceAck)
std::string balance;
END

REQ(getblocktransactioncountReq)
std::string blockHash;
END

ACK(getblocktransactioncountAck)
std::string txCount;
END

REQ(getaccountsReq)
END

ACK(getaccountsAck)
std::vector<std::string> acccountlist;
END

REQ(getchainidReq)
END

ACK(getchainidAck)
std::string chainId;
END

REQ(getpeerlistReq)
END

ACK(getpeerlistAck)
std::vector<std::string> peerList;
END

REQ(apiipReq)
END

ACK(apiipAck)
std::vector<std::string> apiIp;
END

REQ(apipubReq)
END

ACK(apipubAck)
std::vector<std::string> apiPub;
END

REQ(getTransactionInfoReq)
std::string txHash;
END

ACK(getTransactionInfoAck)
std::string tx;
END


REQ(getBlockInfoByHashReq)
std::string blockHash;
END

ACK(getBlockInfoByHashAck)
std::string block;
END


REQ(getBlockInfoByHeightReq)
std::string height;
END

ACK(getBlockInfoByHeightAck)
std::vector<std::string> blocks;
END

ACK(rpcAck)
std::string txHash;
END

ACK(txAck)
std::string txJson;
std::string height;
std::string vrfJson;
std::string txType;
std::string time;
std::string gas;
std::string commissionRate;
END


ACK(contractAck)
std::string contractJs;
std::string txJson;
END

#endif

