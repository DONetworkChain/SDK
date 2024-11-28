#include "new_tx.h"
#include "debug.h"
#include "json.hpp"

// Parse the params field
#define PARSE_PARAMS(value)\
  if(jsObject.contains(#value)){\
        if(jsObject[#value].is_string()) { \
              try { \
                jsParams = nlohmann::json::parse(jsObject[#value].get<std::string>()); \
              } catch (const nlohmann::json::parse_error& e) { \
                errorL("Parse error for key %s: %s", std::string(#value).c_str(), e.what()); \
                return Sutil::Format("parse fail for key %s: %s", std::string(#value).c_str(), e.what()); \
              } \
            } else if(jsObject[#value].is_object()) { \
              jsParams = jsObject[#value].get<nlohmann::json>(); \
            } else { \
              errorL("Unsupported type for key %s", std::string(#value).c_str()); \
              return Sutil::Format("unsupported type for key %s", std::string(#value).c_str()); \
            } \
        }else{\
            if(!jsParams.contains("isFindUtxo")){\
                jsParams[#value] = false;\
            }else if(!jsParams.contains("txInfo")){\
                jsParams[#value] = "";\
            }else{\
                errorL("not found key:%s" ,std::string(#value))                             \
            return Sutil::Format("not found key:%s",std::string(#value));\
            }\
    }

// Parse inherent fields (id jsonrpc method)
#define PARSE_REGULAR_JSON(value)                                                      \
  if(jsObject.contains(#value)){\
		jsObject[#value].get_to(this->value);\
	}else{\
		if(!jsObject.contains("isFindUtxo")){\
			jsObject[#value] = false;\
		}else if(!jsObject.contains("txInfo")){\
			jsObject[#value] = "";\
		}else{\
			  errorL("not found key:%s" ,std::string(#value))                             \
        return Sutil::Format("not found key:%s",std::string(#value));\
		}\
	}

//Parse struct specific fields
#define PARSE_JSON(value)\
  if(jsParams.contains(#value)){\
		jsParams[#value].get_to(this->value);\
	}else{\
		if(!jsParams.contains("isFindUtxo")){\
			jsParams[#value] = false;\
		}else if(!jsParams.contains("txInfo")){\
			jsParams[#value] = "";\
		}else{\
			  errorL("not found key:%s" ,std::string(#value))                             \
        return Sutil::Format("not found key:%s",std::string(#value));\
		}\
	}

// Converts the inherent fields to json
#define TO_JSON(value) jsObject[#value] = this->value;
// Put specific fields into params
#define TO_RESULT(value) jsResult[#value] = this->value;
// Puts specific fields in result
#define TO_PARAMS(value) jsParams[#value] = this->value;

// Parsing req requests parsing params fields into the struct
#define PARSE_REQ(sname)                                                     \
  std::string sname::_paseFromJson(const std::string& json) {                  \
    nlohmann::json jsObject;                                                   \
    try {                                                                      \
        jsObject = nlohmann::json::parse(json);                                \
        nlohmann::json jsParams;\
        PARSE_REGULAR_JSON(id)\
        PARSE_REGULAR_JSON(method)\
        PARSE_REGULAR_JSON(jsonrpc)\
        PARSE_PARAMS(params)

// The parse ack request parses the result field into the struct
#define PARSE_ACK(sname)                                                     \
  std::string sname::_paseFromJson(const std::string& json) {                   \
    nlohmann::json jsObject;                                                   \
    try {                                                                      \
        jsObject = nlohmann::json::parse(json);                                \
        nlohmann::json jsParams;\
        PARSE_REGULAR_JSON(id)\
        PARSE_REGULAR_JSON(method)\
        PARSE_REGULAR_JSON(jsonrpc)\
        PARSE_PARAMS(result)

// The serialized req request places the values in the struct in params
#define DUMP_REQ(sname)                                                     \
  std::string sname::_paseToString() {                                          \
    nlohmann::json jsObject;                                                   \
    nlohmann::json jsParams;                                                   \
    try {                                                                      \
    TO_JSON(id)\
    TO_JSON(method)\
    TO_JSON(jsonrpc)\
    // TO_JSON(params)

// The serialized ack request places the value in the struct in result
#define DUMP_ACK(sname)                                                     \
  std::string sname::_paseToString() {                                          \
    nlohmann::json jsObject;                                                   \
    nlohmann::json jsResult;                                                   \
    try {                                                                      \
      TO_JSON(id)\
      TO_JSON(method)\
      TO_JSON(jsonrpc)
// TO_JSON(result)

// End of parsing
#define PARSE_END \
    }                                                                            \
    catch (std::exception & e) {                                                 \
        errorL("error:%s" , e.what());                                              \
        return e.what();                                                              \
    }                                                                            \
  return "OK";                                                                 \
  }

// REQ serialization ends
#define REQ_DUMP_END                                                                \
      jsObject["params"] = jsParams;\
      }                                                                            \
    catch (std::exception & e) {                                                 \
      errorL("error:%s",e.what());                                              \
      return std::string();                                                      \
    }                                                                            \
  return jsObject.dump();                                                      \
  }

// ACK serialization end
#define ACK_DUMP_END                                                                \
        TO_RESULT(code)\
        TO_RESULT(message)\
        jsObject["result"] = jsResult;\
      }                                                                            \
    catch (std::exception & e) {                                                 \
      errorL("error:%s",e.what());                                              \
      return std::string();                                                      \
    }                                                                            \
  return jsObject.dump();                                                      \
}
// //------------------------the_top
// PARSE_REQ(the_top)
// PARSE_JSON(height)
// PARSE_JSON(identity)
// PARSE_END

// DUMP_REQ(the_top)
// TO_JSON(height)
// TO_JSON(identity)
// DUMP_END

// //------------------------balance_req
// PARSE_REQ(balance_req)
// PARSE_JSON(addr)
// PARSE_END

// DUMP_REQ(balance_req)
// TO_JSON(addr)
// DUMP_END

// PARSE_ACK(balance_ack)
// PARSE_JSON(addr)
// PARSE_JSON(balance)
// PARSE_END

// DUMP_ACK(balance_ack)
// TO_JSON(addr)
// TO_JSON(balance)
// DUMP_END

// //------------------------contract_info
// PARSE_REQ(contract_info)
// PARSE_JSON(name)
// PARSE_JSON(language)
// PARSE_JSON(languageVersion)
// PARSE_JSON(standard)
// PARSE_JSON(logo)
// PARSE_JSON(source)
// PARSE_JSON(ABI)
// PARSE_JSON(userDoc)
// PARSE_JSON(developerDoc)
// PARSE_JSON(compilerVersion)
// PARSE_JSON(compilerOptions)
// PARSE_JSON(srcMap)
// PARSE_JSON(srcMapRuntime)
// PARSE_JSON(metadata)
// PARSE_JSON(other)
// PARSE_END

// nlohmann::json contract_info::_paseToJsonObj(const std::string &json){
//     nlohmann::json jsObject;
//     try {
//       jsObject = nlohmann::json::parse(json);
//     }catch (std::exception & e) {
//         errorL("error:%s" , e.what());
//     }   return  nlohmann::json();
//     return jsObject;
// }

// DUMP_REQ(contract_info)
// TO_JSON(name)
// TO_JSON(language)
// TO_JSON(languageVersion)
// TO_JSON(standard)
// TO_JSON(logo)
// TO_JSON(source)
// TO_JSON(ABI)
// TO_JSON(userDoc)
// TO_JSON(developerDoc)
// TO_JSON(compilerVersion)
// TO_JSON(compilerOptions)
// TO_JSON(srcMap)
// TO_JSON(srcMapRuntime)
// TO_JSON(metadata)
// TO_JSON(other)
// DUMP_END

//------------------------deploy_contract_req
PARSE_REQ(deploy_contract_req)
    PARSE_JSON(addr)
        PARSE_JSON(nContractType)
            PARSE_JSON(info)
                PARSE_JSON(contract)
                    PARSE_JSON(data)
                        PARSE_JSON(pubstr)
                            PARSE_JSON(isFindUtxo)
                                PARSE_JSON(txInfo)
                                    PARSE_END

    DUMP_REQ(deploy_contract_req)
        TO_PARAMS(addr)
            TO_PARAMS(nContractType)
                TO_PARAMS(info)
                    TO_PARAMS(contract)
                        TO_PARAMS(data)
                            TO_PARAMS(pubstr)
                                TO_PARAMS(isFindUtxo)
                                    TO_PARAMS(txInfo)
                                        REQ_DUMP_END

    //------------------------call_contract_req
    PARSE_REQ(call_contract_req)
        PARSE_JSON(addr)
            PARSE_JSON(deployer)
                PARSE_JSON(deployutxo)
                    PARSE_JSON(args)
                        PARSE_JSON(pubstr)
                            PARSE_JSON(tip)
                                PARSE_JSON(money)
                                    PARSE_JSON(istochain)
                                        PARSE_JSON(isFindUtxo)
                                            PARSE_JSON(txInfo)
                                                PARSE_JSON(contractAddress)
                                                    PARSE_END

    DUMP_REQ(call_contract_req)
        TO_PARAMS(addr)
            TO_PARAMS(deployer)
                TO_PARAMS(deployutxo)
                    TO_PARAMS(args)
                        TO_PARAMS(pubstr)
                            TO_PARAMS(tip)
                                TO_PARAMS(money)
                                    TO_PARAMS(istochain)
                                        TO_PARAMS(isFindUtxo)
                                            TO_PARAMS(txInfo)
                                                TO_PARAMS(contractAddress)
                                                    REQ_DUMP_END

    // //------------------------deploy_utxo_req
    // PARSE_REQ(deploy_utxo_req)
    // PARSE_JSON(addr)
    // PARSE_END

    // DUMP_REQ(deploy_utxo_req)
    // TO_JSON(addr)
    // DUMP_END

    // PARSE_ACK(deploy_utxo_ack)
    // PARSE_JSON(utxos)
    // PARSE_END

    // DUMP_ACK(deploy_utxo_ack)
    // TO_JSON(utxos)
    // DUMP_END

    // //------------------------deployers_ack
    // PARSE_ACK(deployers_ack)
    // PARSE_JSON(deployers)
    // PARSE_END

    // DUMP_ACK(deployers_ack)
    // TO_JSON(deployers)
    // DUMP_END

    //------------------------tx_req
    PARSE_REQ(tx_req)
        PARSE_JSON(fromAddr) if (jsObject.contains("toAddr")) {
  auto map_ = jsObject["toAddr"];

  for (auto iter = map_.begin(); iter != map_.end(); iter++) {
    auto obj_c = iter.value();
    std::string addr_t;
    std::string value_t;
    if (obj_c.contains("addr")) {
      obj_c["addr"].get_to(addr_t);
    } else {
      errorL("not found key addr");
    }
    if (obj_c.contains("value")) {
      obj_c["value"].get_to(value_t);
    } else {
      errorL("not found key value");
    }
    toAddr[addr_t] = value_t;
  }
} else {
  errorL("not found key toAddr");
}
PARSE_JSON(isFindUtxo)
PARSE_JSON(txInfo)
PARSE_END

DUMP_REQ(tx_req)
TO_PARAMS(fromAddr)
nlohmann::json to_addrs;
for (auto iter = toAddr.begin(); iter != toAddr.end(); iter++) {
  nlohmann::json to_addr;
  to_addr["addr"] = iter->first;
  to_addr["value"] = iter->second;
  to_addrs.push_back(to_addr);
}
jsParams["toAddr"] = to_addrs;
TO_PARAMS(isFindUtxo)
TO_PARAMS(txInfo)
REQ_DUMP_END

// PARSE_ACK(tx_ack)
// PARSE_JSON(txJson)
// PARSE_JSON(height)
// PARSE_JSON(vrfJson)
// PARSE_JSON(txType)
// PARSE_JSON(time)
// PARSE_JSON(gas)
// PARSE_END

// DUMP_ACK(tx_ack)
// TO_RESULT(txJson)
// TO_RESULT(height)
// TO_RESULT(vrfJson)
// TO_RESULT(txType)
// TO_RESULT(time)
// TO_RESULT(gas)
// ACK_DUMP_END

//------------------------contract_ack
// PARSE_ACK(contract_ack)
// PARSE_JSON(contractJs)
// PARSE_JSON(txJs);
// PARSE_END


// DUMP_ACK(contract_ack)
// TO_RESULT(contractJs)
// TO_RESULT(txJs);
// ACK_DUMP_END

//------------------------getStakeReq
PARSE_REQ(getStakeReq)
PARSE_JSON(fromAddr)
PARSE_JSON(stakeAmount)
PARSE_JSON(PledgeType)
PARSE_JSON(commissionRate)
PARSE_JSON(isFindUtxo)
PARSE_JSON(txInfo)
PARSE_END

DUMP_REQ(getStakeReq)
TO_PARAMS(fromAddr)
TO_PARAMS(stakeAmount)
TO_PARAMS(PledgeType)
TO_PARAMS(commissionRate)
TO_PARAMS(isFindUtxo)
TO_PARAMS(txInfo)
REQ_DUMP_END

//------------------------get_unstake_req
PARSE_REQ(getUnStakeReq)
PARSE_JSON(fromAddr)
PARSE_JSON(utxoHash)
PARSE_JSON(isFindUtxo)
PARSE_JSON(txInfo)
PARSE_END

DUMP_REQ(getUnStakeReq)
TO_PARAMS(fromAddr)
TO_PARAMS(utxoHash)
TO_PARAMS(isFindUtxo)
TO_PARAMS(txInfo)
REQ_DUMP_END

//------------------------get_invest_req
PARSE_REQ(getInvestReq)
PARSE_JSON(fromAddr)
PARSE_JSON(toAddr)
PARSE_JSON(investAmount)
PARSE_JSON(investType)
PARSE_JSON(isFindUtxo)
PARSE_JSON(txInfo)
PARSE_END

DUMP_REQ(getInvestReq)
TO_PARAMS(fromAddr)
TO_PARAMS(toAddr)
TO_PARAMS(investAmount)
TO_PARAMS(investType)
TO_PARAMS(isFindUtxo)
TO_PARAMS(txInfo)
REQ_DUMP_END

//------------------------getDisinvestreq
PARSE_REQ(getDisinvestreq)
PARSE_JSON(fromAddr)
PARSE_JSON(toAddr)
PARSE_JSON(utxoHash)
PARSE_JSON(isFindUtxo)
PARSE_JSON(txInfo)
PARSE_END

DUMP_REQ(getDisinvestreq)
TO_PARAMS(fromAddr)
TO_PARAMS(toAddr)
TO_PARAMS(utxoHash)
TO_PARAMS(isFindUtxo)
TO_PARAMS(txInfo)
REQ_DUMP_END

// //------------------------get_declare_req
// PARSE_REQ(get_declare_req)
// PARSE_JSON(fromAddr);
// PARSE_JSON(toAddr);
// PARSE_JSON(amount);
// PARSE_JSON(multiSignPub);
// PARSE_JSON(signAddrList);
// PARSE_JSON(signThreshold);
// PARSE_END
// DUMP_REQ(get_declare_req)
// TO_JSON(fromAddr);
// TO_JSON(toAddr);
// TO_JSON(amount);
// TO_JSON(multiSignPub);
// TO_JSON(signAddrList);
// TO_JSON(signThreshold);
// DUMP_END

//------------------------getBonusReq
PARSE_REQ(getBonusReq)
PARSE_JSON(Addr)
PARSE_JSON(isFindUtxo)
PARSE_JSON(txInfo)
PARSE_END

DUMP_REQ(getBonusReq)
TO_PARAMS(Addr)
TO_PARAMS(isFindUtxo)
TO_PARAMS(txInfo)
REQ_DUMP_END

//------------------------get_stakeutxo_req
PARSE_REQ(get_stakeutxo_req)
PARSE_JSON(fromAddr)
PARSE_END
DUMP_REQ(get_stakeutxo_req)
TO_JSON(fromAddr)
REQ_DUMP_END

DUMP_ACK(get_stakeutxo_ack)
nlohmann::json jsonUtxos;
for (auto iter = utxos.begin(); iter != utxos.end(); iter++) {
  nlohmann::json jsonUtxo;
  jsonUtxo["utxo"] = iter->first;
  jsonUtxo["value"] = iter->second;
  jsonUtxos.push_back(jsonUtxo);
}
jsResult["utxos"] = jsonUtxos;
ACK_DUMP_END

// //------------------------rpc_ack
// PARSE_ACK(rpc_ack)
// PARSE_JSON(txhash)
// PARSE_END

// DUMP_ACK(rpc_ack)
// TO_JSON(txhash)
// DUMP_END

// //------------------------rsa_code
// PARSE_REQ(rsa_code)
// PARSE_JSON(isEcode)
// PARSE_JSON(strEncTxt)
// PARSE_JSON(cipher_text)
// PARSE_JSON(sign_message)
// PARSE_JSON(strpub)
// PARSE_END

// DUMP_REQ(rsa_code)
// TO_JSON(isEcode)
// TO_JSON(strEncTxt)
// TO_JSON(cipher_text)
// TO_JSON(sign_message)
// TO_JSON(strpub)
// DUMP_END
// //------------------------rsa_pubstr_ack
// PARSE_ACK(rsa_pubstr_ack)
// PARSE_JSON(rsa_pubstr)
// PARSE_END

// DUMP_ACK(rsa_pubstr_ack)
// TO_JSON(rsa_pubstr)
// DUMP_END

//------------------------get_disinvestutxo_req
PARSE_REQ(get_disinvestutxo_req)
PARSE_JSON(fromAddr)
PARSE_JSON(toAddr)
PARSE_END

DUMP_REQ(get_disinvestutxo_req)
TO_JSON(fromAddr)
TO_JSON(toAddr)
REQ_DUMP_END

PARSE_ACK(get_disinvestutxo_ack)
// PARSE_JSON(utxos)
PARSE_END

DUMP_ACK(get_disinvestutxo_ack)
TO_RESULT(utxos)
ACK_DUMP_END

//------------------------confirm_transaction_req
PARSE_REQ(confirm_transaction_req)
PARSE_JSON(txhash)
PARSE_JSON(height)
PARSE_END

DUMP_REQ(confirm_transaction_req)
TO_JSON(txhash)
TO_JSON(height)
REQ_DUMP_END

PARSE_ACK(confirm_transaction_ack)
PARSE_JSON(txhash)
PARSE_JSON(percent)
PARSE_JSON(sendsize)
PARSE_JSON(receivedsize)
PARSE_JSON(tx)
PARSE_END

DUMP_ACK(confirm_transaction_ack)
TO_RESULT(txhash)
TO_RESULT(percent)
TO_RESULT(sendsize)
TO_RESULT(receivedsize)
TO_RESULT(tx)
ACK_DUMP_END

// //------------------------get_restinverst_req
// PARSE_REQ(get_restinverst_req)
// PARSE_JSON(addr);
// PARSE_END

// DUMP_REQ(get_restinverst_req)
// TO_JSON(addr)
// DUMP_END

// PARSE_ACK(get_restinverst_ack)
// PARSE_JSON(addr);
// PARSE_JSON(amount)
// PARSE_END

// DUMP_ACK(get_restinverst_ack)
// TO_JSON(addr)
// TO_JSON(amount)
// DUMP_END

//------------------------get_tx_info_req
PARSE_REQ(get_tx_info_req)
PARSE_JSON(txhash)
PARSE_END

DUMP_REQ(get_tx_info_req)
TO_JSON(txhash)
REQ_DUMP_END

PARSE_ACK(get_tx_info_ack)
PARSE_JSON(tx)
PARSE_JSON(blockhash)
PARSE_JSON(blockheight)
PARSE_END

DUMP_ACK(get_tx_info_ack)
TO_RESULT(tx)
TO_RESULT(blockhash)
TO_RESULT(blockheight)
ACK_DUMP_END


PARSE_REQ(getAllbonusInfoReq)
PARSE_END

DUMP_REQ(getAllbonusInfoReq)
REQ_DUMP_END

PARSE_ACK(getAllbonusInfoAck)
PARSE_END

DUMP_ACK(getAllbonusInfoAck)
TO_RESULT(info)
ACK_DUMP_END

PARSE_REQ(get_all_stake_node_list_req)
PARSE_END

DUMP_REQ(get_all_stake_node_list_req)
REQ_DUMP_END

PARSE_ACK(get_all_stake_node_list_ack)
PARSE_END

DUMP_ACK(get_all_stake_node_list_ack)
TO_RESULT(list)
ACK_DUMP_END

//-------------------getblocknumberReq
PARSE_REQ(getblocknumberReq)
PARSE_END

DUMP_REQ(getblocknumberReq)
REQ_DUMP_END


PARSE_ACK(getblocknumberAck)
PARSE_JSON(top)
PARSE_END

DUMP_ACK(getblocknumberAck)
TO_RESULT(top)
ACK_DUMP_END

//-------------------getweb3clientversion
PARSE_REQ(getweb3clientversionReq)
PARSE_END

DUMP_REQ(getweb3clientversionReq)
REQ_DUMP_END


PARSE_ACK(getweb3clientversionAck)
PARSE_JSON(netVersion)
PARSE_JSON(clientVersion)
PARSE_END

DUMP_ACK(getweb3clientversionAck)
TO_RESULT(netVersion)
TO_RESULT(clientVersion)
ACK_DUMP_END

//------------------------getbalance
PARSE_REQ(balanceReq)
PARSE_JSON(addr)
PARSE_END

DUMP_REQ(balanceReq)
TO_JSON(addr)
REQ_DUMP_END

PARSE_ACK(balanceAck)
PARSE_JSON(balance)
PARSE_END

DUMP_ACK(balanceAck)
TO_RESULT(balance)
ACK_DUMP_END

//------------------------getblocktransactioncountbyhash
PARSE_REQ(getblocktransactioncountReq)
PARSE_JSON(blockHash)
PARSE_END

DUMP_REQ(getblocktransactioncountReq)
TO_JSON(blockHash)
REQ_DUMP_END

PARSE_ACK(getblocktransactioncountAck)
PARSE_JSON(txCount)
PARSE_END

DUMP_ACK(getblocktransactioncountAck)
TO_RESULT(txCount)
ACK_DUMP_END

//------------------------getaccounts
PARSE_REQ(getaccountsReq)
PARSE_END

DUMP_REQ(getaccountsReq)
REQ_DUMP_END

PARSE_ACK(getaccountsAck)
PARSE_JSON(acccountlist)
PARSE_END

DUMP_ACK(getaccountsAck)
TO_RESULT(acccountlist)
ACK_DUMP_END

//------------------------getchainid
PARSE_REQ(getchainidReq)
PARSE_END

DUMP_REQ(getchainidReq)
REQ_DUMP_END

PARSE_ACK(getchainidAck)
PARSE_JSON(chainId)
PARSE_END

DUMP_ACK(getchainidAck)
TO_RESULT(chainId)
ACK_DUMP_END


//------------------------getpeerlist
PARSE_REQ(getpeerlistReq)
PARSE_END

DUMP_REQ(getpeerlistReq)
REQ_DUMP_END

PARSE_ACK(getpeerlistAck)
PARSE_JSON(peerList)
PARSE_END

DUMP_ACK(getpeerlistAck)
TO_RESULT(peerList)
ACK_DUMP_END


//------------------------apiip
PARSE_REQ(apiipReq)
PARSE_END

DUMP_REQ(apiipReq)
REQ_DUMP_END

PARSE_ACK(apiipAck)
PARSE_JSON(apiIp)
PARSE_END

DUMP_ACK(apiipAck)
TO_RESULT(apiIp)
ACK_DUMP_END

//------------------------apipub
PARSE_REQ(apipubReq)
PARSE_END

DUMP_REQ(apipubReq)
REQ_DUMP_END

PARSE_ACK(apipubAck)
PARSE_JSON(apiPub)
PARSE_END

DUMP_ACK(apipubAck)
TO_RESULT(apiPub)
ACK_DUMP_END


PARSE_REQ(getTransactionInfoReq)
PARSE_JSON(txHash)
PARSE_END

DUMP_REQ(getTransactionInfoReq)
TO_JSON(txHash)
REQ_DUMP_END

PARSE_ACK(getTransactionInfoAck)
PARSE_JSON(tx)
PARSE_END

DUMP_ACK(getTransactionInfoAck)
TO_JSON(tx)
ACK_DUMP_END


PARSE_REQ(getBlockInfoByHashReq)
PARSE_JSON(blockHash)
PARSE_END

DUMP_REQ(getBlockInfoByHashReq)
TO_JSON(blockHash)
REQ_DUMP_END

PARSE_ACK(getBlockInfoByHashAck)
PARSE_JSON(block)
PARSE_END

DUMP_ACK(getBlockInfoByHashAck)
TO_RESULT(block)
ACK_DUMP_END


PARSE_REQ(getBlockInfoByHeightReq)
PARSE_JSON(height)
PARSE_END

DUMP_REQ(getBlockInfoByHeightReq)
TO_JSON(height)
REQ_DUMP_END

PARSE_ACK(getBlockInfoByHeightAck)
PARSE_JSON(blocks)
PARSE_END

DUMP_ACK(getBlockInfoByHeightAck)
TO_RESULT(blocks)
ACK_DUMP_END


PARSE_ACK(rpcAck)
PARSE_JSON(txHash)
PARSE_END

DUMP_ACK(rpcAck)
TO_JSON(txHash)
ACK_DUMP_END

PARSE_ACK(txAck)
PARSE_JSON(txJson)
PARSE_JSON(height)
PARSE_JSON(vrfJson)
PARSE_JSON(txType)
PARSE_JSON(time)
PARSE_JSON(gas)
PARSE_END

DUMP_ACK(txAck)
TO_RESULT(txJson)
TO_RESULT(height)
TO_RESULT(vrfJson)
TO_RESULT(txType)
TO_RESULT(time)
TO_RESULT(gas)
ACK_DUMP_END


PARSE_ACK(contractAck)
PARSE_JSON(contractJs)
PARSE_JSON(txJson);
PARSE_END


DUMP_ACK(contractAck)
TO_RESULT(contractJs)
TO_RESULT(txJson);
ACK_DUMP_END