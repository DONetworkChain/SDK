#ifndef __MAC_H_
#define  __MAC_H_
#include <string>
/**
 * @brief Get the Addr object
 * 
 * @param pkey 
 * @return std::string 
 */
std::string getAddr(const void *pkey);

/**
 * @brief Get the Pub Str object
 * 
 * @param pkey 
 * @return std::string 
 */
std::string getPubStr(const void *pkey);

/**
 * @brief Get the Pri Str object
 * 
 * @param pkey 
 * @return std::string 
 */
std::string getPriStr(const void * pkey);
#endif