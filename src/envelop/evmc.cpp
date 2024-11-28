#include "evmc.hpp"
#include <ripemd160.h>
namespace evm_utils {
evmc_address stringToEvmAddr(const std::string &addr) {
    const char *s = addr.data();
    evmc_address evm_addr = from_hex<address>(s);
    return evm_addr;
}

evmc_address pubStrToEvmAddr(const std::string &pub) {
    std::string EvmAddress = generateEvmAddr(pub);
    const char *s = EvmAddress.data();
    evmc_address evmaddr = from_hex<address>(s);
    return evmaddr;
}

std::string EvmAddrToString(const evmc_address& addr)
{
    return hex({addr.bytes,sizeof(addr.bytes)});
}
} // namespace evm_utils