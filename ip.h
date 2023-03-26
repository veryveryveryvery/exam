#ifndef IP_H
#define IP_H
#include "datapackage.h"


class IP : public DataPackage
{
public:
    IP();
    IP(DataPackage);

    // get the ip info
    virtual QString getIpVersion();                   // get the ip version
    virtual QString getIpHeaderLength();              // get the ip head length
    virtual QString getIpTos();                       // get the ip tos
    virtual QString getIpTotalLength();               // get the ip total package length
    virtual QString getIpIdentification();            // get the ip identification
    virtual QString getIpFlag();                      // get the ip flag
    virtual QString getIpReservedBit();               // the reserved bit
    virtual QString getIpDF();                        // Don't fragment
    virtual QString getIpMF();                        // More fragment
    virtual QString getIpFragmentOffset();            // get the offset of package
    virtual QString getIpTTL();                       // get ip ttl [time to live]
    virtual QString getIpProtocol();                  // get the ip protocol
    virtual QString getIpCheckSum();                  // get the checksum
};

#endif // IP_H
