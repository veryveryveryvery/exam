#ifndef UDP_H
#define UDP_H
#include "datapackage.h"

class Udp : public DataPackage
{
public:
    Udp();
    Udp(DataPackage);

    // get the udp info
    virtual QString getUdpSourcePort();               // get udp source port
    virtual QString getUdpDestinationPort();          // get udp destination port
    virtual QString getUdpDataLength();               // get udp data length
    virtual QString getUdpCheckSum();                 // get udp checksum
};

#endif // UDP_H
