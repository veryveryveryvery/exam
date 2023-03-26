#ifndef ARP_H
#define ARP_H
#include <datapackage.h>

class Arp : public DataPackage
{
public:
    Arp();
    Arp(DataPackage);

    // get the arp info
    virtual QString getArpHardwareType();             // get arp hardware type
    virtual QString getArpProtocolType();             // get arp protocol type
    virtual QString getArpHardwareLength();           // get arp hardware length
    virtual QString getArpProtocolLength();           // get arp protocol length
    virtual QString getArpOperationCode();            // get arp operation code
    virtual QString getArpSourceEtherAddr();          // get arp source ethernet address
    virtual QString getArpSourceIpAddr();             // get arp souce ip address
    virtual QString getArpDestinationEtherAddr();     // get arp destination ethernet address
    virtual QString getArpDestinationIpAddr();        // get arp destination ip address
};

#endif // ARP_H
