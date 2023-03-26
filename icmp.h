#ifndef ICMP_H
#define ICMP_H
#include "datapackage.h"

class Icmp : public DataPackage
{
public:
    Icmp();
    Icmp(DataPackage);

    // get the icmp info
    virtual QString getIcmpType();                    // get the icmp type
    virtual QString getIcmpCode();                    // get the icmp code
    virtual QString getIcmpCheckSum();                // get the icmp checksum
    virtual QString getIcmpIdentification();          // get the icmp identification
    virtual QString getIcmpSequeue();                 // get the icmp sequence
    virtual QString getIcmpData(int size);            // get the icmp data
};

#endif // ICMP_H
