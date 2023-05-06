#ifndef DNS_H
#define DNS_H
#include "datapackage.h"

class Dns : public DataPackage
{
public:
    Dns();
    Dns(DataPackage);

    virtual QString getDnsTransactionId();            // get dns transaction id
    virtual QString getDnsFlags();                    // get dns flags
    virtual QString getDnsFlagsQR();                  // get dns flag QR
    virtual QString getDnsFlagsOpcode();              // get dns flag operation code
    virtual QString getDnsFlagsAA();                  // get dns flag AA
    virtual QString getDnsFlagsTC();                  // get dns flag TC
    virtual QString getDnsFlagsRD();                  // get dns flag RD
    virtual QString getDnsFlagsRA();                  // get dns flag RApublic DataPackage
    virtual QString getDnsFlagsZ();                   // get dns flag Z [reserved]
    virtual QString getDnsFlagsRcode();               // get dns flag Rcode
    virtual QString getDnsQuestionNumber();           // get dns question number
    virtual QString getDnsAnswerNumber();             // get dns answer number
    virtual QString getDnsAuthorityNumber();          // get dns authority number
    virtual QString getDnsAdditionalNumber();         // get dns addition number
    virtual void getDnsQueriesDomain(QString&name,int&Type,int&Class);
    virtual QString getDnsDomainType(int type);
    virtual QString getDnsDomainName(int offset);
    virtual int getDnsAnswersDomain(int offset,QString&name1,ushort&Type,ushort& Class,uint&ttl,ushort&dataLength,QString& name2);
};

#endif // DNS_H
