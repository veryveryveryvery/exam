#ifndef TCP_H
#define TCP_H
#include "datapackage.h"

class Tcp : public DataPackage
{
public:
    Tcp();
    Tcp(DataPackage);

    // get the tcp info
    virtual QString getTcpSourcePort();               // get tcp source port
    virtual QString getTcpDestinationPort();          // get tcp destination port
    virtual QString getTcpSequence();                 // get tcp sequence
    virtual QString getTcpAcknowledgment();           // get acknowlegment
    virtual QString getTcpHeaderLength();             // get tcp head length
    virtual QString getTcpRawHeaderLength();          // get tcp raw head length [default is 0x05]
    virtual QString getTcpFlags();                    // get tcp flags
    virtual QString getTcpPSH();                      // PSH flag
    virtual QString getTcpACK();                      // ACK flag
    virtual QString getTcpSYN();                      // SYN flag
    virtual QString getTcpURG();                      // URG flag
    virtual QString getTcpFIN();                      // FIN flag
    virtual QString getTcpRST();                      // RST flag
    virtual QString getTcpWindowSize();               // get tcp window size
    virtual QString getTcpCheckSum();                 // get tcp checksum
    virtual QString getTcpUrgentPointer();            // get tcp urgent pointer
    virtual QString getTcpOperationKind(int kind);    // get tcp option kind
    virtual int getTcpOperationRawKind(int offset);   // get tcp raw option kind
    virtual bool getTcpOperationMSS(int offset,ushort& mss);                          // kind = 2
    virtual bool getTcpOperationWSOPT(int offset,uchar&shit);                         // kind = 3
    virtual bool getTcpOperationSACKP(int offset);                                     // kind = 4
    virtual bool getTcpOperationSACK(int offset,uchar&length,QVector<uint>&edge);    // kind = 5
    virtual bool getTcpOperationTSPOT(int offset,uint& value,uint&reply);            // kind = 8
};

#endif // TCP_H
