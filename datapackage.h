#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include "Format.h"

class DataPackage
{
private:
    uint dataLength;
    QString timeStamp;
    QString info;
    int packageType;


protected:
    static QString byteToString(uchar* str,int size);
public:
    DataPackage();
    const uchar* pkt_content;  //指向选中的数据包

    // set the var
    void setDataLength(uint length);                            // 设置数据包长度
    void setTimeStamp(QString timeStamp);                       // 设置时间戳
    void setInfo(QString info);                                 // 设置包信息
    void setPackageType(int type);                              // 设置包类型
    void setPackagePointer(const uchar* pkt_content,int size);  // 设置包的指针


    // get the var
    QString getDataLength();                  // 获取数据包长度
    QString getTimeStamp();                   // 获取时间戳
    QString getInfo();                        // 获取包信息
    QString getPackageType();                 // 获取包类型
    QString getSource();                      // 获取包源地址
    QString getDestination();                 // 获取包目的地址
    // get mac info
    QString getDesMacAddr();                  // get the destination MAC address
    QString getSrcMacAddr();                  // get the source MAC address
    QString getMacType();                     // get the type of MAC address
    QString getDesIpAddr();                   // get the destination ip address
    QString getSrcIpAddr();                   // get the source ip address

    // ARP
    virtual QString getArpHardwareType(){return "";}              // get arp hardware type
    virtual QString getArpProtocolType(){return "";}              // get arp protocol type
    virtual QString getArpHardwareLength(){return "";}            // get arp hardware length
    virtual QString getArpProtocolLength(){return "";}            // get arp protocol length
    virtual QString getArpOperationCode(){return "";}             // get arp operation code
    virtual QString getArpSourceEtherAddr(){return "";}           // get arp source ethernet address
    virtual QString getArpSourceIpAddr(){return "";}              // get arp souce ip address
    virtual QString getArpDestinationEtherAddr(){return "";}      // get arp destination ethernet address
    virtual QString getArpDestinationIpAddr(){return "";}         // get arp destination ip address

    // ICMP
    virtual QString getIcmpType(){return "";}                    // get the icmp type
    virtual QString getIcmpCode(){return "";}                    // get the icmp code
    virtual QString getIcmpCheckSum(){return "";}                // get the icmp checksum
    virtual QString getIcmpIdentification(){return "";}          // get the icmp identification
    virtual QString getIcmpSequeue(){return "";}                 // get the icmp sequence
    virtual QString getIcmpData(int size){return "";}            // get the icmp data

    // IP
    virtual QString getIpVersion(){return "";}                   // get the ip version
    virtual QString getIpHeaderLength(){return "";}              // get the ip head length
    virtual QString getIpTos(){return "";}                       // get the ip tos
    virtual QString getIpTotalLength(){return "";}               // get the ip total package length
    virtual QString getIpIdentification(){return "";}            // get the ip identification
    virtual QString getIpFlag(){return "";}                      // get the ip flag
    virtual QString getIpReservedBit(){return "";}               // the reserved bit
    virtual QString getIpDF(){return "";}                        // Don't fragment
    virtual QString getIpMF(){return "";}                        // More fragment
    virtual QString getIpFragmentOffset(){return "";}            // get the offset of package
    virtual QString getIpTTL(){return "";}                       // get ip ttl [time to live]
    virtual QString getIpProtocol(){return "";}                  // get the ip protocol
    virtual QString getIpCheckSum(){return "";}                  // get the checksum

    // TCP
    virtual QString getTcpSourcePort(){return "";}               // get tcp source port
    virtual QString getTcpDestinationPort(){return "";}          // get tcp destination port
    virtual QString getTcpSequence(){return "";}                 // get tcp sequence
    virtual QString getTcpAcknowledgment(){return "";}           // get acknowlegment
    virtual QString getTcpHeaderLength(){return "";}             // get tcp head length
    virtual QString getTcpRawHeaderLength(){return "";}          // get tcp raw head length [default is 0x05]
    virtual QString getTcpFlags(){return "";}                    // get tcp flags
    virtual QString getTcpPSH(){return "";}                      // PSH flag
    virtual QString getTcpACK(){return "";}                      // ACK flag
    virtual QString getTcpSYN(){return "";}                      // SYN flag
    virtual QString getTcpURG(){return "";}                      // URG flag
    virtual QString getTcpFIN(){return "";}                      // FIN flag
    virtual QString getTcpRST(){return "";}                      // RST flag
    virtual QString getTcpWindowSize(){return "";}               // get tcp window size
    virtual QString getTcpCheckSum(){return "";}                 // get tcp checksum
    virtual QString getTcpUrgentPointer(){return "";}            // get tcp urgent pointer
    virtual QString getTcpOperationKind(int kind){return "";}    // get tcp option kind
    virtual int getTcpOperationRawKind(int offset){return 0;}   // get tcp raw option kind
    virtual bool getTcpOperationMSS(int offset,ushort& mss){return false;}                          // kind = 2
    virtual bool getTcpOperationWSOPT(int offset,uchar&shit){return false;}                         // kind = 3
    virtual bool getTcpOperationSACKP(int offset){return false;}                                    // kind = 4
    virtual bool getTcpOperationSACK(int offset,uchar&length,QVector<uint>&edge){return false;}     // kind = 5
    virtual bool getTcpOperationTSPOT(int offset,uint& value,uint&reply){return false;}             // kind = 8

    // UDP
    virtual QString getUdpSourcePort(){return "";}               // get udp source port
    virtual QString getUdpDestinationPort(){return "";}          // get udp destination port
    virtual QString getUdpDataLength(){return "";}               // get udp data length
    virtual QString getUdpCheckSum(){return "";}                 // get udp checksum

    // DNS
    virtual QString getDnsTransactionId(){return "";}            // get dns transaction id
    virtual QString getDnsFlags(){return "";}                    // get dns flags
    virtual QString getDnsFlagsQR(){return "";}                  // get dns flag QR
    virtual QString getDnsFlagsOpcode(){return "";}              // get dns flag operation code
    virtual QString getDnsFlagsAA(){return "";}                  // get dns flag AA
    virtual QString getDnsFlagsTC(){return "";}                  // get dns flag TC
    virtual QString getDnsFlagsRD(){return "";}                  // get dns flag RD
    virtual QString getDnsFlagsRA(){return "";}                  // get dns flag RA
    virtual QString getDnsFlagsZ(){return "";}                   // get dns flag Z [reserved]
    virtual QString getDnsFlagsRcode(){return "";}               // get dns flag Rcode
    virtual QString getDnsQuestionNumber(){return "";}           // get dns question number
    virtual QString getDnsAnswerNumber(){return "";}             // get dns answer number
    virtual QString getDnsAuthorityNumber(){return "";}          // get dns authority number
    virtual QString getDnsAdditionalNumber(){return "";}         // get dns addition number
    virtual void getDnsQueriesDomain(QString&name,int&Type,int&Class){return;}
    virtual QString getDnsDomainType(int type){return "";}
    virtual QString getDnsDomainName(int offset){return "";}
    virtual int getDnsAnswersDomain(int offset,QString&name1,ushort&Type,ushort& Class,uint&ttl,ushort&dataLength,QString& name2){return 0;}
};


#endif // DATAPACKAGE_H
