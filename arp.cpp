#include "arp.h"

Arp::Arp(DataPackage d)
{
    this->pkt_content = d.pkt_content;
}
Arp::Arp()
{

}
/* arp info */
QString Arp::getArpHardwareType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->hardware_type);
    QString res = "";
    if(type == 0x0001) res = "Ethernet(1)";
    else res = QString::number(type);
    return res;
}
/********************** get arp protocol type **********************/
QString Arp::getArpProtocolType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->protocol_type);
    QString res = "";
    if(type == 0x0800) res = "IPv4(0x0800)";
    else res = QString::number(type);
    return res;
}
/********************** get hardware length **********************/
QString Arp::getArpHardwareLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->mac_length);
}
/********************** get arp protocol length **********************/
QString Arp::getArpProtocolLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->ip_length);
}
/********************** get arp operator code **********************/
QString Arp::getArpOperationCode(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1) res  = "request(1)";
    else if(code == 2) res = "reply(2)";
    return res;
}
/********************** get arp source ethernet address **********************/
QString Arp::getArpSourceEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    uchar*addr;
    if(arp){
        addr = arp->src_eth_addr;
        if(addr){
            QString res = byteToString(addr,1) + ":"
                    + byteToString((addr+1),1) + ":"
                    + byteToString((addr+2),1) + ":"
                    + byteToString((addr+3),1) + ":"
                    + byteToString((addr+4),1) + ":"
                    + byteToString((addr+5),1);
            return res;
        }
    }
    return "";
}
/********************** get arp destination ethernet address **********************/
QString Arp::getArpDestinationEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    uchar*addr;
    if(arp){
        addr = arp->des_eth_addr;
        if(addr){
            QString res = byteToString(addr,1) + ":"
                    + byteToString((addr+1),1) + ":"
                    + byteToString((addr+2),1) + ":"
                    + byteToString((addr+3),1) + ":"
                    + byteToString((addr+4),1) + ":"
                    + byteToString((addr+5),1);
            return res;
        }
    }
    return "";
}
//QString DataPackage::getArpDestinationEtherAddr(){
//    ARP_HEADER*arp;
//    arp = (ARP_HEADER*)(pkt_content + 14);
//    u_char*addr;
//    if(arp){
//        addr = arp->des_eth_addr;
//        if(addr){
//            QString res = byteToHex(addr,1) + ":"
//                    + byteToHex((addr+1),1) + ":"
//                    + byteToHex((addr+2),1) + ":"
//                    + byteToHex((addr+3),1) + ":"
//                    + byteToHex((addr+4),1) + ":"
//                    + byteToHex((addr+5),1);
//            return res;
//        }
//    }
//    return "";
//}
/********************** get arp source ip address **********************/
QString Arp::getArpSourceIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        uchar*addr = arp->src_ip_addr;
        QString srcIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return srcIp;
    }
    return "";
}
/********************** get arp destination ip address **********************/
QString Arp::getArpDestinationIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        uchar*addr = arp->des_ip_addr;
        QString desIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return desIp;
    }
    return "";
}
