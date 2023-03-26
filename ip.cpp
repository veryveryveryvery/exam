#include "ip.h"

IP::IP()
{

}

IP::IP(DataPackage data)
{
    this->pkt_content = data.pkt_content;
}

/********************** get ip version **********************/
QString IP::getIpVersion(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->versiosn_head_length >> 4);
}
/********************** get ip header length **********************/
QString IP::getIpHeaderLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    QString res = "";
    int length = ip->versiosn_head_length & 0x0F;
    if(length == 5) res = "20 bytes (5)";
    else res = QString::number(length*5) + "bytes (" + QString::number(length) + ")";
    return res;
}

/********************** get ip TOS **********************/
QString IP::getIpTos(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->TOS));
}
/********************** get ip total length **********************/
QString IP::getIpTotalLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->total_length));
}
/********************** get ip indentification **********************/
QString IP::getIpIdentification(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->identification),16);
}
/********************** get ip flag **********************/
QString IP::getIpFlag(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset)& 0xe000) >> 8,16);
}
/********************** get ip reverse bit **********************/
QString IP::getIpReservedBit(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int bit = (ntohs(ip->flag_offset) & 0x8000) >> 15;
    return QString::number(bit);
}
/********************** get ip DF flag[Don't Fragment] **********************/
QString IP::getIpDF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x4000) >> 14);
}
/********************** get ip MF flag[More Fragment] **********************/
QString IP::getIpMF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x2000) >> 13);
}
/********************** get ip Fragment Offset **********************/
QString IP::getIpFragmentOffset(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->flag_offset) & 0x1FFF);
}
/********************** get ip TTL **********************/
QString IP::getIpTTL(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->ttl);
}
/********************** get ip protocol **********************/
QString IP::getIpProtocol(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int protocol = ip->protocol;
    switch (protocol) {
    case 1:return "ICMP (1)";
    case 6:return "TCP (6)";
    case 17:return "UDP (17)";
    default:{
        return "";
    }
    }
}
/********************** get ip checksum **********************/
QString IP::getIpCheckSum(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->checksum),16);
}
