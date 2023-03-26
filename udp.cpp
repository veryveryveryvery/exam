#include "udp.h"

Udp::Udp()
{

}

Udp::Udp(DataPackage data)
{
    this->pkt_content = data.pkt_content;
}
/* udp */
/********************** get udp source port **********************/
QString Udp::getUdpSourcePort(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    int port = ntohs(udp->src_port);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}
/********************** get udp destination port **********************/
QString Udp::getUdpDestinationPort(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    int port = ntohs(udp->des_port);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}
/********************** get udp data length **********************/
QString Udp::getUdpDataLength(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    return QString::number(ntohs(udp->data_length));

}
/********************** get udp checksum **********************/
QString Udp::getUdpCheckSum(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    return QString::number(ntohs(udp->checksum),16);
}
