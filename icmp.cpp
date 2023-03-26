#include "icmp.h"

Icmp::Icmp()
{

}

Icmp::Icmp(DataPackage data)
{
    this->pkt_content = data.pkt_content;
}


/* icmp */
/********************** get icmp type **********************/
QString Icmp::getIcmpType(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->type));
}
/********************** get icmp code **********************/
QString Icmp::getIcmpCode(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->code));

}
/********************** get icmp checksum **********************/
QString Icmp::getIcmpCheckSum(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->checksum),16);
}
/********************** get icmp identification **********************/
QString Icmp::getIcmpIdentification(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->identification));
}
/********************** get icmp sequence **********************/
QString Icmp::getIcmpSequeue(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->sequence));
}
QString Icmp::getIcmpData(int size){
    char*icmp;
    icmp = (char*)(pkt_content + 14 + 20 + 8);
    QString res= "";
    for(int i = 0;i < size;i++){
        res += (*icmp);
        icmp++;
    }
    return res;
}
