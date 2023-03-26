#include "datapackage.h"
#include <QDebug>
#include <arpa/inet.h>

DataPackage::DataPackage()
{
    qRegisterMetaType<DataPackage>("DataPackage");
    this->dataLength = 0;
    this->timeStamp = "";
    this->packageType = 0;
    this->info = "";
    this->pkt_content = nullptr;

}

void DataPackage::setDataLength(unsigned int length){
    this->dataLength = length;
}

void DataPackage::setTimeStamp(QString timeStamp){
    this->timeStamp = timeStamp;
}

void DataPackage::setPackageType(int type){
    this->packageType = type;
}

void DataPackage::setPackagePointer(const uchar* pkt_content,int size){
    this->pkt_content = (uchar*)malloc(size);
    if(this->pkt_content != nullptr)
        memcpy((char*)(this->pkt_content),pkt_content,size);
    else this->pkt_content = nullptr;

}
void DataPackage::setInfo(QString info){
    this->info = info;
}

QString DataPackage::byteToString(uchar* str, int size){
    QString res = "";
//    qDebug() << str;
    for(int i = 0;i < size;i++){
        char one = str[i] >> 4;
        if(one >= 0x0A)
            one = one + 0x41 - 0x0A;
        else one = one + 0x30;
        char two = str[i] & 0xF;
        if(two >= 0x0A)
            two = two  + 0x41 - 0x0A;
        else two = two + 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}
//QString DataPackage::byteToHex(u_char *str, int size){
//    QString res = "";
//    for(int i = 0;i < size;i++){
//        char one = str[i] >> 4;
//        if(one >= 0x0A)
//            one = one + 0x41 - 0x0A;
//        else one = one + 0x30;
//        char two = str[i] & 0xF;
//        if(two >= 0x0A)
//            two = two  + 0x41 - 0x0A;
//        else two = two + 0x30;
//        res.append(one);
//        res.append(two);
//    }
//    return res;
//}

QString DataPackage::getTimeStamp(){
    return this->timeStamp;
}

QString DataPackage::getDataLength(){
    return QString::number(this->dataLength);
}

QString DataPackage::getPackageType(){
    switch (this->packageType) {
    case 1:return ARP;
    case 2:return ICMP;
    case 3:return TCP;
    case 4:return UDP;
    case 5:return DNS;
    case 6:return TLS;
    case 7:return SSL;
    // TODU ...more protocol you can add
    default:{
        return "";
    }
    }
}

QString DataPackage::getInfo(){
    return info;
}

QString DataPackage::getSource(){
    if(this->packageType == 1)   //arp协议就显示Mac地址
        return getSrcMacAddr();
    else return getSrcIpAddr();
}
QString DataPackage::getDestination(){
    if(this->packageType == 1)   //arp协议就显示Mac地址
        return getDesMacAddr();
    else return getDesIpAddr();
}
/* Ether */
/********************** get destination ethenet address **********************/
QString DataPackage::getDesMacAddr(){
    ETHER_HEADER* ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    uchar* addr;
    if(ethernet){
        addr = ethernet->ether_des_host;
        if(addr){
            QString res = byteToString(addr,1) + ":"
                    + byteToString((addr+1),1) + ":"
                    + byteToString((addr+2),1) + ":"
                    + byteToString((addr+3),1) + ":"
                    + byteToString((addr+4),1) + ":"
                    + byteToString((addr+5),1);
            if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
            else return res;
        }
    }
    return "";
}
/********************** get source ethenet address **********************/
QString DataPackage::getSrcMacAddr(){
    ETHER_HEADER* ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    uchar* addr;
    if(ethernet){
        addr = ethernet->ether_src_host;
        if(addr){
            QString res = byteToString(addr,1) + ":"
                    + byteToString((addr+1),1) + ":"
                    + byteToString((addr+2),1) + ":"
                    + byteToString((addr+3),1) + ":"
                    + byteToString((addr+4),1) + ":"
                    + byteToString((addr+5),1);
            if(res == "FF:FF:FF:FF:FF:FF") return "FF:FF:FF:FF:FF:FF(Broadcast)";
            else return res;
        }
    }
    return "";
}
/********************** get ethenet type **********************/
QString DataPackage::getMacType(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    ushort ethernet_type = ntohs(ethernet->ether_type);
    switch (ethernet_type) {
    case 0x0800: return "IPv4(0x800)";
    case 0x0806:return "ARP(0x0806)";
    default:{
        return "";
    }
    }
}
/* ip */
/********************** get destination ip address **********************/
QString DataPackage::getDesIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}
/********************** get source ip address **********************/
QString DataPackage::getSrcIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = ip->src_addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}


