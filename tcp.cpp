#include "tcp.h"

Tcp::Tcp()
{

}

Tcp::Tcp(DataPackage data)
{
    this->pkt_content = data.pkt_content;
}

/* tcp */
/********************** get tcp source port **********************/
QString Tcp::getTcpSourcePort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->src_port);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp destination port **********************/
QString Tcp::getTcpDestinationPort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->des_port);
    if(port == 443) return "https(443)";
    return QString::number(port);
}
/********************** get tcp sequence **********************/
QString Tcp::getTcpSequence(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->sequence));
}
/********************** get tcp acknowledgment **********************/
QString Tcp::getTcpAcknowledgment(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->ack));
}
/********************** get tcp header length **********************/
QString Tcp::getTcpHeaderLength(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int length = (tcp->header_length >> 4);
    if(length == 5) return "20 bytes (5)";
    else return QString::number(length*4) + " bytes (" + QString::number(length) + ")";
}
QString Tcp::getTcpRawHeaderLength(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->header_length >> 4);
}

/********************** get tcp flags **********************/
QString Tcp::getTcpFlags(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->flags,16);
}

/********************** get tcp PSH **********************/
QString Tcp::getTcpPSH(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x08) >> 3);
}
/********************** get tcp ACK **********************/
QString Tcp::getTcpACK(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x10) >> 4);
}
/********************** get tcp SYN **********************/
QString Tcp::getTcpSYN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x02) >> 1);
}
/********************** get tcp UGR **********************/
QString Tcp::getTcpURG(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x20) >> 5);
}
/********************** get tcp FIN **********************/
QString Tcp::getTcpFIN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number((tcp->flags) & 0x01);
}
/********************** get tcp RST **********************/
QString Tcp::getTcpRST(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x04) >> 2);
}
/********************** get tcp window size **********************/
QString Tcp::getTcpWindowSize(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->window_size));
}
/********************** get tcp checksum **********************/
QString Tcp::getTcpCheckSum(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->checksum),16);
}
/********************** get tcp urgent pointer **********************/
QString Tcp::getTcpUrgentPointer(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->urgent));
}

QString Tcp::getTcpOperationKind(int kind){
    switch(kind){
    case 0:return "EOL";              // end of list
    case 1:return "NOP";              // no operation
    case 2:return "MSS";              // max segment
    case 3:return "WSOPT";            // window scaling factor
    case 4:return "SACK-Premitted";   // support SACK
    case 5:return "SACK";             // SACK Block
    case 8:return "TSPOT";            // Timestamps
    case 19:return "TCP-MD5";         // MD5
    case 28:return "UTP";             // User Timeout
    case 29:return "TCP-AO";          // authenticated
    }
}
int Tcp::getTcpOperationRawKind(int offset){
    uchar*tcp;
    tcp = (uchar*)(pkt_content + 14 + 20 + offset + 20);
    return *tcp;
}
bool Tcp::getTcpOperationSACK(int offset,uchar&length,QVector<uint>&edge){
    uchar*tcp;
    tcp = (uchar*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 5){
        tcp++;
        length = *tcp;
        tcp++;
        uint* pointer = (uint*)tcp;
        for(int i = 0;i < (length - 2)/4;i++){
            uint temp = htonl(*pointer);
            edge.push_back(temp);
            pointer++;
        }
        return true;
    }else return false;
}
bool Tcp::getTcpOperationMSS(int offset, ushort &mss){
    uchar *tcp;
    tcp = (uchar*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 2){
        tcp++;
        if(*tcp == 4){
            tcp++;
            ushort* Mss = (ushort*)tcp;
            mss = ntohs(*Mss);
            return true;
        }
        else return false;
    }
    return false;
}
bool Tcp::getTcpOperationSACKP(int offset){
    uchar *tcp;
    tcp = (uchar*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 4)
        return true;
    else return false;
}
bool Tcp::getTcpOperationWSOPT(int offset, uchar &shit){
    uchar *tcp;
    tcp = (uchar*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 3){
        tcp++;
        if(*tcp == 3){
            tcp++;
            shit = *tcp;
            return true;
        }else return false;
    }else return false;
}

bool Tcp::getTcpOperationTSPOT(int offset, uint &value, uint &reply){
    uchar *tcp;
    tcp = (uchar*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 8){
        tcp++;
        if(*tcp == 10){
            tcp++;
            uint *pointer = (uint*)(tcp);
            value = ntohl(*pointer);
            pointer++;
            reply = ntohl(*pointer);
            return true;
        }else return false;
    }else return false;
}
