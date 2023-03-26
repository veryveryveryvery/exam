#include "dns.h"

Dns::Dns()
{

}

Dns::Dns(DataPackage data)
{
    this->pkt_content = data.pkt_content;
}

/* dns */
/********************** get dns transaction **********************/
QString Dns::getDnsTransactionId(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->identification),16);
}
/********************** get dns flag **********************/
QString Dns::getDnsFlags(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    int type = ntohs(dns->flags);
    QString info = "";
    if((type & 0xf800) == 0x0000){
        info = "(Standard query)";
    }
    else if((type & 0xf800) == 0x8000){
        info = "(Standard query response)";
    }
    return QString::number(type,16) + info;
}
/********************** get dns QR **********************/
QString Dns::getDnsFlagsQR(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x8000) >> 15);
}
/********************** get dns Operation code **********************/
QString Dns::getDnsFlagsOpcode(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x7800) >> 11);
}
/********************** get dns AA **********************/
QString Dns::getDnsFlagsAA(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0400) >> 10);
}
/********************** get dns TC **********************/
QString Dns::getDnsFlagsTC(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0200) >> 9);
}
/********************** get dns RD **********************/
QString Dns::getDnsFlagsRD(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0100) >> 8);
}
/********************** get dns RA **********************/
QString Dns::getDnsFlagsRA(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0080) >> 7);
}
/********************** get dns Z(reserved) **********************/
QString Dns::getDnsFlagsZ(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0070) >> 4);
}
/********************** get dns Response code **********************/
QString Dns::getDnsFlagsRcode(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x000f));
}
/********************** get dns Question number **********************/
QString Dns::getDnsQuestionNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->question));
}
/********************** get dns Answer number **********************/
QString Dns::getDnsAnswerNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->answer));
}
/********************** get dns Authority number **********************/
QString Dns::getDnsAuthorityNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->authority));
}
/********************** get dns Additional number **********************/
QString Dns::getDnsAdditionalNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->additional));
}
/********************** get dns query result **********************/
void Dns::getDnsQueriesDomain(QString&name,int&Type,int&Class){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    char*domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
    while(*domain != 0x00){
        if(domain && (*domain) <= 64){
            int length = *domain;
            domain++;
            for(int k = 0;k < length;k++){
                name += (*domain);
                domain++;
            }
            name += ".";
        }else break;
    }
    domain++;
    name = name.left(name.length() - 1);
    DNS_QUESITON *qus = (DNS_QUESITON*)(domain);
    Type = ntohs(qus->query_type);
    Class = ntohs(qus->query_class);
}
/********************** get dns domian name **********************/
QString Dns::getDnsDomainName(int offset){
    char*dns;
    dns = (char*)(pkt_content + 14 + 20 + 8 + offset);
    QString name = "";
    while(dns && *dns != 0x00){
        if((unsigned char)(*dns) <= 64){
            int length = *dns;
            dns++;
            for(int k = 0;k<length;k++){
                name += (*dns);
                dns++;
            }
            name += ".";
        }else if(((*dns) & 0xc0) == 0xc0){
            int accOffset = (((*dns) & 0x3f) << 8);
            dns++;
            accOffset += (unsigned char)(*dns);
            name += getDnsDomainName(accOffset) + ".";
            dns++;
            break;
        }
    }
    name = name.left(name.length() - 1);
    return name;
}
/********************** get dns answer result **********************/
int Dns::getDnsAnswersDomain(int offset, QString &name1, ushort &Type, ushort &Class, uint &ttl, ushort &dataLength,QString&name2){
    char*dns = (char*)(pkt_content + 14 + 20 + 8 + 12 + offset);
    if(((*dns) & 0xc0) == 0xc0){
        int accOffset = (((*dns) & 0x3f) << 8);
        dns++; //
        accOffset += (*dns);
        name1 = getDnsDomainName(accOffset);
        dns++; //
        DNS_ANSWER*answer = (DNS_ANSWER*)(dns);
        Type = ntohs(answer->answer_type);
        Class = ntohs(answer->answer_class);
        ttl = ntohl(answer->TTL);
        dataLength = ntohs(answer->dataLength);
        dns += (2 + 2 + 4 + 2);
        if(dataLength == 4){
            for(int i = 0;i < 4;i++){
                name2 += QString::number((unsigned char)(*dns));
                name2 += ".";
                dns++;
            }
        }else{
            for(int k = 0;k<dataLength;k++){
                if((unsigned char)(*dns) <= 64){
                    int length = *dns;
                    dns++;
                    k++;
                    for(int j = 0;j < length;j++){
                        name2 += *dns;
                        dns++;
                        k++;
                    }
                    name2 += ".";
                }else if(((*dns) & 0xc0) == 0xc0){
                    int accOffset = (((*dns) & 0x3f) << 8);
                    dns++;
                    k++;
                    accOffset += (unsigned char)(*dns);
                    name2 += getDnsDomainName(accOffset) + ".";
                    dns++;
                    k++;
                }
            }
        }
        name2 = name2.left(name2.length() - 1);
        return dataLength + 2 + 2 + 2 + 4 + 2;

    }else{
        name1 = getDnsDomainName(offset + 12);
        DNS_ANSWER*answer = (DNS_ANSWER*)(dns + name1.size() + 2);
        Type = ntohs(answer->answer_type);
        Class = ntohs(answer->answer_class);
        ttl = ntohl(answer->TTL);
        dataLength = ntohs(answer->dataLength);
        if(dataLength == 4){
            dns += (2 + 2 + 4 + 2 + name1.size() + 1);
            for(int i = 0;i < 4;i++){
                name2 += (QChar)(*dns);
                dns++;
            }
        }else{
            for(int k = 0;k<dataLength;k++){
                if((unsigned char)(*dns) <= 64){
                    int length = *dns;
                    dns++;
                    k++;
                    for(int j = 0;j < length;j++){
                        name2 += *dns;
                        dns++;
                        k++;
                    }
                    name2 += ".";
                }else if(((*dns) & 0xc0) == 0xc0){
                    int accOffset = (((*dns) & 0x3f) << 8);
                    dns++;
                    k++;
                    accOffset += (*dns);
                    name2 += getDnsDomainName(accOffset);
                    dns++;
                    k++;
                }
            }
        }
        name2 = name2.left(name2.length() - 1);
        return dataLength + 2 + 2 + 2 + 4 + 2 + name1.size() + 2;
    }
}
/********************** get dns domain type **********************/
QString Dns::getDnsDomainType(int type){
    switch (type) {
    case 1: return "A (Host Address)";
    case 2:return "NS";
    case 5:return "CNAME (Canonical NAME for an alias)";
    case 6:return "SOA";
    case 11:return "WSK";
    case 12:return "PTR";
    case 13:return "HINFO";
    case 15:return "MX";
    case 28:return "AAAA";
    case 252:return "AXFR";
    case 255:return "ANY";
    default:return "";
    }
}
