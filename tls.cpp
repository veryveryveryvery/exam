#include "tls.h"

Tls::Tls()
{

}

Tls::Tls(DataPackage data)
{
    this->pkt_content = data.pkt_content;
}

// tls
/********************** get tls protocol to check the data is meet this format or not **********************/
bool Tls::getisTlsProtocol(int offset){
    char*ssl;
    ssl = (char*)(pkt_content + 14 + 20 + 20 + offset);
    uchar type = (uchar)(*ssl);
    if(type >= 20 && type <= 23){
        ushort *point = (ushort*)(ssl+1);
        int version = ntohs(*point);
        if(version >= 0x0301 && version <= 0x0304)
            return true;
        else return false;
    }
    else return false;
}
/********************** get tls basic information **********************/
void Tls::getTlsBasicInfo(int offset, uchar &contentType, ushort &version, ushort &length){
    uchar*ssl;
    ssl = (uchar*)(pkt_content + 14 + 20 + offset);
    contentType = *ssl;
    ssl++;
    ushort* pointer = (ushort*)(ssl);
    version = ntohs(*pointer);
    pointer++;
    length = ntohs(*(pointer));
}

/********************** get tls handshake type **********************/
void Tls::getTlsHandshakeType(int offset, uchar &type){
    uchar*ssl;
    ssl = (uchar*)(pkt_content + 14 + 20 + offset);
    type = *ssl;
}
/********************** get tls client hello information **********************/
void Tls::getTlsClientHelloInfo(int offset, uchar &handShakeType, int &length, ushort &version, QString &random, uchar &sessionIdLength, QString &sessionId,ushort&cipherLength,QVector<ushort> &cipherSuit,uchar& cmLength,QVector<uchar>&CompressionMethod,ushort&extensionLength){
    uchar*ssl;
    ssl = (uchar*)(pkt_content + 14 + 20 + offset);
    handShakeType = *ssl;
    ssl++;
    length = (*ssl) * 4096 + (*(ssl+1)) * 256 + *(ssl + 2);
    ssl += 3;
    ushort* ver = (ushort*)(ssl);
    version = ntohs(*ver);
    ver++;
    ssl += 2;
    for(int i = 0;i < 32;i++){
        random += QString::number(*ssl,16);
        ssl++;
    }
    sessionIdLength = *ssl;
    ssl++;
    for(int k = 0;k < sessionIdLength;k++){
        sessionId += QString::number(*ssl,16);
        ssl++;
    }
    ushort* clen = (ushort*)(ssl);
    cipherLength = ntohs(*clen);
    clen++;
    for(int k = 0;k < cipherLength/2;k++){
        cipherSuit.push_back(ntohs(*clen));
        clen++;
    }
    ssl += (2 + cipherLength);
    cmLength = *ssl;
    ssl++;
    for(int k = 0;k<cmLength;k++){
        CompressionMethod.push_back(*ssl);
        ssl++;
    }
    extensionLength = (*(ssl)) * 256 + *(ssl + 1);
}

void Tls::getTlsServerHelloInfo(int offset, uchar &handShakeType, int &length, ushort &version, QString& random, uchar &sessionIdLength, QString &sessionId, ushort &cipherSuit, uchar &compressionMethod, ushort &extensionLength){
    uchar*ssl;
    ssl = (uchar*)(pkt_content + 14 + 20 + offset);
    handShakeType = *ssl;
    ssl++;
    length = (*ssl) * 4096 + (*(ssl + 1)) * 256 + *(ssl + 2);
    ssl += 3;
    ushort* ver = (ushort*)(ssl);
    version = ntohs(*ver);
    ver++;
    ssl += 2;
    for(int i = 0;i < 32;i++){
        random += QString::number(*ssl,16);
        ssl++;
    }
    sessionIdLength = *ssl;
    ssl++;
    for(int k = 0;k < sessionIdLength;k++){
        sessionId += QString::number(*ssl,16);
        ssl++;
    }
    ushort*point = (ushort*)(ssl);
    cipherSuit = ntohs(*point);
    ssl += 2;
    compressionMethod = *ssl;
    ssl++;
    extensionLength = (*ssl) * 256 + (*(ssl + 1));
}
void Tls::getTlsServerKeyExchange(int offset, uchar &handShakeType, int &length, uchar &curveType, ushort &curveName, uchar &pubLength, QString &pubKey, ushort &sigAlgorithm, ushort &sigLength, QString &sig){
    uchar*ssl;
    ssl = (uchar*)(pkt_content + 14 + 20 + offset);
    handShakeType = *ssl;
    ssl++;
    length = (*ssl) * 4096 + (*(ssl + 1)) * 256 + *(ssl + 2);
    ssl += 3;
    curveType = (*ssl);
    ssl++;
    ushort*point = (ushort*)(ssl);
    curveName = ntohs(*point);
    ssl += 2;
    pubLength = (*ssl);
    ssl++;
    for(int i = 0;i < pubLength;i++){
        pubKey += QString::number(*ssl,16);
        ssl++;
    }
    point = (ushort*)(ssl);
    sigAlgorithm = ntohs(*point);
    point++;
    sigLength = ntohs(*point);
    ssl += 4;
    for(int i = 0;i < sigLength;i++){
        sig += QString::number(*ssl,16);
        ssl++;
    }
}
/********************** get tls handshake type **********************/
QString Tls::getTlsHandshakeType(int type){
    switch (type) {
    case 1:return "Client Hello";
    case 2:return "Server hello";
    case 11:return "Certificate";
    case 16:return "Client Key Exchange";
    case 4:return "New Session Ticket";
    case 12:return "Server Key Exchange";
    case 14:return "Server Hello Done";

    default:return "";
    }
}
/********************** get tls content type **********************/
QString Tls::getTlsContentType(int type){
    switch (type) {
    case 20: return "Change Cipher Spec";
    case 21:return "Alert";
    case 22:return "Handshake";
    case 23:return "Application Data";
    default:return "";
    }
}
/********************** get tls version **********************/
QString Tls::getTlsVersion(int version){
    switch (version) {
    case 0x0300:return "SSL 3.0";
    case 0x0301:return "TLS 1.0";
    case 0x0302:return "TLS 1.1";
    case 0x0303:return "TLS 1.2";
    case 0x0304:return "TLS 1.3";
    default:return "Unkonwn";
    }
}
/********************** get tls handshake cipher suites **********************/
QString Tls::getTlsHandshakeCipherSuites(ushort code){
    switch (code) {
    case 0x00ff: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)";
    case 0xc02c: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)";
    case 0xc030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)";
    case 0x009f: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)";
    case 0xc0ad: return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM (0xc0ad)";
    case 0xc09f: return "TLS_DHE_RSA_WITH_AES_256_CCM (0xc09f)";
    case 0xc024: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)";
    case 0xc028: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)";
    case 0x006b: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)";
    case 0xc00a: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)";
    case 0xc014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)";
    case 0x0039: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)";
    case 0xc0af: return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 (0xc0af)";
    case 0xc0a3: return "TLS_DHE_RSA_WITH_AES_256_CCM_8 (0xc0a3)";
    case 0xc087: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc087)";
    case 0xc08b: return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc08b)";
    case 0xc07d: return "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc07d)";
    case 0xc073: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc073)";
    case 0xc077: return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc077)";
    case 0x00c4: return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c4)";
    case 0x0088: return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)";
    case 0xc02b: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)";
    case 0xc02f: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)";
    case 0x009e: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)";
    case 0xc0ac: return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM (0xc0ac)";
    case 0xc09e: return "TLS_DHE_RSA_WITH_AES_128_CCM (0xc09e)";
    case 0xc023: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)";
    case 0xc027: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)";
    case 0x0067: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)";
    case 0xc009: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)";
    case 0xc013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)";
    case 0x0033: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)";
    case 0xc0ae: return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xc0ae)";
    case 0xc0a2: return "TLS_DHE_RSA_WITH_AES_128_CCM_8 (0xc0a2)";
    case 0xc086: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc086)";
    case 0xc08a: return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc08a)";
    case 0xc07c: return "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc07c)";
    case 0xc072: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc072)";
    case 0xc076: return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc076)";
    case 0x00be: return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00be)";
    case 0x0045: return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)";
    case 0xc008: return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)";
    case 0xc012: return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)";
    case 0x0016: return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)";
    case 0x00ab: return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 (0x00ab)";
    case 0xc0a7: return "TLS_DHE_PSK_WITH_AES_256_CCM (0xc0a7)";
    case 0xc038: return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 (0xc038)";
    case 0x00b3: return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 (0x00b3)";
    case 0xc036: return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA (0xc036) ";
    case 0x0091: return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA (0x0091)";
    case 0xc091: return "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc091)";
    case 0xc09b: return "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc09b)";
    case 0xc097: return "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc097)";
    case 0xc0ab: return "TLS_PSK_DHE_WITH_AES_256_CCM_8 (0xc0ab)";
    case 0x00aa: return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 (0x00aa)";
    case 0xc0a6: return "TLS_DHE_PSK_WITH_AES_128_CCM (0xc0a6)";
    case 0xc037: return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 (0xc037)";
    case 0x00b2: return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 (0x00b2)";
    case 0xc035: return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA (0xc035)";
    case 0x0090: return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA (0x0090)";
    case 0xc090: return "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc090)";
    case 0xc096: return "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc096)";
    case 0xc09a: return "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc09a)";
    case 0xc0aa: return "TLS_PSK_DHE_WITH_AES_128_CCM_8 (0xc0aa)";
    case 0xc034: return "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA (0xc034)";
    case 0x008f: return "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA (0x008f)";
    case 0x009d: return "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)";
    case 0xc09d: return "TLS_RSA_WITH_AES_256_CCM (0xc09d)";
    case 0x003d: return "TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)";
    case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)";
    case 0xc032: return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 (0xc032)";
    case 0xc02a: return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 (0xc02a)";
    case 0xc00f: return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (0xc00f)";
    case 0xc02e: return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02e)";
    case 0xc026: return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 (0xc026)";
    case 0xc005: return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xc005)";
    case 0xc0a1: return "TLS_RSA_WITH_AES_256_CCM_8 (0xc0a1)";
    case 0xc07b: return "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc07b)";
    case 0x00c0: return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c0)";
    case 0x0084: return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)";
    case 0xc08d: return "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc08d)  ";
    case 0xc079: return "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc079)  ";
    case 0xc089: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc089)";
    case 0xc075: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc075)";
    case 0x009c: return "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)";
    case 0xc09c: return "TLS_RSA_WITH_AES_128_CCM (0xc09c)";
    case 0x003c: return "TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)";
    case 0x002f: return "TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)";
    case 0xc031: return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0xc031)";
    case 0xc029: return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0xc029)";
    case 0xc00e: return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (0xc00e)";
    case 0xc02d: return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02d)";
    case 0xc025: return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 (0xc025)";
    case 0xc004: return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xc004)";
    case 0xc0a0: return "TLS_RSA_WITH_AES_128_CCM_8 (0xc0a0)";
    case 0xc07a: return "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc07a)";
    case 0x00ba: return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00ba)";
    case 0x0041: return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)";
    case 0xc08c: return "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc08c)";
    case 0xc078: return "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc078)";
    case 0xc088: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc088)";
    case 0xc074: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc074)";
    case 0x000a: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)";
    case 0xc00d: return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (0xc00d)  ";
    case 0xc003: return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc003)";
    case 0x00ad: return "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 (0x00ad)";
    case 0x00b7: return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 (0x00b7)";
    case 0x0095: return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA (0x0095)";
    case 0xc093: return "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc093)";
    case 0xc099: return "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc099)";
    case 0x00ac: return "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 (0x00ac)";
    case 0x00b6: return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 (0x00b6)";
    case 0x0094: return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA (0x0094)";
    case 0xc092: return "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc092)";
    case 0xc098: return "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc098)";
    case 0x0093: return "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA (0x0093)";
    case 0x00a9: return "TLS_PSK_WITH_AES_256_GCM_SHA384 (0x00a9)";
    case 0xc0a5: return "TLS_PSK_WITH_AES_256_CCM (0xc0a5)";
    case 0x00af: return "TLS_PSK_WITH_AES_256_CBC_SHA384 (0x00af)";
    case 0x008d: return "TLS_PSK_WITH_AES_256_CBC_SHA (0x008d)";
    case 0xc08f: return "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc08f)";
    case 0xc095: return "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc095)";
    case 0xc0a9: return "TLS_PSK_WITH_AES_256_CCM_8 (0xc0a9)";
    case 0x00a8: return "TLS_PSK_WITH_AES_128_GCM_SHA256 (0x00a8)";
    case 0xc0a4: return "TLS_PSK_WITH_AES_128_CCM (0xc0a4)";
    case 0x00ae: return "TLS_PSK_WITH_AES_128_CBC_SHA256 (0x00ae)";
    case 0x008c: return "TLS_PSK_WITH_AES_128_CBC_SHA (0x008c)";
    case 0xc08e: return "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc08e)";
    case 0xc094: return "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc094)";
    case 0xc0a8: return "TLS_PSK_WITH_AES_128_CCM_8 (0xc0a8)";
    case 0x008b: return "TLS_PSK_WITH_3DES_EDE_CBC_SHA (0x008b)";
    case 0xc007: return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007)";
    case 0xc011: return "TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011)";
    case 0xc033: return "TLS_ECDHE_PSK_WITH_RC4_128_SHA (0xc033)";
    case 0x008e: return "TLS_DHE_PSK_WITH_RC4_128_SHA (0x008e) ";
    case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA (0x0005)";
    case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5 (0x0004)";
    case 0xc00c: return "TLS_ECDH_RSA_WITH_RC4_128_SHA (0xc00c)";
    case 0xc002: return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA (0xc002) ";
    case 0x0092: return "TLS_RSA_PSK_WITH_RC4_128_SHA (0x0092)";
    case 0x008a: return "TLS_PSK_WITH_RC4_128_SHA (0x008a)";
    case 0x1302: return "TLS_AES_256_GCM_SHA384 (0x1302)";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256 (0x1303)";
    case 0x1301: return "TLS_AES_128_GCM_SHA256 (0x1301)";
    case 0xcca9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)";
    case 0xcca8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)";
    case 0xccaa: return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)";
    default:return "0x" + QString::number(code,16);
    }
}
/********************** get tls handshake compression **********************/
QString Tls::getTlsHandshakeCompression(uchar code){
    switch (code) {
    case 0:return "null";
    default:return "";
    }
}

QString Tls::getTlsHandshakeExtension(ushort type){
    switch (type) {
    case 0: return "server_name";
    case 5: return "status_request";
    case 11:return "ec_point_format";
    case 10:return "supported_groups";
    case 35:return "session_ticket";
    case 22:return "encrypt_then_mac";
    case 23:return "extended_master_secret";
    case 13:return "signature_algorithms";
    case 43:return "supported_versions";
    case 45:return "psk_key_exchange_modes";
    case 51:return "key_share";
    case 21:return "padding";
    case 18:return "signed_certificate_timestamp";
    case 39578:return "Reserved (GREASE) (39578)";
    default:return "Unknown type";
    }
}

QString Tls::getTlsHandshakeExtensionECPointFormat(uchar type){
    switch (type) {
    case 0:return "EC point format: uncompressed (0)";
    case 1:return "EC point format: ansiX962_compressed_prime (1)";
    case 2:return "EC point format: ansiX962_compressed_char2 (2)";
    default:return QString::number(type);
    }
}

QString Tls::getTlsHandshakeExtensionSupportGroup(ushort type){
    switch (type) {
    case 0x001d:return "x25519 (0x001d)";
    case 0x0017:return "secp256r1 (0x0017)";
    case 0x001e:return "x448 (0x001e)";
    case 0x0019:return "secp521r1 (0x0019)";
    case 0x0018:return "secp384r1 (0x0018)";
    case 0x001c:return "brainpoolP512r1 (0x001c)";
    case 0x001b:return "brainpoolP384r1 (0x001b)";
    case 0x0016:return "secp256k1 (0x0016)";
    case 0x001a:return "brainpoolP256r1 (0x001a)";
    case 0x0015:return "secp224r1 (0x0015)";
    case 0x0014:return "secp224k1 (0x0014)";
    case 0x0013:return "secp192r1 (0x0013)";
    case 0x0012:return "secp192k1 (0x0012)";
    default:return "0x" + QString::number(type,16);
    }
}

QString Tls::getTlsHadshakeExtensionHash(uchar type){
    switch (type) {
    case 4:return "SHA256";
    case 5:return "SHA384";
    case 6:return "SHA512";
    case 2:return "SHA1";
    case 3:return "SHA224";
    case 1:return "MD5";
    default:return "Unknown";
    }
}
QString Tls::getTlsHadshakeExtensionSignature(uchar type){
    switch (type) {
    case 1:return "RSA";
    case 2:return "DSA";
    case 3:return "ECDSA";
    default:return "Unknown";
    }
}
ushort Tls::getTlsExtensionType(int offset){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    return ntohs(*ssl);
}

void Tls::getTlsExtensionServerName(int offset, ushort &type, ushort &length, ushort &listLength, uchar &nameType, ushort &nameLength, QString &name){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    listLength = ntohs(*ssl);
    ssl++;
    uchar*p = (uchar*)ssl;
    nameType = *p;
    p++;
    nameLength = (*p) * 16 + *(p+1);
    p += 2;
    for(int i = 0;i < nameLength;i++){
        name += QChar(*p);
        p++;
    }
    return;
}

void Tls::getTlsExtensionKeyShare(int offset, ushort &type, ushort &length, ushort &shareLength, ushort &group, ushort &exchangeLength,QString &exchange){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    shareLength = ntohs(*ssl);
    ssl++;
    group = ntohs(*ssl);
    ssl++;
    exchangeLength = ntohs(*ssl);
    ssl++;
    uchar*point = (uchar*)(ssl);
    for(int i = 0;i < exchangeLength;i++){
        exchange += QString::number(*point,16);
        point++;
    }
}

void Tls::getTlsExtensionEcPointFormats(int offset, ushort &type, ushort &length,uchar& ecLength,QVector<uchar> &EC){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    uchar* point = (uchar*)(ssl);
    ecLength = *point;
    point++;
    for(int i = 0;i < ecLength;i++){
        EC.push_back(*point);
        point++;
    }
}

void Tls::getTlsExtensionOther(int offset, ushort &type, ushort &length,QString&data){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    uchar*point = (uchar*)(ssl);
    for(int i = 0;i < length;i++){
        data += QString::number(*point,16);
        point++;
    }
}

void Tls::getTlsExtensionSupportGroups(int offset, ushort &type, ushort &length, ushort &groupListLength, QVector<ushort> &group){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    groupListLength = ntohs(*ssl);
    ssl++;
    for(int i = 0;i < groupListLength/2;i++){
        group.push_back(ntohs(*ssl));
        ssl++;
    }
}

void Tls::getTlsExtensionSessionTicket(int offset, ushort &type, ushort &length){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
}

void Tls::getTlsExtensionEncryptThenMac(int offset, ushort &type, ushort &length){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
}

void Tls::getTlsExtensionExtendMasterSecret(int offset, ushort &type, ushort &length){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
}

void Tls::getTlsExtensionSignatureAlgorithms(int offset, ushort &type, ushort &length, ushort &algorithmLength, QVector<ushort> &signatureAlgorithm){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    algorithmLength = ntohs(*ssl);
    ssl++;
    for(int i = 0;i < algorithmLength/2;i++){
        signatureAlgorithm.push_back(ntohs(*ssl));
        ssl++;
    }
}

void Tls::getTlsExtensionSupportVersions(int offset, ushort &type, ushort &length, uchar &supportLength, QVector<ushort> &supportVersion){
    ushort*ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    uchar*point = (uchar*)(ssl);
    supportLength = *point;
    point++;
    ssl = (ushort*)(point);
    for(int i = 0;i < supportLength;i++){
        supportVersion.push_back(ntohs(*ssl));
        ssl++;
    }
}

void Tls::getTlsExtensionPskKeyExchangeModes(int offset, ushort &type, ushort &length, uchar &modeLength, QVector<uchar> &mode)
{

}

void Tls::getTlsExtensionPadding(int offset, ushort &type, ushort &length,QString& data){
    ushort* ssl;
    ssl = (ushort*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    uchar*point = (uchar*)(ssl);
    for(int i = 0;i < length;i++){
        data += QString::number(*point,16);
        point++;
    }
}
