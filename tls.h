#ifndef TLS_H
#define TLS_H
#include "datapackage.h"

class Tls : public DataPackage
{
public:
    Tls();
    Tls(DataPackage);

    // get the tls info
    virtual bool getisTlsProtocol(int offset);
    virtual void getTlsBasicInfo(int offset,uchar&contentType,ushort&version,ushort&length);
    virtual void getTlsClientHelloInfo(int offset,uchar&handShakeType,int& length,ushort&version,QString&random,uchar&sessionIdLength,QString&sessionId,ushort&cipherLength,QVector<ushort>&cipherSuit,uchar& cmLength,QVector<uchar>&CompressionMethod,ushort&extensionLength);
    virtual void getTlsServerHelloInfo(int offset,uchar&handShakeType,int&length,ushort&version,QString& random,uchar&sessionIdLength,QString&sessionId,ushort&cipherSuit,uchar&compressionMethod,ushort&extensionLength);
    virtual void getTlsServerKeyExchange(int offset,uchar&handShakeType,int&length,uchar&curveType,ushort&curveName,uchar&pubLength,QString&pubKey,ushort&sigAlgorithm,ushort&sigLength,QString&sig);
    virtual ushort getTlsExtensionType(int offset);
    virtual void getTlsHandshakeType(int offset,uchar&type);

    /*
     * these functions are used to parse the extension parts
     * extension parts are common in handshake parts (client hello,server hello ...)
     * there are some extension types are not included in, maybe you should refer the official API
    */
    virtual void getTlsExtensionServerName(int offset,ushort&type,ushort&length,ushort&listLength,uchar&nameType,ushort&nameLength,QString& name);
    virtual void getTlsExtensionSignatureAlgorithms(int offset,ushort&type,ushort&length,ushort&algorithmLength,QVector<ushort>&signatureAlgorithm);
    virtual void getTlsExtensionSupportGroups(int offset,ushort&type,ushort&length,ushort&groupListLength,QVector<ushort>&group);
    virtual void getTlsExtensionEcPointFormats(int offset,ushort&type,ushort&length,uchar& ecLength,QVector<uchar>&EC);
    virtual void getTlsExtensionSessionTicket(int offset,ushort&type,ushort&length);
    virtual void getTlsExtensionEncryptThenMac(int offset,ushort&type,ushort&length);
    virtual void getTlsExtensionSupportVersions(int offset,ushort&type,ushort&length,uchar&supportLength,QVector<ushort>&supportVersion);
    virtual void getTlsExtensionPskKeyExchangeModes(int offset,ushort&type,ushort&length,uchar&modeLength,QVector<uchar>&mode);
    virtual void getTlsExtensionKeyShare(int offset,ushort&type,ushort&length,ushort&shareLength,ushort&group,ushort&exchangeLength,QString& exchange);
    virtual void getTlsExtensionOther(int offset,ushort&type,ushort&length,QString& data);
    virtual void getTlsExtensionExtendMasterSecret(int offset,ushort&type,ushort&length);
    virtual void getTlsExtensionPadding(int offset,ushort&type,ushort&length,QString&data);

    /*
     * when transfer data,some types will be encoded,like using 0x01 to represent the MD5 in extension hash part
     * to visual display these types,we need to decode and analysis
     * this functions are used to do these analisis
     * however,some types may be the custom types, so we can't decode
     * also,there are some rules not be included, maybe you should refer the official API
    */
    // Parsing the encode data
    virtual QString getTlsHandshakeType(int type);                         // Parsing TLS handshake type
    virtual QString getTlsContentType(int type);                           // Parsing TLS content type
    virtual QString getTlsVersion(int version);                            // Parsing TLS version
    virtual QString getTlsHandshakeCipherSuites(ushort code);              // Parsing TLS cipher suite
    virtual QString getTlsHandshakeCompression(uchar code);                // Parsing TLS compression
    virtual QString getTlsHandshakeExtension(ushort type);                 // Parsing TLS extension
    virtual QString getTlsHandshakeExtensionECPointFormat(uchar type);     // Parsing TLS EC point format
    virtual QString getTlsHandshakeExtensionSupportGroup(ushort type);     // Parsing TLS support group
    virtual QString getTlsHadshakeExtensionSignature(uchar type);          // Parsing TLS signature
    virtual QString getTlsHadshakeExtensionHash(uchar type);               // Parsing TLS hash
};



#endif // TLS_H
