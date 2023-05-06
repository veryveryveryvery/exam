#ifndef CAPTURE_H
#define CAPTURE_H

#include <QObject>
#include <pcap.h>
#include <QDebug>
#include "datapackage.h"
#include <QMutex>


class Capture : public QObject
{
    Q_OBJECT
public:
    explicit Capture(QObject *parent = nullptr);
    bool setPointer(pcap_t* pointer);  //传入会话地址
    void setStop();
    void setStart();
    bool getIsDone();
    void working();
    static QString byteToString(uchar *str, int size);

    QMutex pauseLook;

    int ethernetPackageHandle(const uchar *pkt_content, QString& info);

    int ipPackageHandle(const uchar *pkt_content,int& ipPackage);
    QString arpPackageHandle(const uchar *pkt_content);
    QString icmpPackageHandle(const uchar *pkt_content);
    int tcpPackageHandle(const uchar *pkt_content, QString& info, int ipPackage);
    int udpPackageHandle(const uchar *pkt_content, QString& info);
    QString dnsPackageHandle(const uchar *pkt_content);

signals:
    void send(DataPackage data);

private:
    pcap_t* pointer;              //会话指针
    struct pcap_pkthdr* header;   //定义数据包头部结构
    const uchar* pkt_data;       //数据包内容
    time_t local_time_sec;        //时间戳
    struct tm local_time;         //定义时间格式
    char timeString[16];
    bool isRunning;                  //判断线程是否结束

};

#endif // CAPTURE_H
