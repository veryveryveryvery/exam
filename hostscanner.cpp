#include "hostscanner.h"

HostScanner::HostScanner(QObject *parent)
    : QThread{parent}
{

}

void HostScanner::scanHost(const QString ip)
{
    //主机：10.13.156.88
    QString ipAddr = "192.168.188.";
//    int startPort = 1;
//    int endPort = 254;
//    for(int i=startPort; i<=endPort;i++)
//    {
//        QString currentIp = ipAddr + QString::number(i);
//        QTcpSocket tcpSocket;
//        tcpSocket.connectToHost(currentIp, 8080);    //此方式扫描端口可行
//        if(tcpSocket.waitForConnected(100))
//        {
//            qDebug()<< "IP地址:" + currentIp << "端口号8080可用";
//        }
//        else
//            qDebug()<< "IP地址:" + currentIp << "端口号8080不可用";
//    }
    for(int i=30;i<40;i++)
    {
        QString currentIP = ipAddr + QString::number(i);
        QHostInfo::lookupHost(currentIP, this, SLOT(lookup(QHostInfo)));
    }

}

void HostScanner::lookup(QHostInfo info)
{
    if(info.error() == QHostInfo::NoError)
    {
        qDebug()<< info.hostName() + " 占用" +info.errorString() + info.localHostName();
    }
    else
    {
        qDebug()<< info.hostName() + " 没有占用";
    }
}
