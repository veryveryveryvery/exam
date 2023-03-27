#include "hostscanner.h"
#include <QProcess>

HostScanner::HostScanner(QObject *parent)
    : QThread{parent}
{

}

void HostScanner::setSubnet(const QString subnet)
{
    this->subnet = subnet;
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
}

void HostScanner::run()
{
    for(int i=1; i<255; i++)//可以扫描主机
    {
        QString cmd = "ping";
        QProcess process;
        QString ipAddr = subnet + QString::number(i);
        process.start(cmd,{ipAddr},QIODeviceBase::ReadWrite);
        process.waitForFinished(300);
//        qDebug()<< process.errorString();
        QString output = QString::fromLocal8Bit(process.readAllStandardOutput());
        if (output.contains("ttl=")) {
            qDebug() << "ip:" << ipAddr << "is online.";
            emit send(HostInfo(ipAddr));
        } else {
//            qDebug() << "ip:" << ipAddr << "is offline.";
        }
        process.close();
    }
}

