#include "hostscanner.h"

#include <QProcess>

HostScanner::HostScanner(QObject *parent)
    : QThread{parent}
{

}

void HostScanner::scanHost(const QString ip)
{
    //主机：10.13.156.88
    QString ipAddr = "192.168.31.30";
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

        QString host =  ipAddr + " -c 1";   //可以扫描主机
        QString cmd = "ping";
        QProcess process;

        process.start(cmd,{host},QIODeviceBase::ReadWrite);
        process.waitForFinished(500);
//        qDebug()<< process.errorString();
        QString output = QString::fromLocal8Bit(process.readAllStandardOutput());
        if (output.contains("ttl=")) {
            qDebug() << "Host" << ipAddr << "is online.";
        } else {
            qDebug() << "Host" << ipAddr << "is offline.";
            qDebug()<< output.data()->unicode();
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
