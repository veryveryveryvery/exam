#include "hostscanner.h"
#include <QProcess>

HostScanner::HostScanner(QObject *parent)
    : QThread{parent}
{

}

void HostScanner::setSubnet(const QString subnet)
{
    this->subnet = subnet;
}

QVector<int> HostScanner::portScan(QString ip)
{
    QVector<int> port_list;
    for(auto &x : ports)
    {
        QTcpSocket tcpSocket;
        tcpSocket.connectToHost(ip, x);
        if(tcpSocket.waitForConnected(100))
        {
            port_list.append(x);
        }

    }
    return port_list;
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
            QVector<int> port_list =  portScan(ipAddr);
            emit send(HostInfo(ipAddr, port_list));
        }
        process.close();
    }
}

