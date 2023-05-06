#ifndef HOSTSCANNER_H
#define HOSTSCANNER_H

#include <QThread>
#include <QTcpSocket>
#include <QDebug>
#include <QVector>
#include "hostinfo.h"

class HostScanner : public QThread
{
    Q_OBJECT
public:
    explicit HostScanner(QObject *parent = nullptr);
    QString subnet = "";
    QVector<int> ports = {20,21,22,23,25,53,67,68,68,80,110,119,123,143,161,194,389,
    443,465,514,587,873,993,995,1080,1433,1531,1723,2049,3306,3389,5432,5900,6379,8080};
    QVector<HostInfo> ip_list;

    void setSubnet(const QString ip);
    QVector<int> portScan(QString ip);

protected:
    void run() override;
signals:
    void send(HostInfo);
};

#endif // HOSTSCANNER_H
