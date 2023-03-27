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
    QVector<HostInfo> ip_list;

    void setSubnet(const QString ip);

protected:
    void run() override;
signals:
    void send(HostInfo);


};

#endif // HOSTSCANNER_H
