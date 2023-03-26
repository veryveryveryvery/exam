#ifndef HOSTSCANNER_H
#define HOSTSCANNER_H

#include <QThread>
#include <QTcpSocket>
#include <QDebug>
#include <QHostInfo>

class HostScanner : public QThread
{
    Q_OBJECT
public:
    explicit HostScanner(QObject *parent = nullptr);
//    QHostInfo info;

    void scanHost(const QString ip);


protected slots:
    void lookup(QHostInfo info);

signals:
    void hostIsUp(const QString ip);

};

#endif // HOSTSCANNER_H
