#ifndef HOSTINFO_H
#define HOSTINFO_H
#include <QVector>

class HostInfo
{
public:
    HostInfo();
    HostInfo(QString ip);

    //get
    QString getIp();
    QVector<int> getPorts();
    QString getOS();
    bool getIsAlive();

    //set
    void setIp(QString ip);
    void setPorts(int port);
    void setOS(QString os);
    void setIsAlive(bool status);

private:
    QString ip;
    QVector<int> ports;
    QString OS;
    bool isAlive;
};

#endif // HOSTINFO_H
