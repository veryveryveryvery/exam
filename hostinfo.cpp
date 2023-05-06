#include "hostinfo.h"
#include <QMetaType>
HostInfo::HostInfo()
{
    qRegisterMetaType<HostInfo>("HostInfo");
    this->ip = "";
    this->OS = "";
    this->isAlive = false;
}

HostInfo::HostInfo(QString ip, QVector<int> port_list)
{
    this->ip = ip;
    this->ports = port_list;
}

QString HostInfo::getIp()
{
    return this->ip;
}

QString HostInfo::getPorts()
{
    QString str = "";
    for(auto &x : ports)
    {
        str += QString::number(x) + " ";
    }
    return str;
}

QString HostInfo::getOS()
{
    return this->OS;
}

bool HostInfo::getIsAlive()
{
    return this->isAlive;
}

void HostInfo::setIp(QString ip)
{
    this->ip = ip;
}

void HostInfo::setPorts(int port)
{
    this->ports.append(port);
}

void HostInfo::setOS(QString os)
{
    this->OS = os;
}

void HostInfo::setIsAlive(bool status)
{
    this->isAlive  = status;
}
