#ifndef SCAN_H
#define SCAN_H

#include <QMainWindow>
#include <QVector>
#include <QDebug>
#include <QThread>
#include "hostscanner.h"
#include "hostinfo.h"

namespace Ui {
class Scan;
}

class Scan : public QMainWindow
{
    Q_OBJECT

public:
    explicit Scan(QWidget *parent = nullptr);
    ~Scan();
    QVector<HostInfo> ip_list;
    int countNumber;

    void showHostinfo(HostInfo);

private slots:

private:
    Ui::Scan *ui;
};

#endif // SCAN_H
