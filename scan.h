#ifndef SCAN_H
#define SCAN_H

#include <QMainWindow>
#include <QVector>
#include <QCoreApplication>
#include <QHostInfo>
#include <QDebug>
#include "hostinfo.h"
#include "hostscanner.h"

namespace Ui {
class Scan;
}

class Scan : public QMainWindow
{
    Q_OBJECT

public:
    explicit Scan(QWidget *parent = nullptr);
    ~Scan();
    QVector<HostInfo> host_list;

    void scanner();


private slots:
    void on_pushButton_clicked();

private:
    Ui::Scan *ui;
};

#endif // SCAN_H
