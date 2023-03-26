#include "scan.h"
#include "ui_scan.h"

Scan::Scan(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Scan)
{
    ui->setupUi(this);

}
Scan::~Scan()
{
    delete ui;
}

void Scan::scanner()
{
    HostScanner* searchIp = new HostScanner;
    searchIp->scanHost("");
}


void Scan::on_pushButton_clicked()
{
    scanner();
}

