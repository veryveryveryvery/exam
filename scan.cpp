#include "scan.h"
#include "ui_scan.h"

Scan::Scan(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::Scan)
{
    ui->setupUi(this);

    HostScanner* search_ip = new HostScanner;
    this->countNumber = 0;

    ui->lineEdit->setInputMask("009.099.099.; ");
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnCount(3);
    QStringList title = {"Number","IP","Port"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,120);
    ui->tableWidget->setColumnWidth(2,550);
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);


    connect(ui->pushButton, &QPushButton::clicked, this, [=](){
        this->ui->tableWidget->clearContents();
        this->ui->tableWidget->setRowCount(0);
        this->ip_list.clear();
        this->countNumber = 0;
        search_ip->terminate();

        QString subnet = ui->lineEdit->text();
        qDebug()<<subnet;
        search_ip->setSubnet(subnet);
        search_ip->start();
    });

    connect(search_ip, &HostScanner::send, this, [=](HostInfo ip){
        this->ip_list.append(ip);
        showHostinfo(ip);
    });


}
Scan::~Scan()
{
    delete ui;
}

void Scan::showHostinfo(HostInfo ip)
{
    qDebug()<< ip.getIp();
    ui->tableWidget->insertRow(countNumber);
    ui->tableWidget->setItem(countNumber, 0, new QTableWidgetItem(QString::number(countNumber + 1)));
    ui->tableWidget->setItem(countNumber, 1, new QTableWidgetItem(ip.getIp()));
    ui->tableWidget->setItem(countNumber, 2, new QTableWidgetItem(ip.getPorts()));
    countNumber++;
}



