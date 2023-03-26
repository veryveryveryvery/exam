#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QObject>
#include <pcap.h>
#include <QVector>
#include <QThread>
#include "datapackage.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "dns.h"


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    bool index = false;  //是否开始
    QString returnPress = "";
    void showNetworkCark();
    int capture();
    void handleMessage(DataPackage data);

    void clearAll();
    void next_packet();
    void previous_packet();
    void first_packet();
    void last_packet();
    void scanner();
    void filter();

    void ARP_analysis();
    void IP_analysis();
    void TCP_analysis();
    void TLS_analysis();
    void SSL_analysis();
    void UDP_analysis();
    void DNS_analysis();
    void ICMP_analysis();



private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);
    void on_lineEdit_returnPressed();

signals:
    void clear();

private:
    Ui::MainWindow *ui;
    pcap_if_t* all_device;  //所有的网卡设备
    pcap_if_t* device;      //指向当前网卡
    pcap_t* pointer;        //会话指针
    char errbuf[PCAP_ERRBUF_SIZE];  //错误信息

    QVector<DataPackage> data;
    int countNumber;      //数据包的个数
    int current_row;      //记录选中的第几行的数据包
    DataPackage* pkt_arp;
    DataPackage* pkt_ip;
    DataPackage* pkt_tcp;
    DataPackage* pkt_udp;
    DataPackage* pkt_dns;
    DataPackage* pkt_icmp;

};
#endif // MAINWINDOW_H
