#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "capture.h"
#include "scan.h"
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //初始化工具栏
    ui->toolBar->addAction(ui->actionstart_stop);
    ui->toolBar->addAction(ui->actionclear);
    ui->toolBar->addAction(ui->actionprevious_packet);
    ui->toolBar->addAction(ui->actionnext_Packet);
    ui->toolBar->addAction(ui->actionfirst_packet);
    ui->toolBar->addAction(ui->actionlast_packet);
    ui->toolBar->addAction(ui->actionscanner);


    //初始化主界面
    this->resize(1300, 700);
    ui->tableWidget->setShowGrid(false);
    ui->toolBar->setMovable(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnCount(7);
    QStringList title = {"NO.","Time","Source","Destination","Protocol","Length","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,300);
    ui->tableWidget->setColumnWidth(3,300);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,1000);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);  //选择单元格时变为选择当前行
    ui->tableWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);

    ui->treeWidget->setHeaderHidden(true);


    showNetworkCark();  //初始化指向网卡的指针
//    static bool index = false;  //是否开始
    QThread* thread_start = new QThread;  //创建一个线程
    Capture* cap = new Capture;     //创建任务对象
    countNumber = 0;  //初始化数据包个数
    current_row = -1;          //初始化行号，表示起初没有选中数据包

    connect(thread_start, &QThread::started, cap, &Capture::working);
    connect(cap, &Capture::send, this, &MainWindow::handleMessage);
    connect(cap, &Capture::send, this, &MainWindow::filter);

    //点击开始或结束捕获的按钮时
    connect(ui->actionstart_stop, &QAction::triggered, this, [=](){
        index = !index;   //第一次：true，false,
        if(index)
        {
            int n = capture();
            if(pointer && n != -1) //选择了网卡且启动网卡监听
            { 
                cap->setPointer(pointer);
                cap->moveToThread(thread_start);
                cap->setStart();
                thread_start->start();
                ui->comboBox->setEnabled(false);
                ui->actionstart_stop->setIcon(QIcon(":/stop.png"));
            }
            else
            {
                index = !index;  //置为false，重新进来又变为true
            }
        }
        else      //结束
        {
            cap->setStop();
            thread_start->quit();
            thread_start->wait();
            pcap_close(pointer);
            ui->comboBox->setEnabled(true);
            ui->actionstart_stop->setIcon(QIcon(":/start.png"));

        }
    });
    //点击清除按钮
    connect(ui->actionclear, &QAction::triggered, this, [=](){
        if(!index && countNumber > 0){   //非捕获状态
            int type = QMessageBox::information(this,"information","Do you want to clear all?","Yes","Cancel");
            if(type == 0){
                ui->tableWidget->setFocus();
                ui->treeWidget->setFocus();
                ui->tableWidget->clearContents();
                ui->tableWidget->setRowCount(0);
                ui->treeWidget->clear();
                countNumber = 0;
                current_row = -1;
                int dataSize = this->data.size();
                for(int i = 0;i < dataSize;i++){
                    free((char*)(this->data[i].pkt_content));
                    this->data[i].pkt_content = nullptr;
                }
                QVector<DataPackage>().swap(data);
                ui->tableWidget->viewport()->update();
            }
        }

    });


    connect(ui->actionprevious_packet, &QAction::triggered, this, &MainWindow::previous_packet);
    connect(ui->actionnext_Packet, &QAction::triggered, this, &MainWindow::next_packet);
    connect(ui->actionfirst_packet, &QAction::triggered, this, &MainWindow::first_packet);
    connect(ui->actionlast_packet, &QAction::triggered, this, &MainWindow::last_packet);
    connect(ui->actionscanner, &QAction::triggered, this, &MainWindow::scanner);

}

MainWindow::~MainWindow()
{
    // free the memory you have allocated!
    int dataSize = this->data.size();
    for(int i = 0;i<dataSize;i++){
        free((char*)(this->data[i].pkt_content));
        this->data[i].pkt_content = nullptr;

    }
    // 通过 swap()方法完全释放 vector占用的内存
    QVector<DataPackage>().swap(data);
    delete ui;
}
//获取网卡链表
void MainWindow::showNetworkCark()
{
    int n = pcap_findalldevs(&all_device, errbuf);  //all_device初始化
    ui->comboBox->clear();
    if(n == -1)
    {
        statusBar()->showMessage("存在未知错误：" + QString(errbuf));
        ui->comboBox->addItem("未能找到相应的网卡，请重新试一下");
        return;
    }
    ui->comboBox->clear();
    ui->comboBox->addItem("请选择网卡");
    for(device = all_device; device != nullptr; device = device->next)  //将网卡设备显示在comboBox
    {
        QString device_name = device->name;
//        qDebug() << device_name;
        QString device_description = device->description;
        QString item = device_name + "  " + device_description;
        ui->comboBox->addItem(item);
    }
}

//选择某张网卡
void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
//    qDebug()<< index;
    if(index != 0)
    {
        for(device = all_device; i<index-1; i++)
            device = device->next;
//        qDebug()<< device->name;
    }
    else
        device = nullptr;
}

int MainWindow::capture()
{
    if(device)
    {
        pointer = pcap_open_live(device->name, 65536, 1, 1000, errbuf);  //该函数返回我们的会话处理程序
//        qDebug()<< pointer;
    }
    else
    {
        statusBar()->showMessage("请选择网卡！");
        return -1;
    }
    if(!pointer)
    {
        statusBar()->showMessage(errbuf);
        pcap_freealldevs(all_device);
        device = nullptr;
        return -1;
    }
    else
    {
        //检查数据链路
        if(pcap_datalink(pointer) != DLT_EN10MB)  //返回链路层的类型，DLT_EN10MB是以太网类型
        {
            pcap_close(pointer);
            pcap_freealldevs(all_device);
            device = nullptr;
            return -1;
        }
        statusBar()->showMessage(device->name);
    }
    return 0;
}

void MainWindow::next_packet()
{
    int index = ui->tableWidget->currentRow();
    if(index >= 0 && index < countNumber -1)
    {
        index = index + 1;
        ui->tableWidget->setCurrentCell(index, 0);
        on_tableWidget_cellClicked(index, 0);
    }
    qDebug()<< "countNumber: " + QString::number(countNumber) + "  current_row: " + QString::number(current_row);
}

void MainWindow::previous_packet()
{
    int index = ui->tableWidget->currentRow();
    if(index > 0)
    {
        index = index -1;
        ui->tableWidget->setCurrentCell(index, 0);
        on_tableWidget_cellClicked(index, 0);
    }
    qDebug()<< "countNumber: " + QString::number(countNumber) + "  current_row: " + QString::number(current_row);
}

void MainWindow::first_packet()
{
    if(countNumber > 0)
    {
        int index = 0;
        ui->tableWidget->setCurrentCell(index, 0);
        on_tableWidget_cellClicked(index, 0);
    }
    qDebug()<< "countNumber: " + QString::number(countNumber) + "  current_row: " + QString::number(current_row);
}

void MainWindow::last_packet()
{
    if(countNumber > 0)
    {
        int index = countNumber - 1;
        ui->tableWidget->setCurrentCell(index, 0);
        on_tableWidget_cellClicked(index, 0);
    }
    qDebug()<< "countNumber: " + QString::number(countNumber) + "  current_row: " + QString::number(current_row);
}

void MainWindow::scanner()
{
    Scan* scan = new Scan(this);
    scan->setAttribute(Qt::WA_DeleteOnClose);
    scan->setWindowTitle("主机扫描");
    scan->setWindowOpacity(1);
    scan->show();
}

void MainWindow::filter()
{
    if(returnPress == "")
        return;
    else if(ui->tableWidget->item(countNumber-1, 4)->text() != returnPress )
    {
        ui->tableWidget->setRowHidden(countNumber-1, true);
    }
}

void MainWindow::handleMessage(DataPackage data)
{
    ui->tableWidget->insertRow(countNumber);
    this->data.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    // show different color
    if(type == TCP){
        color = QColor(216,191,216);
    }else if(type == TCP){
        color = QColor(144,238,144);
    }
    else if(type == ARP){
        color = QColor(238,238,0);
    }
    else if(type == DNS){
        color = QColor(255,255,224);
    }else if(type == TLS || type == SSL){
        color = QColor(210,149,210);
    }else{
        color = QColor(255,218,185);
    }
    ui->tableWidget->setItem(countNumber,0,new QTableWidgetItem(QString::number(countNumber + 1)));
    ui->tableWidget->setItem(countNumber,1,new QTableWidgetItem(data.getTimeStamp()));
    ui->tableWidget->setItem(countNumber,2,new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(countNumber,3,new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(countNumber,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(countNumber,5,new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(countNumber,6,new QTableWidgetItem(data.getInfo()));
    // set color
    for(int i = 0;i < 7;i++){
        ui->tableWidget->item(countNumber,i)->setBackground(color);
    }
    countNumber++;
}

void MainWindow::on_lineEdit_returnPressed()
{
    QString text = ui->lineEdit->text();
    text = text.toUpper();
    if(text == "")  //未查找，显示全部
    {
        for(int i=0; i<countNumber; i++)
            ui->tableWidget->setRowHidden(i, false);
    }
    else if(text == "ARP" || text == "ICMP" || text == "TCP" || text == "UDP" || text == "SSL" || text == "TLS" || text == "DNS")  //显示相应的数据包
    {
        ui->lineEdit->setStyleSheet("QLineEdit {backgruond-color}: rgb(154,255,154);");
        this->returnPress = text;
        for(int i=0; i< countNumber; i++)
        {
            if(ui->tableWidget->item(i,4)->text() != text)
            {
                ui->tableWidget->setRowHidden(i, true);
            }
            else
            {
                ui->tableWidget->setRowHidden(i, false);
            }
        }
    }
    else   //未找到，隐藏全部
    {
        this->returnPress = text;
        for(int i=0; i< countNumber; i++)
        {
            ui->tableWidget->setRowHidden(i, true);
        }
    }
}

void MainWindow::on_tableWidget_cellClicked(int row, int)
{
    if(current_row == row || row < 0){
        return;
    }else{
        ui->treeWidget->clear();
        current_row = row;
        if(current_row < 0 || current_row > data.size())
            return;
        QString desMac = data[current_row].getDesMacAddr();
        QString srcMac = data[current_row].getSrcMacAddr();
        QString type = data[current_row].getMacType();
        QString tree1 = "Ethernet, Src:" +srcMac + ", Dst:" + desMac;
        QTreeWidgetItem*item = new QTreeWidgetItem(QStringList()<<tree1);
        ui->treeWidget->addTopLevelItem(item);
        item->addChild(new QTreeWidgetItem(QStringList()<<"Destination:" + desMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Source:" + srcMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type));

        QString packageType = data[current_row].getPackageType();
//        qDebug()<< packageType;
        if(packageType == "ARP")
        {
            ARP_analysis();
        }
        else
        {
            IP_analysis();
            if(packageType == TCP || packageType == TLS || packageType == SSL)
            {
                TCP_analysis();//!!!有bug
                if(packageType == TLS)
                    TLS_analysis();
                else
                    SSL_analysis();
            }else if(packageType == UDP || packageType == DNS)
            {
                UDP_analysis();
                if(packageType == DNS)
                    DNS_analysis();
            }else if(packageType == ICMP)
            {
                ICMP_analysis();
            }
        }
    }
}

void MainWindow::ARP_analysis()
{
    pkt_arp = new Arp(data[current_row]);
    QTreeWidgetItem* item2 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol "+pkt_arp->getArpOperationCode());
    ui->treeWidget->addTopLevelItem(item2);
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type:"+pkt_arp->getArpHardwareType()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type:"+pkt_arp->getArpProtocolType()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size:"+pkt_arp->getArpHardwareLength()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size:"+pkt_arp->getArpProtocolLength()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:"+pkt_arp->getArpOperationCode()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address:"+pkt_arp->getArpSourceEtherAddr()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address:"+pkt_arp->getArpSourceIpAddr()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address:"+pkt_arp->getArpDestinationEtherAddr()));
    item2->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address:"+pkt_arp->getArpDestinationIpAddr()));
}


void MainWindow::IP_analysis()
{
    pkt_ip = new IP(data[current_row]);

    QString srcIp = pkt_ip->getSrcIpAddr();
    QString desIp = pkt_ip->getDesIpAddr();

    QTreeWidgetItem*item3 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src:" + srcIp + ", Dst:" + desIp);
    ui->treeWidget->addTopLevelItem(item3);

    QString version = pkt_ip->getIpVersion();
    QString headerLength = pkt_ip->getIpHeaderLength();
    QString Tos = pkt_ip->getIpTos();
    QString totalLength = pkt_ip->getIpTotalLength();
    QString id = "0x" + pkt_ip->getIpIdentification();
    QString flags = pkt_ip->getIpFlag();
    if(flags.size()<2)
        flags = "0" + flags;
    flags = "0x" + flags;
    QString FragmentOffset = pkt_ip->getIpFragmentOffset();
    QString ttl = pkt_ip->getIpTTL();
    QString protocol = pkt_ip->getIpProtocol();
    QString checksum = "0x" + pkt_ip->getIpCheckSum();
    int dataLengthofIp = totalLength.toUtf8().toInt() - 20;
    item3->addChild(new QTreeWidgetItem(QStringList()<<"0100 .... = Version:" + version));
    item3->addChild(new QTreeWidgetItem(QStringList()<<".... 0101 = Header Length:" + headerLength));
    item3->addChild(new QTreeWidgetItem(QStringList()<<"TOS:" + Tos));
    item3->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:" + totalLength));
    item3->addChild(new QTreeWidgetItem(QStringList()<<"Identification:" + id));

    QString reservedBit = pkt_ip->getIpReservedBit();
    QString DF = pkt_ip->getIpDF();
    QString MF = pkt_ip->getIpMF();
    QString FLAG = ",";

    if(reservedBit == "1"){
        FLAG += "Reserved bit";
    }
    else if(DF == "1"){
        FLAG += "Don't fragment";
    }
    else if(MF == "1"){
        FLAG += "More fragment";
    }
    if(FLAG.size() == 1)
        FLAG = "";
    QTreeWidgetItem*bitTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags + FLAG);
    item3->addChild(bitTree);
    QString temp = reservedBit == "1"?"Set":"Not set";
    bitTree->addChild(new QTreeWidgetItem(QStringList()<<reservedBit + "... .... = Reserved bit:" + temp));
    temp = DF == "1"?"Set":"Not set";
    bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment:" + temp));
    temp = MF == "1"?"Set":"Not set";
    bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment:" + temp));

    item3->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset:" + FragmentOffset));
    item3->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live:" + ttl));
    item3->addChild(new QTreeWidgetItem(QStringList()<<"Protocol:" + protocol));
    item3->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum:" + checksum));
    item3->addChild(new QTreeWidgetItem(QStringList()<<"Source Address:" + srcIp));
    item3->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address:" + desIp));
}

void MainWindow::TCP_analysis()
{
    pkt_tcp = new Tcp(data[current_row]);
    QString desPort = pkt_tcp->getTcpDestinationPort();
    QString srcPort = pkt_tcp->getTcpSourcePort();
    QString ack = pkt_tcp->getTcpAcknowledgment();
    QString seq = pkt_tcp->getTcpSequence();
    QString headerLength = pkt_tcp->getTcpHeaderLength();
    int rawLength = pkt_tcp->getTcpRawHeaderLength().toUtf8().toInt();
    QString totalLength = pkt_ip->getIpTotalLength();
    int dataLengthofIp = totalLength.toUtf8().toInt() - 20;
    QString dataLength = QString::number(dataLengthofIp);
    QString flag = pkt_tcp->getTcpFlags();
    while(flag.size()<2)
        flag = "0" + flag;
    flag = "0x" + flag;
    QTreeWidgetItem* item4 = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort + ",Seq:" + seq + ", Ack:" + ack + ", Len:" + dataLength);

    ui->treeWidget->addTopLevelItem(item4);
    item4->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
    item4->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
    item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number (raw) :" + seq));
    item4->addChild(new QTreeWidgetItem(QStringList()<<"Ackowledgment Number (raw) :" + ack));


    QString sLength = QString::number(rawLength,2);
    while(sLength.size()<4)
        sLength = "0" + sLength;
    item4->addChild(new QTreeWidgetItem(QStringList()<<sLength + " .... = Header Length:" + headerLength));

    QString PSH = pkt_tcp->getTcpPSH();
    QString URG = pkt_tcp->getTcpURG();
    QString ACK = pkt_tcp->getTcpACK();
    QString RST = pkt_tcp->getTcpRST();
    QString SYN = pkt_tcp->getTcpSYN();
    QString FIN = pkt_tcp->getTcpFIN();
    QString FLAG = "";

    if(PSH == "1")
        FLAG += "PSH,";
    if(URG == "1")
        FLAG += "UGR,";
    if(ACK == "1")
        FLAG += "ACK,";
    if(RST == "1")
        FLAG += "RST,";
    if(SYN == "1")
        FLAG += "SYN,";
    if(FIN == "1")
        FLAG += "FIN,";
    FLAG = FLAG.left(FLAG.length()-1);
    if(SYN == "1"){
        item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
        item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 0 (relative ack number)"));
    }
    if(SYN == "1" && ACK == "1"){
        item4->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
        item4->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 1 (relative ack number)"));
    }
    QTreeWidgetItem* flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flag + " (" + FLAG + ")");
    item4->addChild(flagTree);
    QString temp = URG == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + URG + ". .... = Urgent(URG):" + temp));
    temp = ACK == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + ACK + " .... = Acknowledgment(ACK):" + temp));
    temp = PSH == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + PSH + "... = Push(PSH):" + temp));
    temp = RST == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + RST + ".. = Reset(RST):" + temp));
    temp = SYN == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .." + SYN + ". = Syn(SYN):" + temp));
    temp = FIN == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ..." + FIN + " = Fin(FIN):" + temp));

    QString window = pkt_tcp->getTcpWindowSize();
    QString checksum = "0x" + pkt_tcp->getTcpCheckSum();
    QString urgent = pkt_tcp->getTcpUrgentPointer();
    item4->addChild(new QTreeWidgetItem(QStringList()<<"window:" + window));
    item4->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
    item4->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer:" + urgent));
    if((rawLength * 4) > 20){
        QTreeWidgetItem * optionTree = new QTreeWidgetItem(QStringList()<<"Options: (" + QString::number(rawLength * 4 - 20) + ") bytes");
        item4->addChild(optionTree);
        for(int j = 0;j < (rawLength * 4 - 20);){
            int kind = pkt_tcp->getTcpOperationRawKind(j);
            switch (kind) {
            case 0:{
                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - End of List (EOL)");
                optionTree->addChild(subTree);
                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind:End of List (0)"));
                optionTree->addChild(subTree);
                j++;
                break;
            }case 1:{
                QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - No-Operation (NOP)");
                optionTree->addChild(subTree);
                subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: No-Operation (1)"));
                optionTree->addChild(subTree);
                j++;
                break;
            }
            case 2:{
                ushort mss;
                if(pkt_tcp->getTcpOperationMSS(j,mss)){
                    QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Maximun Segment Size: " + QString::number(mss) + " bytes");
                    optionTree->addChild(subTree);
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Maximun Segment Size (2)"));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 4"));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"MSS Value: " + QString::number(mss)));
                    j += 4;
                }
                break;
            }
            case 3:{
                u_char shift;
                if(pkt_tcp->getTcpOperationWSOPT(j,shift)){
                    int factor = 1 << shift;
                    QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - Window scale: " + QString::number(shift) + " (multiply by " + QString::number(factor) + ")");
                    optionTree->addChild(subTree);
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"kind: Window scale (3)"));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 3"));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Shift Count: " + QString::number(shift)));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"[Multiplier: " + QString::number(factor) + "]"));
                    j += 3;
                }
                break;
            }
            case 4:{
                if(pkt_tcp->getTcpOperationSACKP(j)){
                    QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK Permitted");
                    optionTree->addChild(subTree);
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK Permitted (4)"));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 2"));
                    j += 2;
                }
                break;
            }
            case 5:{
                u_char length = 0;
                QVector<u_int>edge;
                if(pkt_tcp->getTcpOperationSACK(j,length,edge)){
                    QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - SACK");
                    optionTree->addChild(subTree);
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: SCAK (5)"));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(length)));
                    int num = edge.size();
                    for(int k = 0;k < num;k += 2){
                        subTree->addChild(new QTreeWidgetItem(QStringList()<<"left edge = " + QString::number(edge[k])));
                        subTree->addChild(new QTreeWidgetItem(QStringList()<<"right edge = " + QString::number(edge[k + 1])));
                    }
                    j += length;
                }
                break;
            }
            case 8:{
                u_int value = 0;
                u_int reply = 0;
                if(pkt_tcp->getTcpOperationTSPOT(j,value,reply)){
                    QString val = QString::number(value);
                    QString rep = QString::number(reply);
                    QTreeWidgetItem * subTree = new QTreeWidgetItem(QStringList()<<"TCP Option - TimeStamps: TSval " +val + ", TSecr " + rep);
                    optionTree->addChild(subTree);
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Kind: Time Stamp Option (8)"));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: 10"));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp value: " + val));
                    subTree->addChild(new QTreeWidgetItem(QStringList()<<"Timestamp echo reply: " + rep));
                    j += 10;
                }
                break;
            }
            case 19:{
                j += 18;
                break;
            }
            case 28:{
                j += 4;
                break;
            }
            default:{
                j++;
                break;
            }
            }
        }
    }
    if(dataLengthofIp > 0)
        item4->addChild(new QTreeWidgetItem(QStringList()<<"TCP Payload (" + QString::number(dataLengthofIp) + ")"));
}

void MainWindow::UDP_analysis()
{
    pkt_udp = new Udp(data[current_row]);
    QString srcPort = pkt_udp->getUdpSourcePort();
    QString desPort = pkt_udp->getUdpDestinationPort();
    QString Length = pkt_udp->getUdpDataLength();
    QString checksum = "0x" + pkt_udp->getUdpCheckSum();
    QTreeWidgetItem*item5 = new QTreeWidgetItem(QStringList()<<"User Datagram Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort);
    ui->treeWidget->addTopLevelItem(item5);
    item5->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
    item5->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
    item5->addChild(new QTreeWidgetItem(QStringList()<<"length:" + Length));
    item5->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
    int udpLength = Length.toUtf8().toInt();
    if(udpLength > 0){
        item5->addChild(new QTreeWidgetItem(QStringList()<<"UDP PayLoad (" + QString::number(udpLength - 8) + " bytes)"));
    }
}

void MainWindow::DNS_analysis()
{
    pkt_dns = new Dns(data[current_row]);
    QString transaction = "0x" + pkt_dns->getDnsTransactionId();
    QString QR = pkt_dns->getDnsFlagsQR();
    QString temp = "";
    if(QR == "0") temp = "query";
    if(QR == "1") temp = "response";
    QString flags = "0x" + pkt_dns->getDnsFlags();
    QTreeWidgetItem*dnsTree = new QTreeWidgetItem(QStringList()<<"Domain Name System (" + temp + ")");
    ui->treeWidget->addTopLevelItem(dnsTree);
    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Transaction ID:" + transaction));
    QTreeWidgetItem* flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags);
    dnsTree->addChild(flagTree);
    temp = QR == "1"?"Message is a response":"Message is a query";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<QR + "... .... .... .... = Response:" + temp));
    QString Opcode = pkt_dns->getDnsFlagsOpcode();
    if(Opcode == "0") temp = "Standard query (0)";
    else if(Opcode == "1") temp = "Reverse query (1)";
    else if(Opcode == "2") temp = "Status request (2)";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".000 " + Opcode + "... .... .... = Opcode:" + temp));
    if(QR == "1"){
        QString AA = pkt_dns->getDnsFlagsAA();
        temp = AA == "1"?"Server is an authority for domain":"Server is not an authority for domain";
        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ." + AA + ".. .... .... = Authoritative:" + temp));
    }
    QString TC = pkt_dns->getDnsFlagsTC();
    temp = TC == "1"?"Message is truncated":"Message is not truncated";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + TC + ". .... .... = Truncated:" + temp));

    QString RD = pkt_dns->getDnsFlagsRD();
    temp = RD == "1"?"Do query recursively":"Do query not recursively";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + RD + " .... .... = Recursion desired:" + temp));

    if(QR == "1"){
        QString RA = pkt_dns->getDnsFlagsRA();
        temp = RA == "1"?"Server can do recursive queries":"Server can not do recursive queries";
        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + RA + "... .... = Recursion available:" + temp));
    }
    QString Z = pkt_dns->getDnsFlagsZ();
    while(Z.size()<3)
        Z = "0" + Z;
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + Z + " .... = Z:reserved(" + Z + ")"));
    if(QR == "1"){
        QString Rcode = pkt_dns->getDnsFlagsRcode();
        if(Rcode == "0")
            temp = "No error (0)";
        else if(Rcode == "1") temp = "Format error (1)";
        else if(Rcode == "2") temp = "Server failure (2)";
        else if(Rcode == "3") temp = "Name Error (3)";
        else if(Rcode == "4") temp = "Not Implemented (4)";
        else if(Rcode == "5") temp = "Refused (5)";
        int code = Rcode.toUtf8().toInt();
        QString bCode = QString::number(code,2);
        while (bCode.size()<4)
            bCode = "0" + bCode;
        flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .... " + bCode + " = Reply code:" + temp));
    }

    QString question = pkt_dns->getDnsQuestionNumber();
    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Questions:" + question));
    QString answer = pkt_dns->getDnsAnswerNumber();
    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Answer RRs:" + answer));
    QString authority = pkt_dns->getDnsAuthorityNumber();
    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Authority RRs:" + authority));
    QString additional = pkt_dns->getDnsAdditionalNumber();
    dnsTree->addChild(new QTreeWidgetItem(QStringList()<<"Additional RRs:" + additional));
    int offset = 0;
    if(question == "1"){
        QString domainInfo;
        int Type;
        int Class;
        pkt_dns->getDnsQueriesDomain(domainInfo,Type,Class);
        QTreeWidgetItem*queryDomainTree = new QTreeWidgetItem(QStringList()<<"Queries");
        dnsTree->addChild(queryDomainTree);
        offset += (4 + domainInfo.size() + 2);
        QString type = pkt_dns->getDnsDomainType(Type);
        QTreeWidgetItem*querySubTree = new QTreeWidgetItem(QStringList()<<domainInfo + " type " + type + ", class IN");
        queryDomainTree->addChild(querySubTree);
        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + domainInfo));
        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"[Name Length:" + QString::number(domainInfo.size()) + "]"));
        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type + "(" + QString::number(Type) + ")"));
        querySubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
    }
    int answerNumber = answer.toUtf8().toInt();
    if(answerNumber > 0){
        QTreeWidgetItem*answerTree = new QTreeWidgetItem(QStringList()<<"Answers");
        dnsTree->addChild(answerTree);
        for(int i = 0;i< answerNumber;i++){
            QString name1;
            QString name2;
            ushort type;
            ushort Class;
            u_int ttl;
            ushort length;

            int tempOffset = pkt_dns->getDnsAnswersDomain(offset,name1,type,Class,ttl,length,name2);
            QString sType = pkt_dns->getDnsDomainType(type);
            QString temp = "";
            if(type == 1) temp = "addr";
            else if(type == 5) temp = "cname";
            QTreeWidgetItem*answerSubTree = new QTreeWidgetItem(QStringList()<<name1 + ": type " + sType + ",class IN, " + temp + ":" + name2);
            answerTree->addChild(answerSubTree);
            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Name:" + name1));
            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + sType + "(" + QString::number(type) + ")"));
            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Class: IN (0x000" + QString::number(Class) + ")"));
            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Time to live:" + QString::number(ttl) + "(" + QString::number(ttl) + " second)"));
            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Data length:" + QString::number(length)));
            answerSubTree->addChild(new QTreeWidgetItem(QStringList()<<sType + ":" + name2));

            offset += tempOffset;
        }
    }
}


void MainWindow::ICMP_analysis()
{
    pkt_icmp = new Icmp(data[current_row]);
    QString totalLength = pkt_ip->getIpTotalLength();
    int dataLengthofIp = totalLength.toUtf8().toInt() - 20;
    dataLengthofIp -= 8;
    QTreeWidgetItem*item6 = new QTreeWidgetItem(QStringList()<<"Internet Control Message Protocol");
    ui->treeWidget->addTopLevelItem(item6);
    QString type = pkt_icmp->getIcmpType();
    QString code = pkt_icmp->getIcmpCode();
    QString info = ui->tableWidget->item(current_row,6)->text();
    QString checksum = "0x" + pkt_icmp->getIcmpCheckSum();
    QString id = pkt_icmp->getIcmpIdentification();
    QString seq = pkt_icmp->getIcmpSequeue();
    item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
    item6->addChild(new QTreeWidgetItem(QStringList()<<"code:" + code));
    item6->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
    item6->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
    item6->addChild(new QTreeWidgetItem(QStringList()<<"Identifier:" + id));
    item6->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number:" + seq));
    if(dataLengthofIp > 0){
        QTreeWidgetItem* dataItem = new QTreeWidgetItem(QStringList()<<"Data (" + QString::number(dataLengthofIp) + ") bytes");
        item6->addChild(dataItem);
        QString icmpData = pkt_icmp->getIcmpData(dataLengthofIp);
        dataItem->addChild(new QTreeWidgetItem(QStringList()<<icmpData));
    }
}

void MainWindow::TLS_analysis()
{
    pkt_tls = new Tls(data[current_row]);
    pkt_tcp = new Tcp(data[current_row]);
    int rawLength = pkt_tcp->getTcpRawHeaderLength().toUtf8().toInt();
    QTreeWidgetItem* tlsTree = new QTreeWidgetItem(QStringList()<<"Transport Layer Security");
    ui->treeWidget->addTopLevelItem(tlsTree);
    u_char contentType = 0;
    ushort version = 0;
    ushort length = 0;
    pkt_tls->getTlsBasicInfo((rawLength * 4),contentType,version,length);
    QString type = pkt_tls->getTlsContentType(contentType);
    QString vs = pkt_tls->getTlsVersion(version);
    switch (contentType) {
    case 20:{
        // ... TODO
        break;
    }
    case 21:{
        QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: Encrypted Alert");
        tlsTree->addChild(tlsSubree);
        tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
        tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
        tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
        tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Alert Message: Encrypted Alert"));
        break;
    }
    case 22:{ // handshake
        u_char handshakeType = 0;
        pkt_tls->getTlsHandshakeType((rawLength * 4 + 5),handshakeType);
        if(handshakeType == 1){ // client hello
            int tlsLength = 0;
            ushort rawVersion = 0;
            QString random = "";
            u_char sessionLength = 0;
            QString sessionId = "";
            ushort cipherLength = 0;
            QVector<ushort>cipher;
            u_char cmLength = 0;
            QVector<u_char>compressionMethod;
            ushort extensionLength = 0;
            pkt_tls->getTlsClientHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipherLength,cipher,cmLength,compressionMethod,extensionLength);

            QString type = pkt_tls->getTlsHandshakeType(handshakeType);
            QString tlsVersion = pkt_tls->getTlsVersion(rawVersion);

            QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
            tlsTree->addChild(tlsSubTree);
            tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
            tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
            tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

            QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
            tlsSubTree->addChild(handshakeTree);
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion) + ")"));
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
            if(sessionLength > 0){
                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
            }
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites Length: " + QString::number(cipherLength)));
            if(cipherLength > 0){
                QTreeWidgetItem* cipherTree = new QTreeWidgetItem(QStringList()<<"Cipher Suites (" + QString::number(cipherLength/2) + " suites)");
                handshakeTree->addChild(cipherTree);
                for(int k = 0;k < cipherLength/2;k++){
                    QString temp = pkt_tls->getTlsHandshakeCipherSuites(cipher[k]);
                    cipherTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suite: " + temp));
                }
            }
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Method Length: " + QString::number(cmLength)));
            if(cmLength > 0){
                QTreeWidgetItem* cmTree = new QTreeWidgetItem(QStringList()<<"Compression Methods (" + QString::number(cmLength) + " method)");
                handshakeTree->addChild(cmTree);
                for(int k = 0;k < cmLength;k++){
                    QString temp = pkt_tls->getTlsHandshakeCompression(compressionMethod[k]);
                    cmTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod[k]) + ")"));
                }
            }
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
            if(extensionLength > 0){
                int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                for(int k = 0;k < extensionLength;){
                    int code = pkt_tls->getTlsExtensionType(exOffset);
                    ushort exType = 0;
                    ushort exLength = 0;
                    switch (code) {
                    case 0:{ // server_name
                        ushort listLength = 0;
                        u_char nameType = 0;
                        ushort nameLength = 0;
                        QString name = "";
                        pkt_tls->getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        if(exLength > 0 && listLength > 0){
                            QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                            extensionTree->addChild(serverTree);
                            serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                            serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                            serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                            serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                        }
                        break;
                    }
                    case 11:{// ec_point_format
                        u_char ecLength = 0;
                        QVector<u_char>EC;
                        pkt_tls->getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                        QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                        extensionTree->addChild(EXTree);
                        for(int g = 0;g < ecLength;g++){
                            QString temp = pkt_tls->getTlsHandshakeExtensionECPointFormat(EC[g]);
                            EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                        }
                        break;
                    }
                    case 10:{// supported_groups
                        ushort groupListLength = 0;
                        QVector<ushort>group;
                        pkt_tls->getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                        QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                        extensionTree->addChild(sptTree);
                        for(int g = 0;g < groupListLength/2;g++){
                            QString temp = pkt_tls->getTlsHandshakeExtensionSupportGroup(group[g]);
                            sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                        }
                        break;
                    }
                    case 35:{// session_ticket
                        pkt_tls->getTlsExtensionSessionTicket(exOffset,exType,exLength);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        break;
                    }
                    case 22:{// encrypt_then_mac
                        pkt_tls->getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        break;
                    }
                    case 23:{// extended_master_secret
                        pkt_tls->getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        break;
                    }
                    case 13:{// signature_algorithms
                        ushort algorithmLength = 0;
                        QVector<ushort>algorithm;
                        pkt_tls->getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                        QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                        extensionTree->addChild(sigTree);
                        for(int g = 0;g < algorithmLength/2;g++){
                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                            sigTree->addChild(subTree);
                            QString hash = pkt_tls->getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                            QString sig = pkt_tls->getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                        }
                        break;
                    }
                    case 43:{// supported_versions
                        u_char supportLength = 0;
                        QVector<ushort>supportVersion;
                        pkt_tls->getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                        for(int g = 0;g < supportLength/2;g++){
                            QString temp = pkt_tls->getTlsVersion(supportVersion[g]);
                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                        }
                        break;
                    }
                    case 51:{// key_share
                        ushort shareLength = 0;
                        ushort group = 0;
                        ushort exchangeLength = 0;
                        QString exchange = "";
                        pkt_tls->getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                        QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                        extensionTree->addChild(subTree);
                        subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                        QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                        subTree->addChild(entryTree);
                        entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                        entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                        entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                        break;
                    }
                    case 21:{// padding
                        QString rdata = "";
                        pkt_tls->getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                        break;
                    }
                    default:{
                        QString rdata = "";
                        pkt_tls->getTlsExtensionOther(exOffset,exType,exLength,rdata);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                        break;
                    }
                    }
                    k += (exLength + 4);
                    exOffset += (exLength + 4);
                }
            }
        }
        else if(handshakeType == 2){// Server hello
            int tlsLength = 0;
            ushort rawVersion = 0;
            QString random = "";
            u_char sessionLength = 0;
            QString sessionId = "";
            ushort cipher = 0;
            u_char compressionMethod = 0;
            ushort extensionLength = 0;
            pkt_tls->getTlsServerHelloInfo((rawLength * 4 + 5),handshakeType,tlsLength,rawVersion,random,sessionLength,sessionId,cipher,compressionMethod,extensionLength);
            QString type = pkt_tls->getTlsHandshakeType(handshakeType);
            QString tlsVersion = pkt_tls->getTlsVersion(rawVersion);

            QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
            tlsTree->addChild(tlsSubTree);
            tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
            tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
            tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

            QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
            tlsSubTree->addChild(handshakeTree);
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + tlsVersion + " (0x0" + QString::number(rawVersion,16) + ")"));
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Random: " + random));
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID Length: " + QString::number(sessionLength)));
            if(sessionLength > 0){
                handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Session ID: " + sessionId));
            }
            QString temp = pkt_tls->getTlsHandshakeCipherSuites(cipher);
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Cipher Suites: " +temp));
            temp = pkt_tls->getTlsHandshakeCompression(compressionMethod);
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Compression Methods: " + temp + " (" + QString::number(compressionMethod) + ")"));
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Extensions Length: " + QString::number(extensionLength)));
            if(extensionLength > 0){
                int exOffset = (rawLength * 4) + (tlsLength - extensionLength + 5 + 4);
                for(int k = 0;k < extensionLength;){
                    int code = pkt_tls->getTlsExtensionType(exOffset);
                    ushort exType = 0;
                    ushort exLength = 0;
                    switch (code) {
                    case 0:{ // server_name
                        ushort listLength = 0;
                        u_char nameType = 0;
                        ushort nameLength = 0;
                        QString name = "";
                        pkt_tls->getTlsExtensionServerName(exOffset,exType,exLength,listLength,nameType,nameLength,name);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        if(exLength > 0 && listLength > 0){
                            QTreeWidgetItem*serverTree = new QTreeWidgetItem(QStringList()<<"Server Name Indication extension");
                            extensionTree->addChild(serverTree);
                            serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name list length: " + QString::number(listLength)));
                            serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name Type: " + QString::number(nameType)));
                            serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name length: " + QString::number(nameLength)));
                            serverTree->addChild(new QTreeWidgetItem(QStringList()<<"Server Name: " + name));
                        }
                        break;
                    }
                    case 11:{// ec_point_format
                        u_char ecLength = 0;
                        QVector<u_char>EC;
                        pkt_tls->getTlsExtensionEcPointFormats(exOffset,exType,exLength,ecLength,EC);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"EC point formats Length: " + QString::number(ecLength)));
                        QTreeWidgetItem* EXTree = new QTreeWidgetItem(QStringList()<<"Elliptic curves point formats (" + QString::number(ecLength) + ")");
                        extensionTree->addChild(EXTree);
                        for(int g = 0;g < ecLength;g++){
                            QString temp = pkt_tls->getTlsHandshakeExtensionECPointFormat(EC[g]);
                            EXTree->addChild(new QTreeWidgetItem(QStringList()<<temp));
                        }
                        break;
                    }
                    case 10:{// supported_groups
                        ushort groupListLength = 0;
                        QVector<ushort>group;
                        pkt_tls->getTlsExtensionSupportGroups(exOffset,exType,exLength,groupListLength,group);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Groups List Length: " + QString::number(groupListLength)));
                        QTreeWidgetItem* sptTree = new QTreeWidgetItem(QStringList()<<"Supported Groups (" + QString::number(groupListLength/2) + " groups)");
                        extensionTree->addChild(sptTree);
                        for(int g = 0;g < groupListLength/2;g++){
                            QString temp = pkt_tls->getTlsHandshakeExtensionSupportGroup(group[g]);
                            sptTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Group: " + temp));
                        }
                        break;
                    }
                    case 35:{// session_ticket
                        pkt_tls->getTlsExtensionSessionTicket(exOffset,exType,exLength);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        break;
                    }
                    case 22:{// encrypt_then_mac
                        pkt_tls->getTlsExtensionEncryptThenMac(exOffset,exType,exLength);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        break;
                    }
                    case 23:{// extended_master_secret
                        pkt_tls->getTlsExtensionExtendMasterSecret(exOffset,exType,exLength);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        break;
                    }
                    case 13:{// signature_algorithms
                        ushort algorithmLength = 0;
                        QVector<ushort>algorithm;
                        pkt_tls->getTlsExtensionSignatureAlgorithms(exOffset,exType,exLength,algorithmLength,algorithm);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms Length: " + QString::number(algorithmLength)));
                        QTreeWidgetItem* sigTree = new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithms (" + QString::number(algorithmLength/2) + " algorithms)");
                        extensionTree->addChild(sigTree);
                        for(int g = 0;g < algorithmLength/2;g++){
                            QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Signature Algorithm: 0x0" + QString::number(algorithm[g],16));
                            sigTree->addChild(subTree);
                            QString hash = pkt_tls->getTlsHadshakeExtensionHash((algorithm[g] & 0xff00) >> 8);
                            QString sig = pkt_tls->getTlsHadshakeExtensionSignature((algorithm[g] & 0x00ff));
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Hash: " + hash + " (" + QString::number((algorithm[g] & 0xff00) >> 8) + ")"));
                            subTree->addChild(new QTreeWidgetItem(QStringList()<<"Signature Hash Algorithm Signature: " + sig + " (" + QString::number(algorithm[g] & 0x00ff) + ")"));
                        }
                        break;
                    }
                    case 43:{// supported_versions
                        u_char supportLength = 0;
                        QVector<ushort>supportVersion;
                        pkt_tls->getTlsExtensionSupportVersions(exOffset,exType,exLength,supportLength,supportVersion);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Versions length: " + QString::number(supportLength)));
                        for(int g = 0;g < supportLength/2;g++){
                            QString temp = pkt_tls->getTlsVersion(supportVersion[g]);
                            extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Supported Version: " + temp));
                        }
                        break;
                    }
                    case 51:{// key_share
                        ushort shareLength = 0;
                        ushort group = 0;
                        ushort exchangeLength = 0;
                        QString exchange = "";
                        pkt_tls->getTlsExtensionKeyShare(exOffset,exType,exLength,shareLength,group,exchangeLength,exchange);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));

                        QTreeWidgetItem*subTree = new QTreeWidgetItem(QStringList()<<"Key Share extension");
                        extensionTree->addChild(subTree);
                        subTree->addChild(new QTreeWidgetItem(QStringList()<<"Client Key Share Length: " + QString::number(shareLength)));
                        QTreeWidgetItem* entryTree = new QTreeWidgetItem(QStringList()<<"Key Share Entry: Group ");
                        subTree->addChild(entryTree);
                        entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Group: " + QString::number(group)));
                        entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange Length: " + QString::number(exchangeLength)));
                        entryTree->addChild(new QTreeWidgetItem(QStringList()<<"Key Exchange: " + exchange));
                        break;
                    }
                    case 21:{// padding
                        QString rdata = "";
                        pkt_tls->getTlsExtensionPadding(exOffset,exType,exLength,rdata);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (21)"));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Padding Data: " + rdata));
                        break;
                    }
                    default:{
                        QString rdata = "";
                        pkt_tls->getTlsExtensionOther(exOffset,exType,exLength,rdata);
                        QString subType = pkt_tls->getTlsHandshakeExtension(exType);
                        QTreeWidgetItem*extensionTree = new QTreeWidgetItem(QStringList()<<"Extension: " + subType + " (len=" + QString::number(exLength) + ")");
                        handshakeTree->addChild(extensionTree);
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Type: " + subType + " (" + QString::number(exType) + ")"));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(exLength)));
                        extensionTree->addChild(new QTreeWidgetItem(QStringList()<<"Data: " + rdata));

                        break;
                    }
                    }
                    k += (exLength + 4);
                    exOffset += (exLength + 4);
                }
            }

        }
        else if(handshakeType == 12){// Server Key Exchange
            int tlsLength = 0;
            u_char curveType = 0;
            ushort curveName = 0;
            u_char pubLength = 0;
            QString pubKey = "";
            ushort sigAlgorithm = 0;
            ushort sigLength = 0;
            QString sig = "";
            pkt_tls->getTlsServerKeyExchange((rawLength * 4 + 5),handshakeType,tlsLength,curveType,curveName,pubLength,pubKey,sigAlgorithm,sigLength,sig);
            QString type = pkt_tls->getTlsHandshakeType(handshakeType);

            QTreeWidgetItem* tlsSubTree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: " + type);
            tlsTree->addChild(tlsSubTree);
            tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
            tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
            tlsSubTree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));

            QTreeWidgetItem* handshakeTree = new QTreeWidgetItem(QStringList()<<"Handshake Protocol: " + type);
            tlsSubTree->addChild(handshakeTree);
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Handshake Type: " + type + "(" + QString::number(handshakeType) + ")"));
            handshakeTree->addChild(new QTreeWidgetItem(QStringList()<<"Length: " + QString::number(tlsLength)));

        }
        // ... TODO
        break;
    }
    case 23:{
        QTreeWidgetItem* tlsSubree = new QTreeWidgetItem(QStringList()<<vs + " Record Layer: " + type + " Protocol: http-over-tls");
        tlsTree->addChild(tlsSubree);
        tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Content Type: " + type + " (" + QString::number(contentType) + ")"));
        tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Version: " + vs + " (0x0" + QString::number(version,16) + ")"));
        tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Length " + QString::number(length)));
        tlsSubree->addChild(new QTreeWidgetItem(QStringList()<<"Encrypted Application Data: ..."));
        break;
    }
    default:break;
    }
}

void MainWindow::SSL_analysis()
{
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<"Secure Socket Layer");
    ui->treeWidget->addTopLevelItem(item);
    item->addChild(new QTreeWidgetItem(QStringList()<<" "));
}



