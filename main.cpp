#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("Shark - @copyright by hxs 2023");
    w.show();
    return a.exec();
}
