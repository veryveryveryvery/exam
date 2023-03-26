QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    arp.cpp \
    capture.cpp \
    datapackage.cpp \
    dns.cpp \
    hostinfo.cpp \
    hostscanner.cpp \
    icmp.cpp \
    ip.cpp \
    main.cpp \
    mainwindow.cpp \
    scan.cpp \
    tcp.cpp \
    udp.cpp

HEADERS += \
    Format.h \
    arp.h \
    capture.h \
    datapackage.h \
    dns.h \
    hostinfo.h \
    hostscanner.h \
    icmp.h \
    ip.h \
    mainwindow.h \
    scan.h \
    tcp.h \
    udp.h

FORMS += \
    mainwindow.ui \
    scan.ui

LIBS += -lpcap

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    src.qrc
