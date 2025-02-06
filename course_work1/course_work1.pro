QT       += core gui network

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    ClientLogin.cpp \
    ClientWorker.cpp \
    ClientWorkerWrapper.cpp \
    main.cpp \
    ClientChat.cpp

HEADERS += \
    ClientChat.h \
    ClientLogin.h \
    ClientWorker.h \
    ClientWorkerWrapper.h \
    MessageType.h

FORMS += \
    ClientChat.ui \
    ClientLogin.ui



unix:!macx|win32: LIBS += -LC:/cryptopp/cryptopp/ -lcryptopp

INCLUDEPATH += C:/cryptopp
DEPENDPATH += C:/cryptopp
