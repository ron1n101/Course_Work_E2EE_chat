#include "Server.h"

#include <QCoreApplication>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    Server server;
    if(!server.listen(QHostAddress::LocalHost, 8001))
    {
        qCritical() << "Failed to start server: " << server.errorString();
        return -1;
    }

    qDebug() << "Server started on port 8001";
    return a.exec();
}
