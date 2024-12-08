#include "ClientChat.h"
#include "ClientLogin.h"
// #include "ClientWorker.h"
#include "ClientWorkerWrapper.h"

#include "QTcpServer"
#include <QApplication>
#include <QThreadPool>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    ClientLogin loginWindow;
    QObject::connect(&loginWindow, &ClientLogin::usernameEntered, [&](const QString &username)
    {
        // int socketDescriptor = ...;
        QTcpSocket tempSocket;
        tempSocket.connectToHost("127.0.0.1", 8001);
        if(!tempSocket.waitForConnected(5000))
        {
            qWarning() << "Failed connect to server: " << tempSocket.errorString();
            return;
        }

        int socketDescriptor = tempSocket.socketDescriptor();
        ClientWorkerWrapper *workerWrapper = new ClientWorkerWrapper(socketDescriptor, username);
        workerWrapper->setParent(&loginWindow);
        // workerWrapper->start();

        ClientChat *chatWindow = new ClientChat();
        chatWindow->setAttribute(Qt::WA_DeleteOnClose);
        QObject::connect(workerWrapper, &ClientWorkerWrapper::messageReceived, chatWindow, &ClientChat::displayMessage);
        QObject::connect(workerWrapper, &ClientWorkerWrapper::errorOccurred, chatWindow, &ClientChat::displayError);
        QObject::connect(chatWindow, &ClientChat::sendMessage, workerWrapper, &ClientWorkerWrapper::sendMessage);

        chatWindow->setUsername(username);
        chatWindow->show();
        // worker->start();
    });
    loginWindow.show();
    return app.exec();
}
