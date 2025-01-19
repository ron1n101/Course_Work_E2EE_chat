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
        ClientWorkerWrapper *workerWrapper = new ClientWorkerWrapper(username);
        // workerWrapper->setParent(&loginWindow);
        // workerWrapper->start();
        workerWrapper->initializeClientData(username);

        ClientChat *chatWindow = new ClientChat();
        chatWindow->setAttribute(Qt::WA_DeleteOnClose);
        chatWindow->setUsername(username);
        QObject::connect(workerWrapper, &ClientWorkerWrapper::messageReceived, chatWindow, &ClientChat::displayMessage);
        QObject::connect(workerWrapper, &ClientWorkerWrapper::errorOccurred, chatWindow, &ClientChat::displayError);
        QObject::connect(chatWindow, &ClientChat::sendMessage, workerWrapper, &ClientWorkerWrapper::sendMessage);


        chatWindow->show();
        // worker->start();
    });
    loginWindow.show();
    return app.exec();
}
