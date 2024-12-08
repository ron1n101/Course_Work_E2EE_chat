#include "Server.h"
#include <QDataStream>
#include <QDebug>
#include "ServerWorker.h"

// Реализовать sendChatMsg
// MessageType messageType;

Server::Server(QObject *parent) : QTcpServer(parent) {}

void Server::incomingConnection(qintptr socketDescriptor)
{
    auto *clientSocket = new QTcpSocket(this);
    if(!clientSocket->setSocketDescriptor(socketDescriptor))
    {
        qDebug() << "Failed to set socket descriptor";
        clientSocket->deleteLater();
        return;
    }

    auto *worker = new ServerWorker(clientSocket, this);
    connect(worker, &ServerWorker::clientDisconnect, this, &Server::handleDisconnection);
    connect(worker, &ServerWorker::messageReceived, this, &Server::broadcastMessage);




    // connect(worker, &ServerWorker::messageReceived, this, &Server::broadcastMessage);




    QString clientIP = clientSocket->peerAddress().toString();
    clientsMutex.lock();
    clientsDetails[clientIP] = "";
    clientsMutex.unlock();

    qDebug()<< "Client connected:" << clientIP;

}

void Server::handleDisconnection()
{
    auto *client = qobject_cast<QTcpSocket*>(sender());
    if(!client) return;

    QString clientIP = client->peerAddress().toString();
    qDebug() << "Client disconnected: " << clientIP;

    clientsMutex.lock();
    clientsDetails.remove(clientIP);
    clientsMutex.unlock();

    client->deleteLater();
}

void Server::handleStatusConnection()
{
    auto *client = qobject_cast<QTcpSocket*>(sender());
    if(!client) return;

    QByteArray data = client->readAll();
    qDebug() << "Received data from client: " << QString::fromUtf8(data);
}
// void Server::handleReadyRead()
// {
//     auto *client = qobject_cast<QTcpSocket*>(sender());
//     if (!client) return;

//     QByteArray data = client->readAll(); // Read data from the client
//     qDebug() << "Received data from client:" << data;

//     // Process or forward data as needed
// }



void Server::broadcastMessage(QTcpSocket *sender, const QByteArray &message)
{
    clientsMutex.lock();
    for(QString& clientIP : clientsDetails.keys())
    {
        if(sender->peerAddress().toString() == clientIP)
        {
            QTcpSocket *client = sender;
            client->write(message);
        }
    }
    clientsMutex.unlock();
}



QString Server::getClientID(QTcpSocket *client)
{
    return client->peerAddress().toString();
}

void Server::removeClient(QTcpSocket* client)
{
    QMutexLocker locker(&clientsMutex);
    if (clients.contains(client))
    {
        clients.remove(client); // Remove the client from the map
        qDebug() << "Client removed successfully.";
    }
    client->deleteLater();
}
