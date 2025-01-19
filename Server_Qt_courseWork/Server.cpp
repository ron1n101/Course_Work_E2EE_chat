#include "Server.h"
#include <QDataStream>
#include <QDebug>
#include "ServerWorker.h"

Server::Server(QObject *parent) : QTcpServer(parent)
{
    this->setMaxPendingConnections(30);
    qDebug() << "Server constructor called. maxPendingConnections = 30";
}

void Server::incomingConnection(qintptr socketDescriptor)
{
    qDebug() << "incomingConnection called with descriptor:" << socketDescriptor;
    auto *clientSocket = new QTcpSocket(this);
    if (!clientSocket->setSocketDescriptor(socketDescriptor))
    {
        qDebug() << "Failed to set socket descriptor";
        clientSocket->deleteLater();
        return;
    }
    qDebug() << "Successfully set socket descriptor. localPort = " << clientSocket->localPort() << "peerPort = " << clientSocket->peerPort();


    auto clientID = clientSocket->peerAddress().toString() + ":" + QString::number(clientSocket->peerPort());
    {
        QMutexLocker locker(&clientsMutex);
        clients[clientSocket] = clientID; // Сохраняем сокет и его IP
    }

    auto *worker = new ServerWorker(clientSocket, this);
    connect(worker, &ServerWorker::clientDisconnect, this, &Server::handleDisconnection);
    connect(worker, &ServerWorker::messageReceived, this, &Server::broadcastMessage);

    qDebug() << "Client connected:" << clientID;
}

void Server::handleStatusConnection()
{
    auto *client = qobject_cast<QTcpSocket*>(sender());
    if(!client) return;

    QByteArray data = client->readAll();
    qDebug() << "Received data from client: " << QString::fromUtf8(data);
}

void Server::handleDisconnection()
{
    auto *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;

    QString clientID = client->peerAddress().toString() + ":" + QString::number(client->peerPort());;
    qDebug() << "Client disconnected: " << clientID;

    QMutexLocker locker(&clientsMutex);
    clients.remove(client);

    client->deleteLater();
}

void Server::broadcastMessage(QTcpSocket *sender, const QByteArray &message)
{
    QMutexLocker locker(&clientsMutex);
    for (QTcpSocket* client : clients.keys())
    {
        if (client != sender) // Исключаем отправителя
        {
            client->write(message);
            client->flush();
        }
    }
}



QString Server::getClientID(QTcpSocket *client)
{
    QMutexLocker locker(&clientsMutex);
    return clients.value(client, QString());
}



void Server::removeClient(QTcpSocket* client)
{
    QMutexLocker locker(&clientsMutex);
    if (clients.contains(client))
    {
        clients.remove(client); // Remove the client from the map
        qDebug() << "Client removSocketed successfully.";
    }
    client->deleteLater();
}

void Server::addPublicKey(const QString &clientID, const QByteArray &key)
{
    QMutexLocker locker(&clientsMutex);
    publicKeys[clientID] = key;
    qDebug() << "Public Key added for client:" << clientID;
}


QByteArray Server::getPublicKey(const QString &clientID) const
{
    QMutexLocker locker(&clientsMutex);
    return publicKeys.value(clientID, QByteArray());
}

QMap<QString, QByteArray> Server::getAllPublicKeys() const          // утечка памяти!!!
{
    QMutexLocker locker(&clientsMutex);
    return publicKeys;
}

QList<QTcpSocket *> Server::getClients()
{
    // QMutexLocker locker(&clientsMutex);
    return clients.keys();
}

void Server::lockClientMutex()
{
    clientsMutex.lock();
}

void Server::unlockClientMutex()
{
    clientsMutex.unlock();
}


