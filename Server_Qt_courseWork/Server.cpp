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
        qDebug() << "[Server] Clients count:" << clients.size();
    }

    auto *worker = new ServerWorker(clientSocket, this);
    connect(worker, &ServerWorker::clientDisconnect, this, &Server::handleDisconnection);
    connect(worker, &ServerWorker::messageReceived, this, &Server::broadcastMessage);

    qDebug() << "Client connected:" << clientID;
}

void Server::handleDisconnection(QTcpSocket *client)
{

    // if(!client)
    // {
    //     return;
    // }
    // QString userID = getUserIDForSocket(client);
    // if(!userID.isEmpty())
    // {

    //     QMutexLocker locker(&clientsMutex);
    //     clients.remove(client);
    //     publicKeys.remove(userID);
    //     client->deleteLater();

    //     qDebug() << "[Server]Client disconnected: " << userID;
    // }

    QByteArray packet;
    QDataStream out (&packet, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);


    quint8 messageType = static_cast<quint8>(MessageType::USER_DISCONNECT);
    QString userID = getUserIDForSocket(client);
    QByteArray userIDBytes = userID.toUtf8();
    quint32 userIDSize = userIDBytes.size();

    quint32 messageLength = sizeof(quint8) + sizeof(quint32) + userIDSize;
    out << messageLength;
    out << messageType;
    out << userIDSize;

    out.writeRawData(userIDBytes.constData(), userIDSize);

    // broadcast all
    {
        QMutexLocker locker(&clientsMutex);
        for(QTcpSocket* c1 : clients.keys())
        {
            if(c1 != client )
            {
                c1->write(packet);
                c1->flush();
            }
        }
        qDebug() << "Broadcast USER_DISCONNECT for user:" << userID;

        clients.remove(client);
        publicKeys.remove(userID);
        client->deleteLater();
    }


    qDebug() << "[Server]Client disconnected: " << userID;

}

void Server::handleStatusConnection()
{
    auto *client = qobject_cast<QTcpSocket*>(sender());
    if(!client) return;

    QByteArray data = client->readAll();
    qDebug() << "Received data from client: " << QString::fromUtf8(data);
}


void Server::broadcastMessage(QTcpSocket *sender, const QByteArray &payload)
{
    QMutexLocker locker(&clientsMutex);
    quint8 messageType = static_cast<quint8>(MessageType::DATA_MESSAGE);
    quint32 messageLength = payload.size() + sizeof(quint8);

    QByteArray packet;
    QDataStream out (&packet, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);

    out << messageLength;
    out << messageType;

    packet.append(payload);

    for (QTcpSocket* client : clients.keys())
    {
        if (client != sender) // Исключаем отправителя
        {
            client->write(packet);
            client->flush();
        }
    }
    qDebug() << "Broadcasting message size:" << packet.size();
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
        qDebug() << "Client remove.";
    }
    client->deleteLater();
}

void Server::addPublicKey(const QString &userID, const QByteArray &key)
{
    QMutexLocker locker(&clientsMutex);
    publicKeys[userID] = key;
    qDebug() << "Public Key added for client:" << userID;
}


QByteArray Server::getPublicKey(const QString &userID) const
{
    QMutexLocker locker(&clientsMutex);
    return publicKeys.value(userID, QByteArray());
}

QMap<QString, QByteArray> Server::getAllPublicKeys() const
{
    QMutexLocker locker(&clientsMutex);
    return publicKeys;
}

QList<QTcpSocket *> Server::getClients()
{
    QMutexLocker locker(&clientsMutex);
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

void Server::setUserIDForSocket(QTcpSocket *socket, const QString &userID)
{
    QMutexLocker locker(&clientsMutex);
    clients[socket] = userID;
    qDebug() << "Assigned userID: " << userID << " to socket: " << socket;
}

QString Server::getUserIDForSocket(QTcpSocket *socket) const
{
    QMutexLocker locker(&clientsMutex);
    return clients.value(socket, QString());
}


