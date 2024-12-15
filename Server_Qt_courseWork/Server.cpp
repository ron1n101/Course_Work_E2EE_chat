#include "Server.h"
#include <QDataStream>
#include <QDebug>
#include "ServerWorker.h"

Server::Server(QObject *parent) : QTcpServer(parent) {}

void Server::incomingConnection(qintptr socketDescriptor)
{
    auto *clientSocket = new QTcpSocket(this);
    if (!clientSocket->setSocketDescriptor(socketDescriptor))
    {
        qDebug() << "Failed to set socket descriptor";
        clientSocket->deleteLater();
        return;
    }


    auto clientID = clientSocket->peerAddress().toString();
    {
        QMutexLocker locker(&clientsMutex);
        clients[clientSocket] = clientID; // Сохраняем сокет и его IP
    }

    auto *worker = new ServerWorker(clientSocket, this);
    connect(worker, &ServerWorker::clientDisconnect, this, &Server::handleDisconnection);
    connect(worker, &ServerWorker::messageReceived, this, &Server::broadcastMessage);

    sendKeysToClients(clientSocket);

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

    QString clientID = client->peerAddress().toString();
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

void Server::broadcastKeysIsReady()
{
    QMap<QTcpSocket*, QString> clientsCopy;
    QMap<QString, QByteArray> publicKeysCopy;

    {
        QMutexLocker locker(&clientsMutex);
        if (clients.size() != publicKeys.size())
        {
            qDebug() << "Not all clients have sent their public keys yet.";
            return;
        }

        clientsCopy = clients;
        publicKeysCopy = publicKeys;
    }

    qDebug() << "All clients have sent their keys. Broadcasting now...";

    for (QTcpSocket *client : clientsCopy.keys())
    {
        sendKeysToClients(client); // No mutex locking here
    }
}

QString Server::getClientID(QTcpSocket *client)
{
    QMutexLocker locker(&clientsMutex);
    return clients.value(client, QString());
}

void Server::sendKeysToClients(QTcpSocket *client)
{
    QMutexLocker locker(&clientsMutex);
    QString requestingClientID = clients.value(client);
    if(requestingClientID.isEmpty())
    {
        qDebug() << "Could not find ID for the requesting client.";
        return;
    }
    QByteArray message;
    QDataStream out (&message, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);
    quint32 messageLength = 0;
    quint8 messageType = static_cast<quint8>(MessageType::PUBLIC_KEY);
    out << messageLength << messageType;

    for (auto it = publicKeys.constBegin(); it != publicKeys.constEnd(); ++it)
    {
        if (it.key() != requestingClientID) // Exclude the requesting client's own key
        {
            QByteArray clientID = it.key().toUtf8();
            QByteArray publicKey = it.value();

            out << static_cast<quint32>(clientID.size());
            out.writeRawData(clientID.data(), clientID.size());

            out << static_cast<quint32>(publicKey.size());
            out.writeRawData(publicKey.data(), publicKey.size());
        }
    }
    messageLength = message.size() - sizeof(quint32);
    memcpy(message.data(), &messageLength, sizeof(quint32));

    client->write(message);
    client->flush();

    qDebug() << "Sent public Key to client: " << requestingClientID;
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

void Server::addPublicKey(const QString &clientID, const QByteArray &key)
{

    {
        QMutexLocker locker(&clientsMutex);
        publicKeys[clientID] = key;

        qDebug() << "Public Key added for client:" << clientID;
    }

    broadcastKeysIsReady(); // Call without the lock
}




QByteArray Server::getPublicKey(const QString &clientID) const
{
    QMutexLocker locker(&clientsMutex);
    return publicKeys.value(clientID, QByteArray());
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


