#include "ServerWorker.h"
#include "MessageType.h"
#include <QDataStream>
#include <QDebug>
#include "Server.h"


ServerWorker::ServerWorker(QTcpSocket *clientSocket, Server *parent): QObject(parent), clientSocket(clientSocket), server(*parent)
{
    connect(clientSocket, &QTcpSocket::readyRead, this, &ServerWorker::processClient);
    connect(clientSocket, &QTcpSocket::disconnected, this, &ServerWorker::handleClientDisconnected);

}




void ServerWorker::processClient()
{
    m_buffer.append(clientSocket->readAll());

    QDataStream in(&m_buffer, QIODevice::ReadOnly);
    in.setByteOrder(QDataStream::LittleEndian);

    while(true)
    {
        if(m_buffer.size() < static_cast<int>(sizeof(quint32) + sizeof(quint8)))
        {
            return;
        }
        quint32 messageLength;
        quint8 messageType;

        // Read length and type
        in >> messageLength >> messageType;

        if (m_buffer.size() < messageLength + sizeof(quint32))
        {
            return;
        }

        // QByteArray payload = clientSocket->read(messageLength - sizeof(quint8));
        QByteArray payload = m_buffer.mid(sizeof(quint32) + sizeof(quint8), messageLength - sizeof(quint8));
        m_buffer.remove(0, messageLength + sizeof(quint32));

        qDebug() << "Received message type:" << messageType
                 << "\nMessage length:" << messageLength
                 << "\nPayload size:" << payload.size() << "\n";

        switch (static_cast<MessageType>(messageType))
        {
        case MessageType::USERNAME_INIT:
            handleUsernameInit();
            break;


        case MessageType::CHAT_MSG:
            handleChatMessage(payload);
            break;

        case MessageType::PUBLIC_KEY:
            handlePublicKey(payload);
            break;

        case MessageType::DATA_MESSAGE:
            handleDataMessage(clientSocket, payload);
            break;

        default:
            qDebug() << "Unknown message type:" << messageType;
            break;
        }
    }
}


void ServerWorker::handleClientDisconnected()
{
    if (!clientSocket) {
        qDebug() << "No client socket available to disconnect.";
        return;
    }

    qDebug() << "Client disconnected:" << clientSocket->peerAddress().toString() + ":" + QString::number(clientSocket->peerPort());
    emit clientDisconnect(this);

    clientSocket->deleteLater();
    deleteLater();
}


void ServerWorker::handleUsernameInit()
{
    QString newUserID = server.generateUserID();
    QByteArray packet;
    QDataStream out(&packet, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);


    quint32 messageLength = 0;
    quint8 messageType = static_cast<quint8>(MessageType::USERID_ASIGNED);
    out << messageLength;
    out << messageType;

    QByteArray userIDBytes = newUserID.toUtf8();
    quint32 userIDSize = userIDBytes.size();

    out << userIDSize;
    out.writeRawData(userIDBytes.constData(), userIDSize);

    messageLength = packet.size() - sizeof(quint32);
    memcpy(packet.data(), &messageLength, sizeof(quint32));
    clientSocket->write(packet);
    clientSocket->flush();


    qDebug() << "Generate userID: " << newUserID ;
    server.setUserIDForSocket(clientSocket, newUserID);

    // sendAcknowledgment(static_cast<quint8>(MessageType::USERID_ASIGNED));
    // qDebug() << "\nReceived USERNAME_INIT from client:" << clientSocket->peerAddress().toString() + ":" + QString::number(clientSocket->peerPort());

    // // Отправляем подтверждение клиенту, что сервер готов для получения имени пользователя
    // sendAcknowledgment(static_cast<quint8>(MessageType::USERNAME_READY));
}



void ServerWorker::handlePublicKey(const QByteArray &payload)
{
    QByteArray decodedKey = QByteArray::fromBase64(payload);
    if(decodedKey.isEmpty())
    {
        qDebug() << "Failed to decode public key from client.";
        return;
    }
    qDebug() << "Received public key size:" << decodedKey.size();

    // QString clientID = clientSocket->peerAddress().toString() + ":" + QString::number(clientSocket->peerPort());

    QString userID = server.getUserIDForSocket(clientSocket);
    if(userID.isEmpty())
    {
        qDebug() << "No userID found for this socket. Possibly no USERNAME_INIT signal";
        return;
    }

    QByteArray existingKey = server.getPublicKey(userID);

    bool isNewClient = existingKey.isEmpty();                               // ключа вовсе нет
    bool isSameKey = (!isNewClient &&  existingKey == decodedKey);          // если ключ совпадает
    bool isChangedKey = (!isNewClient && existingKey != decodedKey);        // если ключ отличился(обновился)

    if(isSameKey)
    {
        qDebug() << "Client " << userID << "sent same public key again. Ignoring";

        return;
    }

    // Сохраняем публичный ключ клиента
    server.addPublicKey(userID, decodedKey);
    qDebug() << "Received and stored public key from client:" << userID;

    // Отправляем подтверждение текущему клиенту
    sendAcknowledgment(static_cast<quint8>(MessageType::PUBLIC_KEY_RECEIVED));

    QList<QTcpSocket*> otherClients;
    for(QTcpSocket *client : server.getClients())
    {
        if( client != clientSocket)
        {
            otherClients.append(client);
        }
    }

    for(QTcpSocket* client : otherClients)
    {
        writePublicKeyPacket(client, userID, decodedKey);
    }
    // Логирование
    qDebug() << "Broadcasted *new/updated* public key to all other clients.";

    if(isNewClient)
    {
        sendAllExistingKeysToNewClient();
    }
}


void ServerWorker::handleDataMessage(QTcpSocket *sender, const QByteArray &payload)
{
    qDebug() << "Receive data message key of size: " << payload.size();
    emit messageReceived(clientSocket, payload);
    // sendAcknowledgment(static_cast<quint8>(MessageType::DATA_MESSAGE));

}


void ServerWorker::handleChatMessage(const QByteArray &payload)
{
    qDebug() << "Handling chat message from user: " << server.getUserIDForSocket(clientSocket) ;
    emit messageReceived(clientSocket, payload);
}


// отправка всех известных старых ключей новому клиенту
void ServerWorker::sendAllExistingKeysToNewClient()
{
    QMap<QString, QByteArray> allKeys = server.getAllPublicKeys();

    QString newUserID = server.getUserIDForSocket(clientSocket);
    if (newUserID.isEmpty())
    {
        return;
    }

    for(auto it = allKeys.constBegin(); it != allKeys.constEnd(); ++it)
    {
        if(it.key() == newUserID)
        {
            continue;
        }

        writePublicKeyPacket(clientSocket, it.key(), it.value());
    }
    qDebug() << "Sent all existing public keys to NEW client:" << newUserID;
}


// сборка правильной инструкции публичного ключа
void ServerWorker::writePublicKeyPacket(QTcpSocket *client, const QString &userID, const QByteArray &rawKey)
{
    QByteArray userIDBytes = userID.toUtf8();
    quint32 userIDSize = userIDBytes.size();

    QByteArray encodedKey = rawKey;
    quint32 publicKeySize = encodedKey.size();

    QByteArray packet;
    QDataStream out (&packet, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);

    quint32 messageLength;
    quint8 messageType = static_cast<quint8>(MessageType::PUBLIC_KEY);

    out << messageLength;
    out << messageType;

    out << userIDSize;
    out.writeRawData(userIDBytes.constData(), userIDBytes.size());

    out << publicKeySize;
    out.writeRawData(encodedKey.constData(), encodedKey.size());

    messageLength = packet.size() - sizeof(quint32);
    memcpy(packet.data(), &messageLength, sizeof(quint32));

    client->write(packet);
    client->flush();

}





void ServerWorker::sendAcknowledgment(quint8 messageType)
{

    if (!clientSocket->isWritable())
    {
        qDebug() << "Socket is not writable. Waiting...";
        if (!clientSocket->waitForBytesWritten(3000))
        {
            qDebug() << "Socket is still not writable. Skipping acknowledgment.";
            return;
        }
    }

    QByteArray message;
    QDataStream out(&message, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);

    quint32 messageLength = sizeof(quint8);
    out << messageLength;
    out << messageType;

    qint64 bytesWritten = clientSocket->write(message);
    clientSocket->flush();

    if (bytesWritten == -1)
    {
        qDebug() << "Failed to write acknowledgment to client. Socket may be busy.";
    }
    else
    {
        qDebug() << "Sent acknowledgment with message type:" << messageType << ", Bytes written:" << bytesWritten;
    }
}


