#include "ServerWorker.h"
#include "MessageType.h"
#include <QDataStream>
#include <QDebug>
#include "Server.h"

MessageType messageType;

ServerWorker::ServerWorker(QTcpSocket *clientSocket, Server *parent): QObject(parent), clientSocket(clientSocket), server(*parent)
{
    connect(clientSocket, &QTcpSocket::readyRead, this, &ServerWorker::processClient);
    // connect(clientSocket, &QTcpSocket::readyRead, this, &ServerWorker::handleReadyRead);
    connect(clientSocket, &QTcpSocket::disconnected, this, &ServerWorker::handleClientDisconnected);

}




void ServerWorker::processClient()
{
    QDataStream in(clientSocket);
    in.setByteOrder(QDataStream::LittleEndian);

    while(clientSocket->bytesAvailable() >= static_cast<int>(sizeof(quint32) + sizeof(quint8)))
    {
        quint32 messageLength;
        quint8 messageType;

        // Read length and type
        in >> messageLength >> messageType;

        if (clientSocket->bytesAvailable() < messageLength - sizeof(quint8))
        {
            // Not enough data for the full message, wait for more
            clientSocket->seek(clientSocket->pos() - sizeof(quint32) - sizeof(quint8));
            return;
        }

        // QByteArray payload = clientSocket->read(messageLength - sizeof(quint8));
        QByteArray payload = clientSocket->read(messageLength - sizeof(quint8));

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

    qDebug() << "\nReceived USERNAME_INIT from client:" << clientSocket->peerAddress().toString() + ":" + QString::number(clientSocket->peerPort());

    // Отправляем подтверждение клиенту, что сервер готов для получения имени пользователя
    sendAcknowledgment(static_cast<quint8>(MessageType::USERNAME_READY));
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

    QString clientID = clientSocket->peerAddress().toString() + ":" + QString::number(clientSocket->peerPort());

    QByteArray existingKey = server.getPublicKey(clientID);

    bool isNewClient = existingKey.isEmpty();       // ключа вовсе нет
    bool isSameKey = (!isNewClient &&  existingKey == decodedKey);   // если ключ совпадает
    bool isChangedKey = (!isNewClient && existingKey != decodedKey);  // если ключ отличился(обновился)

    if(isSameKey)
    {
        qDebug() << "Client " << clientID << "sent same public key again. Ignoring";
        // sendAcknowledgment(static_cast<quint8>(MessageType::PUBLIC_KEY_RECEIVED));
        return;
    }

    // Сохраняем публичный ключ клиента
    server.addPublicKey(clientID, decodedKey);
    qDebug() << "Received and stored public key from client:" << clientID;

    // Отправляем подтверждение текущему клиенту
    sendAcknowledgment(static_cast<quint8>(MessageType::PUBLIC_KEY_RECEIVED));

    // вручную формируем пакет на отправку с сигналом *нового* публичного ключа
    {
        // QByteArray broadcastMessage;
        // QDataStream out (&broadcastMessage, QIODevice::WriteOnly);
        // out.setByteOrder(QDataStream::LittleEndian);

        // QByteArray base64key = decodedKey.toBase64();
        // quint32 messageLength = base64key.size() + sizeof(quint8);
        // quint8 messageType = static_cast<quint8>(MessageType::PUBLIC_KEY);

        // out << messageLength << messageType;
        // broadcastMessage.append(base64key);

        // Получаем список других клиентов
        // QList<QTcpSocket*> otherClients;
        // {
        //     server.lockClientMutex();
        //     for (QTcpSocket* client : server.getClients())
        //     {
        //         if (client != clientSocket) // Пропускаем текущего клиента
        //         {
        //             otherClients.append(client);
        //         }
        //     }
        //     server.unlockClientMutex();
        // }

        // Отправляем публичный ключ текущего клиента другим клиентам
        // for (QTcpSocket* client : otherClients)
        // {
        //     // if (client->write(broadcastMessage) == -1)
        //     // {
        //     //     qDebug() << "Failed to send public key to client:" << clientSocket->peerAddress().toString() + ":" + QString::number(clientSocket->peerPort());
        //     // }
        //     // client->flush();

        // }

        QList<QTcpSocket*> otherClients;
        for(QTcpSocket* client : otherClients)
        {
            writePublicKeyPacket(client, clientID, decodedKey);
        }
        // Логирование
        qDebug() << "Broadcasted *new/updated* public key to all other clients.";
    }

    if(isNewClient)
    {
        sendAllExistingKeysToNewClient();
    }
}


void ServerWorker::handleDataMessage(QTcpSocket *sender, const QByteArray &payload)
{
    qDebug() << "Receive data message key of size: " << payload.size();
    emit messageReceived(clientSocket, payload);

}


void ServerWorker::handleChatMessage(const QByteArray &payload)
{
    qDebug() << "Handling chat message from user: " << username;

    // The payload contains the chat message to broadcast
    emit messageReceived(clientSocket, payload);
}


// отправка всех известных старых ключей новому клиенту
void ServerWorker::sendAllExistingKeysToNewClient()
{
    QMap<QString, QByteArray> allKeys = server.getAllPublicKeys();          // при подключении второго клиента утечка ОЗУ

    QString newClientID = clientSocket->peerAddress().toString() + ":" + QString::number(clientSocket->peerPort());

    for(auto it = allKeys.constBegin(); it != allKeys.constEnd(); ++it)
    {
        if(it.key() == newClientID)
        {
            continue;
        }

        writePublicKeyPacket(clientSocket, it.key(), it.value());

        // const QByteArray &existingKey = it.value();
        // quint32 messageLength = existingKey.size() + sizeof(quint8);


        // QByteArray message;
        // QDataStream out (&message, QIODevice::WriteOnly);
        // out.setByteOrder(QDataStream::LittleEndian);

        // quint8 messageType = static_cast<quint8>(MessageType::PUBLIC_KEY);

        // out << messageLength << messageType;
        // message.append(existingKey);

        // clientSocket->write(message);
        // clientSocket->flush();
    }
    qDebug() << "Sent all existing public keys to NEW client:" << newClientID;
}


// сборка правильной инструкции публичного ключа
void ServerWorker::writePublicKeyPacket(QTcpSocket *client, const QString &sourceClientID, const QByteArray &rawKey)
{
    QByteArray clientIDBytes = sourceClientID.toUtf8();
    quint32 clientIDSize = clientIDBytes.size();

    QByteArray encodedKey = rawKey.toBase64();
    quint32 publicKeySize = encodedKey.size();

    QByteArray packet;
    QDataStream out (&packet, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);

    quint32 messageLength = sizeof(quint8);
    quint8 messageType = static_cast<quint8>(MessageType::PUBLIC_KEY);

    out << messageLength;
    out << messageType;

    out << clientIDSize;
    out.writeRawData(clientIDBytes.constData(), clientIDBytes.size());

    out << publicKeySize;
    out.writeRawData(encodedKey.constData(), encodedKey.size());

    // memcpy(packet.data(), &messageLength, sizeof(quint32));


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


