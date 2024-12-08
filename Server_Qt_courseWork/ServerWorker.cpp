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

void ServerWorker::sendPublicKeyToClient(const QByteArray &publicKey)
{
    QByteArray encodedKey = publicKey.toBase64();
    QByteArray message;
    QDataStream out (&message, QIODevice::WriteOnly);
    out.setByteOrder(QDataStream::LittleEndian);

    quint32 messageLength = encodedKey.size() + sizeof(quint8);
    quint8 messageType = static_cast<quint8>(MessageType::PUBLIC_KEY);

    out << messageLength;
    out << messageType;
    message.append(encodedKey);

    clientSocket->write(message);
    clientSocket->flush();
    qDebug() << "Sent public Key size of: " << publicKey.size() << " after base64 encoded";

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

    qDebug() << "Client disconnected:" << clientSocket->peerAddress().toString();
    emit clientDisconnect(this);

    clientSocket->deleteLater();
    deleteLater();
}


void ServerWorker::handleUsernameInit()
{

    qDebug() << "Received USERNAME_INIT from client:" << clientSocket->peerAddress().toString();

    // Отправляем подтверждение клиенту, что сервер готов для получения имени пользователя
    sendAcknowledgment(static_cast<quint8>(MessageType::USERNAME_READY));
}

void ServerWorker::handlePublicKey(const QByteArray &payload)
{
    QByteArray decodedKey = QByteArray::fromBase64(payload);
    qDebug() << "Received public key size: " << decodedKey.size();

    // send ack to the client
    clientPublicKey = payload;
    sendAcknowledgment(static_cast<quint8>(MessageType::PUBLIC_KEY_RECEIVED));
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


