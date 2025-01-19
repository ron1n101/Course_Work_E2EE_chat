#include "ClientWorker.h"
#include <QDataStream>
#include <QHostAddress>
#include <QThread>
#include <cryptopp/base64.h>
#include <QMutexLocker>


#include "MessageType.h"

// QMutex workerMutex;
// MessageType messageType;

using namespace CryptoPP;


ClientWorker::ClientWorker( const QString &username, QObject *parent)
    : QObject(parent),  username(username)
{

}

void ClientWorker::run()
{
    QMutexLocker locker (&workerMutex);
    if(username.isEmpty())
    {
        emit errorOccurred("Username not set before running client Worker");
        return;
    }
    socket = new QTcpSocket(this);

    connect(socket, &QTcpSocket::readyRead, this, &ClientWorker::handleConnection);
    connect(socket, &QTcpSocket::connected, this, &ClientWorker::onConnected);
    connect(socket, &QTcpSocket::disconnected, this, &ClientWorker::deleteLater);
    connectToServer();


    if(socket->state() == QAbstractSocket::ConnectedState)
    {
        onConnected();
    }

}


void ClientWorker::connectToServer()
{
    if(socket->state() == QAbstractSocket::UnconnectedState)
    {
        qDebug() << "Attempting to connect to server...";
        socket->connectToHost("127.0.0.1", 8001);

    }
    else
    {
        qDebug() << "Socket is already in state: " << socket->state();
    }
}



void ClientWorker::onConnected()
{
    qDebug() << "Connected to server successfully!";

    // Формируем и отправляем сообщение USERNAME_INIT серверу
    QByteArray message;
    QDataStream stream(&message, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::LittleEndian);

    quint32 messageLength = sizeof(quint8);
    quint8 messageType = static_cast<quint8>(MessageType::USERNAME_INIT);
    stream << messageLength << messageType;

    qint64 bytesWritten = socket->write(message);
    socket->flush();

    if (bytesWritten == -1)
    {
        emit errorOccurred("Failed to send USERNAME_INIT signal");
        return;
    }
    qDebug() << "Sent USERNAME_INIT signal to server, waiting for response...";

    if(!socket->isOpen())
    {
        emit errorOccurred("Socket is not opened, cannot read data");
        return;
    }
    if(!socket->isWritable())
    {
        emit errorOccurred("Socket is not readable. data cannot to be received");
        return;
    }

    if(socket->waitForReadyRead(3000))
    {
        handleConnection();
    }

}


void ClientWorker::sendPublicKey()
{
    if(socket && socket->state() == QAbstractSocket::ConnectedState)
    {
        emit publicKeyStatus(QString("%1 connected, sending public key to server. Waiting for another client to exchange public key.").arg(username));
        std::string pubKeyStr;
        StringSink sink(pubKeyStr);
        publicKey.Save(sink);

        QByteArray keyData = QByteArray::fromStdString(pubKeyStr).toBase64();
        QByteArray message;
        QDataStream stream(&message, QIODevice::WriteOnly);
        stream.setByteOrder(QDataStream::LittleEndian);

        // message structure
        quint32 messageLength = sizeof(quint8) + keyData.size();
        quint8 messageType = static_cast<quint8>(MessageType::PUBLIC_KEY);
        stream << messageLength << messageType;
        message.append(keyData);
        qDebug() << "Size of key data: " << keyData.size();

        qint64 bytesWritten = socket->write(message);
        socket->flush();

        if(bytesWritten == -1)
        {
            emit errorOccurred("Failed to send pubkey to server");
            return;
        }

        qDebug() << "Send public Key to server";

        if(!socket->waitForReadyRead(3000))
        {
            emit errorOccurred("No ACK from server for public key(timeout");

        }
        else
        {
            handleConnection();
        }

    }
    else
    {
        emit errorOccurred("Socket is not connected to send public Key");
    }
}






void ClientWorker::receivePublicKey()
{
    if (!socket || socket->state() != QAbstractSocket::ConnectedState)
    {
        emit errorOccurred("Socket is not connected. Cannot receive public key");
        return;
    }

    QDataStream in(socket);
    in.setByteOrder(QDataStream::LittleEndian);

    quint32 messageLength;
    quint8 messageType;

    // Проверяем заголовок
    if (socket->bytesAvailable() < sizeof(quint32) + sizeof(quint8) || !socket->waitForReadyRead(3000))
    {
        emit errorOccurred("Failed to receive public key header within timeout.");
        return;
    }

    in >> messageLength >> messageType;

    if (messageType != static_cast<quint8>(MessageType::PUBLIC_KEY))
    {
        emit errorOccurred("Unexpected message type. Expected PUBLIC_KEY.");
        return;
    }

    QByteArray keyDataBase64 = socket->read(messageLength - sizeof(quint8));
    QByteArray keyData = QByteArray::fromBase64(keyDataBase64);

    try
    {
        qDebug() << "Key data size: " << keyData.size();
        StringSource source(reinterpret_cast<const byte*>(keyData.data()), keyData.size(), true);
        otherPublicKey.Load(source);
        qDebug() << "Received and loaded public key of size: " << keyData.size();
    }
    catch (const Exception &e)
    {
        emit errorOccurred(QString("Failed to load public key: %1").arg(e.what()));
        return;
    }


}

QString ClientWorker::encryptMessageAES(const QString &message)
{
    AutoSeededRandomPool rng;
    SecByteBlock iv (AES::BLOCKSIZE);
    rng.GenerateBlock(iv, iv.size());

    std::string plainText = QString("%1: %2").arg(username, message).toStdString();
    std::string cipherText;
    try
    {
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(aesKey, aesKey.size(), iv);

        StringSource(plainText, true, new StreamTransformationFilter(encryption, new StringSink(cipherText), StreamTransformationFilter::PKCS_PADDING));
        QByteArray encryptedData = QByteArray::fromStdString(cipherText);
        encryptedData.prepend(reinterpret_cast<const char*>(iv.data(), iv.size()));
        return QString::fromUtf8(encryptedData.toBase64());
    }
    catch(const Exception &e)
    {
        emit errorOccurred(QString::fromStdString(e.what()));
        return QString();
    }
}


QString ClientWorker::decryptMessageAES(const QByteArray &cipherText)
{
    QByteArray encryptedData = QByteArray::fromBase64(cipherText);
    if(encryptedData.size() < AES::BLOCKSIZE)
    {
        emit errorOccurred("Invalid cipherText size");
        return QString();
    }
    SecByteBlock iv(reinterpret_cast<const byte*>(encryptedData.data()), AES::BLOCKSIZE);
    QByteArray encryptedMessage = encryptedData.mid(AES::BLOCKSIZE);

    std::string decryptedText;

    try
    {
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(aesKey, aesKey.size(), iv);
        StringSource(reinterpret_cast<const byte*>(encryptedMessage.data()),
                     encryptedMessage.size(), true,
                     new StreamTransformationFilter(decryption, new StringSink(decryptedText),
                                                    StreamTransformationFilter::PKCS_PADDING));
    }
    catch (const Exception& e)
    {
        emit errorOccurred(QString::fromStdString(e.what()));
        return QString();
    }
    return QString::fromStdString(decryptedText);
}


QString ClientWorker::encryptRSA(const QByteArray &key, const CryptoPP::RSA::PublicKey &publicKey)
{
    AutoSeededRandomPool rng;
    std::string cipherText;
    try
    {
        RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
        StringSource ss(reinterpret_cast<const byte*>(key.data()), key.size(), true, new PK_EncryptorFilter(rng, encryptor, new StringSink(cipherText)));

    }
    catch (Exception &e)
    {
        emit errorOccurred(QString("RSA encryption error %1: ").arg(e.what()));
        return QString();
    }
    return QString::fromUtf8(QByteArray::fromStdString(cipherText).toBase64());
}



QString ClientWorker::decryptRSA(const QString &cipherText, CryptoPP::RSA::PrivateKey &privateKey)
{
    QByteArray encryptedData = QByteArray::fromBase64(cipherText.toUtf8());
    std::string decryptedText;
    try
    {
        AutoSeededRandomPool rng;
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        StringSource ss(reinterpret_cast<const byte*>(encryptedData.data()), encryptedData.size(), true, new PK_DecryptorFilter(rng, decryptor, new StringSink(decryptedText)));
    }
    catch (Exception &e)
    {
        emit errorOccurred(QString("RSA decrypt failed %1: ").arg(e.what()));
        return QString();
    }
    return QString::fromStdString(decryptedText);
}


void ClientWorker::handleConnection()
{
    while (socket && socket->bytesAvailable() > 0)
    {
        QDataStream in(socket);
        in.setByteOrder(QDataStream::LittleEndian);

        if (socket->bytesAvailable() < static_cast<int>(sizeof(quint32) + sizeof(quint8)))
        {
            qDebug() << "Not enough data available. waiting more...";
            return;
        }

        quint32 messageLength;
        quint8 messageTypeRaw;

        in >> messageLength >> messageTypeRaw;

        MessageType messageType = static_cast<MessageType>(messageTypeRaw);

        if(socket->bytesAvailable() < messageLength - sizeof(quint8))
        {
            qDebug() << "Incomplete message received. Waiting for more data.";
            return;
        }
        QByteArray payload = socket->read(messageLength - sizeof(quint8));

        switch(messageType)
        {
        case MessageType::PUBLIC_KEY_RECEIVED:
            // receivePublicKey();
            emit publicKeyAcknowledged();
            qDebug() << "ACK for public key received.";
            break;

        case MessageType::USERNAME_READY:
            sendPublicKey();
            break;

        case MessageType::PUBLIC_KEY:
            processPublicKey(payload);
            break;


        case MessageType::DATA_MESSAGE:
            receiveMessage();
            break;
        default:
            qDebug() << "Unexpected message type received: " << static_cast<quint8>(MessageType::UNKNOW_MESSAGE);
            break;
        }

    }
}


void ClientWorker::receiveMessage()
{
    if(!socket || socket->state() != QAbstractSocket::ConnectedState)
    {
        emit errorOccurred("Socket not connected. Cannot receive message");
        return;
    }
    while(socket->bytesAvailable() > 0)
    {
        QDataStream in(socket);
        in.setByteOrder(QDataStream::LittleEndian);
        // collect msg size
        int msgSize = 0;
        in >> msgSize;

        if(msgSize <= 0 || msgSize > BUFFER_SIZE)
        {
            emit errorOccurred("Invalid message size");
            return;
        }

        // read data msg
        QByteArray buffer(msgSize, 0);
        if(in.readRawData(buffer.data(), msgSize) != msgSize)
        {
            emit errorOccurred("Failed receive complete message data.");
            return;
        }

        // decrypt data AES
        QByteArray encryptedAESkey = buffer.mid(0, 256);
        QByteArray iv = buffer.mid(256, AES::BLOCKSIZE);
        QByteArray encryptedMessage = buffer.mid(256 + AES::BLOCKSIZE);

        QString decryptedAESkey = decryptRSA(QString::fromUtf8(encryptedAESkey), privateKey);
        if(decryptedAESkey.isEmpty())
        {
            emit errorOccurred("Failed to decrypt AES Key");
            return;
        }

        QString decryptedMessage = decryptMessageAES(encryptedMessage);
        if(decryptedMessage.isEmpty())
        {
            emit errorOccurred("Failed to decrypt message.");
            return;
        }
        emit messageReceived("OtherClient: ", decryptedMessage) ;
    }

}

void ClientWorker::processPublicKey(const QByteArray &payload)
{
    QDataStream in(payload);
    in.setByteOrder(QDataStream::LittleEndian);

    while (!in.atEnd())
    {
        quint32 clientIDSize, publicKeySize;
        in >> clientIDSize;

        QByteArray clientIDBytes(clientIDSize, 0);
        in.readRawData(clientIDBytes.data(), clientIDSize);
        QString clientID = QString::fromUtf8(clientIDBytes);

        in >> publicKeySize;
        QByteArray publicKeyBytes(publicKeySize, 0);
        in.readRawData(publicKeyBytes.data(), publicKeySize);

        qDebug() << "Received public key for client:" << clientID << ", Key size:" << publicKeyBytes.size();

        try
        {
            CryptoPP::RSA::PublicKey otherClientKey;

            // Properly load the key using ByteQueue
            CryptoPP::ByteQueue byteQueue;
            byteQueue.Put(reinterpret_cast<const byte*>(publicKeyBytes.data()), publicKeyBytes.size());
            byteQueue.MessageEnd();

            otherClientKey.Load(byteQueue); // Correctly call the Load method

            // Store the key for later use
            receivedPublicKeys[clientID] = otherClientKey;
        }
        catch (const CryptoPP::Exception &e)
        {
            qDebug() << "Failed to process public key for client:" << clientID
                     << ", Error:" << e.what();
        }
    }
}



void ClientWorker::initializeClientData(const QString &username)
{
    QMutexLocker locker(&workerMutex);
    this->username = username;
    qDebug() << "Username :" << username;
    try
    {
        AutoSeededRandomPool rng;
        InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, 2048);
        publicKey = RSA::PublicKey(params);
        privateKey = RSA::PrivateKey(params);

        aesKey = SecByteBlock(AES::DEFAULT_KEYLENGTH);
        rng.GenerateBlock(aesKey, aesKey.size());

        std::string pubKeyStr;
        StringSink sink(pubKeyStr);
        publicKey.Save(sink);
        qDebug() << "RSA keys generated successfully. Public Key (base64):" << QString::fromStdString(pubKeyStr).toUtf8().toBase64();
    }
    catch(const Exception &e)
    {
        emit errorOccurred(QString::fromStdString(e.what()));
        return;
    }
    locker.unlock();

}


void ClientWorker::sendMessage(const QString &message)
{
    if(socket && socket->state() == QAbstractSocket::ConnectedState)
    {
        QByteArray messageData = message.toUtf8();
        QByteArray payload;
        QDataStream stream(&payload, QIODevice::WriteOnly);
        stream.setByteOrder(QDataStream::LittleEndian);

        // message structure
        stream << static_cast<quint32>(5 + messageData.size());
        stream << static_cast<quint8>(MessageType::DATA_MESSAGE);
        payload.append(messageData);

        socket->write(payload);
        socket->flush();
    }
    else
    {
        emit errorOccurred("Socket is not connected to send the message.");
    }
}




