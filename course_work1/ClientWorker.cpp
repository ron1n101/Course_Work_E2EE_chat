#include "ClientWorker.h"
#include <QDataStream>
#include <QHostAddress>
#include <QThread>
#include <cryptopp/base64.h>
#include <QMutexLocker>


#include "MessageType.h"

QMutex workerMutex;
MessageType messageType;

using namespace CryptoPP;


ClientWorker::ClientWorker(int socketDescriptor, const QString &username, QObject *parent)
    : QObject(parent), socketDescriptor(socketDescriptor), username(username)
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
    socket = new QTcpSocket();
    if(!socket->setSocketDescriptor(socketDescriptor))
    {
        emit errorOccurred("Failed to set socket descriptor: " + QString::number(socketDescriptor));
        return;
    }

    qDebug() << "Socket set successfully. attempting to connect to server.";

    connect(socket, &QTcpSocket::readyRead, this, &ClientWorker::handleConnection);
    connect(socket, &QTcpSocket::connected, this, &ClientWorker::onConnected);
    connect(socket, &QTcpSocket::disconnected, this, &ClientWorker::deleteLater);



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

        qint64 bytesWritten = socket->write(message);
        socket->write(message);
        socket->flush();

        if(bytesWritten == -1)
        {
            emit errorOccurred("Failed to send pubkey to server");
            return;
        }

        qDebug() << "Send public Key to server";

        if(socket->waitForReadyRead(3000))
        {
            handleConnection();
        }
        else
        {
            emit errorOccurred("No ACK from server for public key");
        }

    }
    else
    {
        emit errorOccurred("Socket is not connected to send public Key");
    }
}






void ClientWorker::receivePublicKey()
{
    if(!socket || socket->state() != QAbstractSocket::ConnectedState)
    {
        emit errorOccurred ("Socket in not connected. Cannot receive public key");
        return;
    }

    QDataStream in(socket);
    in.setByteOrder(QDataStream::LittleEndian);

    const int maxAttempts = 5;
    int attempt = 0;


    while(socket->bytesAvailable() < static_cast<int>(sizeof(quint32) + sizeof(quint8)) && attempt < maxAttempts)
    {
        // emit errorOccurred("Not enough data available to proccess pub key");
        if(!socket->waitForReadyRead(1000))
        {
            attempt++;
            qDebug() << "Attempt" << attempt << ": Waiting for more data to read public key header...";
        }

    }


    if (attempt == maxAttempts)
    {
        emit errorOccurred("Failed to receive public key header within timeout.");
        return;
    }

    quint32 messageLength;
    quint8 messageType;

    in >> messageLength >> messageType;

    if(messageType != static_cast<quint8>(MessageType::PUBLIC_KEY_RECEIVED))
    {
        emit errorOccurred("Unexpected message type. Expected PUBLIC_KEY_RECEIVED");
        return;
    }

    int expectedPayloadSize = messageLength - sizeof(quint8);
    attempt = 0;
    while (socket->bytesAvailable() < expectedPayloadSize && attempt < maxAttempts)
    {
        if (!socket->waitForReadyRead(1000)) // Ждем данные в течение 1 секунды
        {
            attempt++;
            qDebug() << "Attempt" << attempt << ": Waiting for more data to read the full public key payload...";
        }
    }

    if (attempt == maxAttempts)
    {
        emit errorOccurred("Failed to receive complete public key payload within timeout.");
        return;
    }

    QByteArray keyDataBase64 = socket->read(expectedPayloadSize);
    if(keyDataBase64.size() < expectedPayloadSize)
    {
        emit errorOccurred("Failed to receive complete public key payload");
        return;
    }

    QByteArray keyData = QByteArray::fromBase64(keyDataBase64);


    try
    {
        StringSource source (reinterpret_cast<const byte*> (keyData.data()), keyData.size(), true );
        otherPublicKey.Load(source);
        qDebug() << "Received public key of size: " << keyData.size();
        emit publicKeyAcknowledged();
    }
    catch (const Exception &e)
    {
        emit errorOccurred(QString("Failed to load public Key: %1").arg(e.what()));
        return;
    }
    emit publicKeyAcknowledged();
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

        // if(socket->bytesAvailable() < messageLength - sizeof(quint8))
        // {
        //     qDebug() << "Incomplete message received. Waiting for more data....";
        // }
        QByteArray payload = socket->read(messageLength - sizeof(quint8));
        switch(messageType)
        {
        case MessageType::PUBLIC_KEY_RECEIVED:
            receivePublicKey();
            break;

        case MessageType::USERNAME_READY:
            sendPublicKey();
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




