#include "ClientWorker.h"
#include <QDataStream>
#include <QHostAddress>
#include <QThread>
#include <cryptopp/base64.h>
#include <QMutexLocker>


#include "MessageType.h"

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
    m_buffer.append(socket->readAll());
    QDataStream in (&m_buffer, QIODevice::ReadOnly);
    in.setByteOrder(QDataStream::LittleEndian);
    while (true)
    {

        if (m_buffer.size() < static_cast<int>(sizeof(quint32) + sizeof(quint8)))
        {
            return;
        }

        quint32 messageLength;
        quint8 messageTypeRaw;

        in >> messageLength;
        in >> messageTypeRaw;



        MessageType messageType = static_cast<MessageType>(messageTypeRaw);

        if (m_buffer.size() < messageLength + sizeof(quint32))
        {
            return;
        }


        QByteArray payload = m_buffer.mid(sizeof(quint32) + sizeof(quint8), messageLength - sizeof(quint8));
        m_buffer.remove(0, messageLength + sizeof(quint32));

        switch(messageType)
        {
        case MessageType::PUBLIC_KEY_RECEIVED:
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
            receiveMessage(payload);
            break;
        default:
            qDebug() << "Unexpected message type received: " << static_cast<quint8>(MessageType::UNKNOW_MESSAGE);
            break;
        }
        qDebug() << "Received message type:" << static_cast<int>(messageTypeRaw);
    }
}


void ClientWorker::receiveMessage(const QByteArray &payload)
{
    if(!socket || socket->state() != QAbstractSocket::ConnectedState)
    {
        emit errorOccurred("Socket not connected. Cannot receive message");
        return;
    }

    // начинаем парсить буфер
    QDataStream parcer(payload);
    parcer.setByteOrder(QDataStream::LittleEndian);

    // считываем подключаемых клиентов
    quint32 numberOfRecepeints;
    parcer >> numberOfRecepeints;


    // проверяем попался ли нам наш блок сообщения и ключа
    bool findMyBlock = false;
    QByteArray myRSAencryptionKey;

    for(quint32 i = 0; i < numberOfRecepeints; ++i)
    {
        // читаем ClientID
        quint32 clientIDSize;
        parcer >> clientIDSize;

        QByteArray clientIDBytes(clientIDSize, 0);
        parcer.readRawData(clientIDBytes.data(), clientIDSize);
        QString clientID = QString::fromUtf8(clientIDBytes);

        // читаем зашифрованный AES-ключ
        quint32 encryptionKeySize;
        parcer >> encryptionKeySize;

        QByteArray encryptionKey(encryptionKeySize, 0);
        parcer.readRawData(encryptionKey.data(), encryptionKeySize);

        // если clientID это мой юзернейм, то это мой блок, просто сохраняем мой ключ и ставим флаг, что мой блок найдем
        if(clientID == this->username)
        {
            myRSAencryptionKey = encryptionKey;
            findMyBlock = true;
        }
    }

    // читаем aes шифр и длину его
    quint32 aesCipherSize;
    parcer >> aesCipherSize;
    QByteArray aesCipher(aesCipherSize, 0);
    parcer.readRawData(aesCipher.data(), aesCipherSize);

    // если мой блок не найден, то скипаем его
    if(!findMyBlock)
    {
        emit errorOccurred("Didnt find my block. Ignoring");
        return;
    }

    // расшифровываем AES ключ через приватный ключ
    QString base64Encoded = QString::fromUtf8(myRSAencryptionKey.toBase64());
    QString decryptedAESKey = decryptRSA(base64Encoded, privateKey);
    if(decryptedAESKey.isEmpty())
    {
        emit errorOccurred(" Failed to decrypt AES Key");
        return;
    }
    // конвертируем обратно в SecByteBlock
    QByteArray aeskeyBytes = decryptedAESKey.toUtf8();
    if(aeskeyBytes.size() != AES::DEFAULT_KEYLENGTH)
    {
        emit errorOccurred("Decrypted AES Key has invalid size");
        return;
    }

    // Заполняем SecByteBlock
    SecByteBlock ephermalAES(reinterpret_cast<const byte*>(aeskeyBytes.data()), aeskeyBytes.size());

    if(aesCipher.size() < AES::BLOCKSIZE)
    {
        emit errorOccurred("aes cipher size to small for IV");
        return;
    }

    QByteArray ivBA = aesCipher.left(AES::BLOCKSIZE);
    QByteArray encryptionMessageBA = aesCipher.mid(AES::BLOCKSIZE);

    std::string decryptedText;
    try {
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(ephermalAES, ephermalAES.size(), reinterpret_cast<const byte*>(ivBA.data(), ivBA.size()));

        std::string cipherString(encryptionMessageBA.constBegin(), encryptionMessageBA.size());
        StringSource ss(cipherString, true, new StreamTransformationFilter(decryption, new StringSink(decryptedText), StreamTransformationFilter::PKCS_PADDING));

    } catch (const CryptoPP::Exception &e) {
        emit errorOccurred(QString("AES decrypt message failed").arg(e.what()));
        return;
    }

    QString message = QString::fromStdString(decryptedText);
    emit messageReceived("OtherClient", message);

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
    // locker.unlock();

}


void ClientWorker::sendMessage(const QString &plainText, const QMap <QString, CryptoPP::RSA::PublicKey> &recepientsID)
{
    if(socket && socket->state() == QAbstractSocket::ConnectedState)
    {
        AutoSeededRandomPool rng;
        SecByteBlock iv(AES::BLOCKSIZE);
        rng.GenerateBlock(iv, iv.size());

        std::string plain = plainText.toStdString();
        std::string cipherText;
        try {
            CBC_Mode<AES>::Encryption encryption;
            encryption.SetKeyWithIV(aesKey, aesKey.size(), iv);
            StringSource(plain, true,
                new StreamTransformationFilter(encryption,
                    new StringSink(cipherText),
                        StreamTransformationFilter::PKCS_PADDING));
        } catch (const Exception& e) {
            emit errorOccurred("AES encryption failed");
            return;
        }



        QByteArray aesCipher = QByteArray::fromStdString(cipherText);
        aesCipher.prepend(reinterpret_cast<const char*>(iv.data()),iv.size());


        QByteArray packet;
        QDataStream out (&packet, QIODevice::WriteOnly);
        out.setByteOrder(QDataStream::LittleEndian);

        quint32 messageLength;
        quint8 messageType = static_cast<quint8>(MessageType::DATA_MESSAGE);

        out << messageLength;
        out << messageType;

        quint32 numberOfRecepients = recepientsID.size();
        out << numberOfRecepients;

        for(auto it = recepientsID.begin(); it != recepientsID.end(); ++it)
        {
            QString clientID = it.key();
            RSA::PublicKey publicKey = it.value();

            qDebug() << "Sending to clientID: " << clientID << "Current username: " << this->username;

            QByteArray aesKeyBytes(reinterpret_cast<const char*>(aesKey.data()), aesKey.size());

            QString rsaEncryptedBase64 = encryptRSA(aesKeyBytes, publicKey);
            QByteArray rsaEncryptedRaw = QByteArray::fromBase64(rsaEncryptedBase64.toUtf8());


            QByteArray clientIDBytes = clientID.toUtf8();
            quint32 clientIDSize = clientIDBytes.size();
            quint32 encryptionKeySize = rsaEncryptedRaw.size();

            out << clientIDSize;
            out.writeRawData(clientIDBytes.constData(), clientIDSize);

            out << encryptionKeySize;
            out.writeRawData(rsaEncryptedRaw.constData(), encryptionKeySize);
        }


        quint32 aesCipherSize = aesCipher.size();
        out << aesCipherSize;
        out.writeRawData(aesCipher.constData(), aesCipherSize);


        messageLength = packet.size() - sizeof(quint32);

        memcpy(packet.data(), &messageLength, sizeof(quint32));

        qint64 bytesWritten = socket->write(packet);
        socket->flush();
        if(bytesWritten == -1)
        {
            qDebug() << "Failed to send message";
        }
        else
        {
            qDebug() << "Message sent. Bytes: " << bytesWritten;
        }
    }
}
