// ClientWorker.h
#ifndef CLIENTWORKER_H
#define CLIENTWORKER_H

#include <cryptopp/aes.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <QObject>
#include <QTcpSocket>
#include <QMutex>
#include <QString>
#include <QAbstractSocket>
#include "MessageType.h"

#define BUFFER_SIZE 4096
// #define USERNAME_INIT 13
// #define USERNAME_READY 14

class ClientWorker : public QObject
{
    Q_OBJECT
public:
    explicit ClientWorker(int socketDescriptor, const QString &username, QObject *parent = nullptr);

    void run();
    void sendMessage(const QString &message);
    void sendPublicKey();
    void receivePublicKey();
    void receiveMessage();

    // void sendUsername();
    // void initializeClientData(const QString &username);

    void initializeClientData(const QString &username);

signals:
    void connectionEstablished();
    void usernameAcknowledged();
    void publicKeyAcknowledged();
    void messageReceived(const QString &sender, const QString &message);
    void errorOccurred(const QString &error);

    void clientStatusChanged(const QString &message);
    void publicKeyStatus(const QString &message);

private slots:
    void onConnected();
    // void handleServerResponse();

private:
    void handleConnection();
    QString encryptMessageAES(const QString &message);
    QString decryptMessageAES(const QByteArray &cipherText);
    QString encryptRSA(const QByteArray& key, const CryptoPP::RSA::PublicKey& publicKey);
    QString decryptRSA(const QString& cipherText, CryptoPP::RSA::PrivateKey& privateKey);

    QTcpSocket *socket;
    int socketDescriptor;
    QString username;
    CryptoPP::RSA::PrivateKey privateKey;
    CryptoPP::RSA::PublicKey publicKey;
    CryptoPP::RSA::PublicKey otherPublicKey;
    CryptoPP::SecByteBlock aesKey;
    QMutex socketMutex;

    QMap<QString, CryptoPP::RSA::PublicKey> receivedPublicKeys;
    void connectToServer();
    void processPublicKey(const QByteArray &payload);

};

#endif // CLIENTWORKER_H
