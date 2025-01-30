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



class Server;

#define BUFFER_SIZE 4096

class ClientWorkerWrapper;


class ClientWorker : public QObject
{
    Q_OBJECT
public:
    explicit ClientWorker( const QString &username, QObject *parent = nullptr);

    void run();
    void sendPublicKey();
    void receiveMessage(const QByteArray &payload);
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

public slots:
    void sendMessage(const QString &plainText);
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
    QByteArray m_buffer;

    QMutex workerMutex;




};

#endif // CLIENTWORKER_H
