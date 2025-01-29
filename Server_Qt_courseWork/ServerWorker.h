#ifndef SERVERWORKER_H
#define SERVERWORKER_H

#include "MessageType.h"

#include <QMutex>
#include <QObject>
#include <QTcpSocket>
#include <QMutexLocker>
#include <QThread>

class Server;

class ServerWorker : public QObject
{
    Q_OBJECT
public:
    explicit ServerWorker(QTcpSocket* clientSocket, Server *parent = nullptr);

    QByteArray getPublicKey() const {return clientPublicKey;}

    // set and get name
    void setUsername(const QString& username) {this->username = username; }

    QString getUsername() const {return this->username;}

signals:
    void clientDisconnect(ServerWorker *worker);

    void messageReceived(QTcpSocket *sender, const QByteArray &message);

    void chatMessageReceived(const QString &sender, const QString &recipient, const QString &message);

private slots:
    void processClient();

    void handleClientDisconnected();


private:

    void sendAcknowledgment(quint8 messageType);



    void broadcastMessage(QTcpSocket* sender, const QByteArray& message);

    void handleUsernameInit();

    void handlePublicKey(const QByteArray &payload);

    void handleDataMessage(QTcpSocket* sender, const QByteArray &payload);

    void handleChatMessage(const QByteArray &payload);

    void sendAllExistingKeysToNewClient();

    void writePublicKeyPacket(QTcpSocket *toClient, const QString &sourceClientID, const QByteArray &rawKey);   // кому отправлено, чей ключ, сам ключ

    QTcpSocket *clientSocket;

    QByteArray clientPublicKey;

    QByteArray m_buffer;

    QString username;

    Server& server;

    QMutex clientsMutex;
};

#endif // SERVERWORKER_H
