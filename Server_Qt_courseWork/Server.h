#ifndef SERVER_H
#define SERVER_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QMap>
#include <QMutex>
#include <QUuid>

class Server : public QTcpServer
{
    Q_OBJECT


public:
    explicit Server(QObject *parent = nullptr);

    void removeClient(QTcpSocket *client);

    void addPublicKey(const QString &userID, const QByteArray &key);

    QByteArray getPublicKey(const QString &userID) const;

    QMap<QString, QByteArray> getAllPublicKeys() const;

    QList<QTcpSocket*> getClients();

    void lockClientMutex();
    void unlockClientMutex();

    void setUserIDForSocket(QTcpSocket* socket, const QString &userID);

    QString getUserIDForSocket(QTcpSocket* socket) const;

    inline QString generateUserID()
    {
        return QUuid::createUuid().toString(QUuid::WithoutBraces);
    }


protected:
    void incomingConnection(qintptr socketDescriptor) override;

private slots:
    void handleDisconnection(QTcpSocket* client);

    void handleStatusConnection();

signals:
    void chatMessageReceived(const QString &sender, const QString &recipient, const QString &message);

private:

    QString getClientID(QTcpSocket *client);

    QMap<QTcpSocket*, QString> clients; // Сокет -> имя пользователя

    QMap<QString, QByteArray> publicKeys; // ID клиента -> публичный ключ

    QMap<QTcpSocket*, QByteArray> waitingClients;

    mutable QMutex clientsMutex;

    void broadcastMessage(QTcpSocket* sender, const QByteArray& payload);

};

#endif // SERVER_H
