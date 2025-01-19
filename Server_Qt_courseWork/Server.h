#ifndef SERVER_H
#define SERVER_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QMap>
#include <QMutex>

class Server : public QTcpServer
{
    Q_OBJECT

public:
    explicit Server(QObject *parent = nullptr);

    void removeClient(QTcpSocket *client);

    void addPublicKey(const QString &clientID, const QByteArray &key);

    QByteArray getPublicKey(const QString &clientID) const;

    QMap<QString, QByteArray> getAllPublicKeys() const;

    QList<QTcpSocket*> getClients();

    void lockClientMutex();
    void unlockClientMutex();



protected:
    void incomingConnection(qintptr socketDescriptor) override;

private slots:
    void handleDisconnection();

    void handleStatusConnection();

signals:
    void chatMessageReceived(const QString &sender, const QString &recipient, const QString &message);

private:

    QString getClientID(QTcpSocket *client);

    QMap<QTcpSocket*, QString> clients; // Сокет -> имя пользователя

    QMap<QString, QByteArray> publicKeys; // ID клиента -> публичный ключ

    QMap<QTcpSocket*, QByteArray> waitingClients;

    mutable QMutex clientsMutex;

    void broadcastMessage(QTcpSocket* sender, const QByteArray& message);

};

#endif // SERVER_H
