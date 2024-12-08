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
protected:
    void incomingConnection(qintptr socketDescriptor) override;

private slots:
    void handleDisconnection();

    void handleStatusConnection();

    // void handleChatMessage();



signals:
    void chatMessageReceived(const QString &sender, const QString &recipient, const QString &message);



private:
    // QMap<QTcpSocket*, ServerWorker*> clientWorkers; // Mapping sockets to workers
    QMap <QString, QString> clientsDetails;

    QMap<QTcpSocket*, QString> clients;      // replace qbytearray to qstring with username

    // QList<QTcpSocket*> clients;
    QMutex clientsMutex;

    void broadcastMessage(QTcpSocket* sender, const QByteArray& message);
    // void CollectID();

    QString getClientID(QTcpSocket *client);

};

#endif // SERVER_H
