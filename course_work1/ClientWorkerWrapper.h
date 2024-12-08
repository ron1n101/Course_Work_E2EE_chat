#ifndef CLIENTWORKERWRAPPER_H
#define CLIENTWORKERWRAPPER_H

#include <QObject>
#include "ClientWorker.h"



class ClientWorkerWrapper : public QObject
{
    Q_OBJECT
public:
    explicit ClientWorkerWrapper(int socketDecriptor, const QString &username);
    void sendMessage(const QString &message);
    void initializeClientData(const QString &username);



signals:
    void messageReceived(const QString &sender, const QString &message);
    void errorOccurred(const QString &error);

public slots:
    void onWorkerConnected();             // Обработка успешного подключения
    void onUsernameAcknowledged();        // Обработка подтверждения получения имени пользователя
    void onPublicKeyAcknowledged();


private:
    ClientWorker *worker;
};

#endif // CLIENTWORKERWRAPPER_H
