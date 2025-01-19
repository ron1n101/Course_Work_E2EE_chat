#ifndef CLIENTWORKERWRAPPER_H
#define CLIENTWORKERWRAPPER_H

#include <QObject>
#include "ClientWorker.h"
#include <QMutex>


class ClientWorkerWrapper : public QObject
{
    Q_OBJECT
public:
    explicit ClientWorkerWrapper(const QString &username);
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
    QMutex wrapperMutex;
};

#endif // CLIENTWORKERWRAPPER_H
