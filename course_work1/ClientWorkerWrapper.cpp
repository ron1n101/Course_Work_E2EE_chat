#include "ClientWorkerWrapper.h"
#include <QThread>
#include <QDebug>
#include <QMutex>

ClientWorkerWrapper::ClientWorkerWrapper( const QString &username)
    : QObject(nullptr), worker(new ClientWorker( username))
{
    // Создание нового потока
    QThread *thread = new QThread(this);

    // Перенос worker в новый поток
    worker->moveToThread(thread);

    // Подключение сигналов для обработки сообщений и ошибок
    connect(worker, &ClientWorker::connectionEstablished, this, &ClientWorkerWrapper::onWorkerConnected);
    connect(worker, &ClientWorker::publicKeyAcknowledged, this, &ClientWorkerWrapper::onPublicKeyAcknowledged);
    connect(worker, &ClientWorker::messageReceived, this, &ClientWorkerWrapper::messageReceived);
    connect(this, &ClientWorkerWrapper::sendMessageRequested, worker, &ClientWorker::sendMessage, Qt::QueuedConnection);
    connect(worker, &ClientWorker::errorOccurred, this, &ClientWorkerWrapper::errorOccurred);

    // Запуск worker, когда поток запущен
    connect(thread, &QThread::started, worker, &ClientWorker::run);

    // Завершение потока и удаление объектов, когда worker завершен или произошла ошибка
    connect(worker, &ClientWorker::errorOccurred, thread, &QThread::quit);
    connect(worker, &ClientWorker::errorOccurred, worker, &ClientWorker::deleteLater);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);

    // Добавление отладочного сообщения
    connect(thread, &QThread::started, []() {
        qDebug() << "Thread started successfully.";
    });

    // Запуск потока
    if (!thread->isRunning()) {
        thread->start();
        qDebug() << "Thread for worker started.";
    } else {
        qDebug() << "Thread is already running.";
    }
}



void ClientWorkerWrapper::initializeClientData(const QString &username)
{
    if (worker)
    {
        worker->initializeClientData(username);
    }
}


void ClientWorkerWrapper::sendMessage(const QString &plainText)
{
    if (worker) {
        qDebug() << "Sending message from wrapper.";
        emit sendMessageRequested(plainText);
    } else {
        qDebug() << "Worker is not available to send message.";
    }
}

// Слот для обработки подключения
void ClientWorkerWrapper::onWorkerConnected()
{
    qDebug() << "Worker connected successfully. Sending username.";
    if (worker) {
        QMutexLocker locker(&wrapperMutex);
        worker->sendPublicKey();
    } else {
        qDebug() << "Worker is not available to send username.";
    }
}

// Слот для обработки подтверждения получения имени пользователя
void ClientWorkerWrapper::onUsernameAcknowledged()
{
    qDebug() << "Username acknowledged by server. Proceeding to send public key.";
    if (worker) {
        QMutexLocker locker (&wrapperMutex);
        worker->sendPublicKey();
    } else {
        qDebug() << "Worker is not available to send public key.";
    }
}

// Слот для обработки подтверждения получения публичного ключа
void ClientWorkerWrapper::onPublicKeyAcknowledged()
{
    qDebug() << "Public key acknowledged by server. Ready to communicate.";

}
