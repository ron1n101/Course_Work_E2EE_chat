#ifndef CLIENTLOGIN_H
#define CLIENTLOGIN_H

#include <QWidget>
#include <QString>
#include "ClientWorkerWrapper.h"

namespace Ui {
class ClientLogin;
}

class ClientLogin : public QWidget
{
    Q_OBJECT
public:
    explicit ClientLogin(QWidget *parent = nullptr);
    ~ClientLogin();

signals:
    void usernameEntered(const QString &username);

private slots:
    void on_loginButton_clicked();

private:
    Ui::ClientLogin *ui;
    ClientWorkerWrapper *workerWrapper = nullptr;
};

#endif // CLIENTLOGIN_H
