#include "ClientLogin.h"
#include "ui_ClientLogin.h"
#include "ClientWorkerWrapper.h"
#include <QThreadPool>

ClientLogin::ClientLogin(QWidget *parent)
    : QWidget{parent},
    ui(new Ui::ClientLogin)
{
    ui->setupUi(this);
}

ClientLogin::~ClientLogin()
{
    delete ui;

}

void ClientLogin::on_loginButton_clicked()
{
    if(!workerWrapper)
    {
        QString username = ui->userNameLineEdit->text();
        if(!username.isEmpty())
        {
            emit usernameEntered(username);
            this->close();

            int socketDescriptor = 0;
            workerWrapper = new ClientWorkerWrapper(socketDescriptor, username);
            workerWrapper->initializeClientData(username);
        }
    }
}
