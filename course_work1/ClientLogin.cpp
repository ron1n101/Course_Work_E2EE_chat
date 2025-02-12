#include "ClientLogin.h"
#include "ui_ClientLogin.h"
#include <QThreadPool>
#include <QMessageBox>

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
    QString username = ui->userNameLineEdit->text();
    if(!username.isEmpty())
    {
        emit usernameEntered(username);
        this->close();        
    }
    else
    {
        QMessageBox::warning(this, "Warning", "Username cannot be empty", "Okay!");
    }
}
