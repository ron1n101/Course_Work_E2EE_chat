#include "ClientChat.h"
#include "ui_ClientChat.h"

ClientChat::ClientChat(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::ClientChat)
{
    ui->setupUi(this);
}

ClientChat::~ClientChat()
{
    delete ui;
}

void ClientChat::setUsername(const QString &username)
{
    this->username = username;
    setWindowTitle(QString("Chat - %1").arg(username));
}

void ClientChat::displayMessage(const QString &sender, const QString &message)
{
    ui->chatTextEdit->append(QString("%1: %2").arg(sender, message));       // добавить в интерфейс
}

void ClientChat::displayError(const QString &error)
{
    ui->chatTextEdit->append(QString("Error: %1").arg(error));              // добавить в интерфейс
}

void ClientChat::on_sendButton_clicked()
{
    QString message = ui->messageLineEdit->text();                          // добавить в интерфейс
    if(!message.isEmpty())
    {
        emit sendMessage(message);
        ui->messageLineEdit->clear();                                       // добавить в интерфейс
    }
}



