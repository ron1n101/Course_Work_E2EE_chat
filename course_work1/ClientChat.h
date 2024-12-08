#ifndef CLIENTCHAT_H
#define CLIENTCHAT_H

#include <QMainWindow>
#include <QString>

// QT_BEGIN_NAMESPACE
namespace Ui {
class ClientChat;
}
// QT_END_NAMESPACE

class ClientChat : public QMainWindow
{
    Q_OBJECT

public:
    explicit ClientChat(QWidget *parent = nullptr);
    ~ClientChat();
    void setUsername(const QString &);

signals:
    void sendMessage(const QString &message);

public slots:
    void displayMessage(const QString &sender, const QString &message);
    void displayError(const QString &error);


private slots:
    void on_sendButton_clicked();

private:
    Ui::ClientChat *ui;
    QString username;
};
#endif // CLIENTCHAT_H
