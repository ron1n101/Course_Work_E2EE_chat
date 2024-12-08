/********************************************************************************
** Form generated from reading UI file 'ClientChat.ui'
**
** Created by: Qt User Interface Compiler version 6.5.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CLIENTCHAT_H
#define UI_CLIENTCHAT_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ClientChat
{
public:
    QWidget *centralwidget;
    QTextEdit *chatTextEdit;
    QLineEdit *messageLineEdit;
    QPushButton *sendButton;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *ClientChat)
    {
        if (ClientChat->objectName().isEmpty())
            ClientChat->setObjectName("ClientChat");
        ClientChat->resize(424, 297);
        centralwidget = new QWidget(ClientChat);
        centralwidget->setObjectName("centralwidget");
        chatTextEdit = new QTextEdit(centralwidget);
        chatTextEdit->setObjectName("chatTextEdit");
        chatTextEdit->setGeometry(QRect(10, 10, 400, 200));
        chatTextEdit->setReadOnly(true);
        messageLineEdit = new QLineEdit(centralwidget);
        messageLineEdit->setObjectName("messageLineEdit");
        messageLineEdit->setGeometry(QRect(10, 220, 301, 26));
        sendButton = new QPushButton(centralwidget);
        sendButton->setObjectName("sendButton");
        sendButton->setGeometry(QRect(320, 220, 88, 26));
        ClientChat->setCentralWidget(centralwidget);
        menubar = new QMenuBar(ClientChat);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 424, 23));
        ClientChat->setMenuBar(menubar);
        statusbar = new QStatusBar(ClientChat);
        statusbar->setObjectName("statusbar");
        ClientChat->setStatusBar(statusbar);

        retranslateUi(ClientChat);

        QMetaObject::connectSlotsByName(ClientChat);
    } // setupUi

    void retranslateUi(QMainWindow *ClientChat)
    {
        ClientChat->setWindowTitle(QCoreApplication::translate("ClientChat", "ClientChat", nullptr));
        messageLineEdit->setPlaceholderText(QCoreApplication::translate("ClientChat", "Type a message...", nullptr));
        sendButton->setText(QCoreApplication::translate("ClientChat", "Send", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ClientChat: public Ui_ClientChat {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CLIENTCHAT_H
