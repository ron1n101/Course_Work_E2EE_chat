/********************************************************************************
** Form generated from reading UI file 'ClientLogin.ui'
**
** Created by: Qt User Interface Compiler version 6.5.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_CLIENTLOGIN_H
#define UI_CLIENTLOGIN_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_ClientLogin
{
public:
    QLineEdit *userNameLineEdit;
    QPushButton *loginButton;

    void setupUi(QWidget *ClientLogin)
    {
        if (ClientLogin->objectName().isEmpty())
            ClientLogin->setObjectName("ClientLogin");
        ClientLogin->resize(320, 240);
        userNameLineEdit = new QLineEdit(ClientLogin);
        userNameLineEdit->setObjectName("userNameLineEdit");
        userNameLineEdit->setGeometry(QRect(20, 50, 280, 30));
        loginButton = new QPushButton(ClientLogin);
        loginButton->setObjectName("loginButton");
        loginButton->setGeometry(QRect(110, 100, 100, 30));

        retranslateUi(ClientLogin);

        QMetaObject::connectSlotsByName(ClientLogin);
    } // setupUi

    void retranslateUi(QWidget *ClientLogin)
    {
        ClientLogin->setWindowTitle(QCoreApplication::translate("ClientLogin", "Login", nullptr));
        userNameLineEdit->setPlaceholderText(QCoreApplication::translate("ClientLogin", "Enter your username", nullptr));
        loginButton->setText(QCoreApplication::translate("ClientLogin", "Login", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ClientLogin: public Ui_ClientLogin {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_CLIENTLOGIN_H
