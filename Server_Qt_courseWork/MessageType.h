#ifndef MESSAGETYPE_H
#define MESSAGETYPE_H
#include "qtypes.h"
enum class MessageType : quint8
{
    USERNAME_INIT,
    CHAT_MSG,
    PUBLIC_KEY,
    DATA_MESSAGE,
    PUBLIC_KEY_RECEIVED,
    USERID_ASIGNED,
    USER_DISCONNECT,
    UNKNOW_MESSAGE

};

#endif // MESSAGETYPE_H
