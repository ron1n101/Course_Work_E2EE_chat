#ifndef MESSAGETYPE_H
#define MESSAGETYPE_H
#include "qtypes.h"
enum class MessageType : quint8
{
    USERNAME_INIT,
    USERNAME_READY,
    CHAT_MSG,
    PUBLIC_KEY,
    DATA_MESSAGE,
    PUBLIC_KEY_RECEIVED,
    UNKNOW_MESSAGE

};

#endif // MESSAGETYPE_H
