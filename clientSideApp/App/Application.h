#ifndef _APPLICATION_H
#define _APPLICATION_H

#include <string.h>
#include <string>

void outputToFile(std::string str);
int sendMessageToExtension(std::string message);
int sendErrorMessageToExtension(std::string message);
std::string receiveMessageFromExtension();

#endif
