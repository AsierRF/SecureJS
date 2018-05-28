#ifndef _ENCLAVE_H
#define _ENCLAVE_H

#include <string.h>
#include <string>
#include <vector>
#include <algorithm>
#include "sgx_tcrypto.h"

/*FOR JSON STRINGS*/
/*DEFINE NAMES FOR VARIABLES, FUNCTION, CODE, ENCRYPTION, MAINFUNCTION for the accepted JAVASCRIPTDATA properties*/
#define variableName "VARIABLE"
#define codeName "CODE"
#define signatureName "SIGNATURE"
#define mainFunctionName "MAINFUNCTION"
#define encryptionName "ENCRYPTION"
/*DEFINE int, str, bool for the accepted variable types*/
#define valueINT "int"
#define valueSTR "str"
#define valueBOOL "bool"
/*DEFINE TYPE, ORDER AND VALUE for the accepted variable properties*/
#define TYPE "TYPE"
#define ORDER "ORDER"
#define VALUE "VALUE"

typedef enum variable_type
{
     TYPE_INT,
     TYPE_STRING,
     TYPE_BOOLEAN,
}variable_type;

typedef struct variable{
    int  order;     /* set to the number for ordering the variables*/
    int type;     /*set to one of the variable_type*/
	std::vector<char> value; /*set the value as char vector*/
}variable;

typedef struct javaScriptData
{
    std::vector<char> signature;
    std::vector<char> functionName;
    std::vector<char> code;
    std::vector<char> encryption;
    std::vector<variable> vars;
}javaScriptData;

struct orderVariables
{
    bool operator()(const variable& x, const variable& y) const
    {
        return x.order < y.order; 
    }
};

double a2d(const char *s);
int a2i(const char *s);
void uint32toa(uint32_t data, std::vector<char> *string);
void uint8toa(uint8_t data, std::vector<char> *string);
std::string createJSONresponse(std::string value);
std::vector<variable> * getVariableInfo(std::string variables);
javaScriptData * getJavaScriptData(std::string variableInfo);
int getSignatureFromString(std::string signatureData, sgx_ec256_signature_t * output);
int getEncryptionFromString(std::string code, std::vector <uint8_t> * codeHex);

#endif