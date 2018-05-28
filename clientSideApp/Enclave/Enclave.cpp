extern "C" {
	#include "MuJS/mujs.h"
} 
#include <string.h>
#include "Enclave.h"
#include "Enclave_t.h"
#include "Crypto.h"

/*ECALL INIT MUJS*/
/*
    Main function of the Enclave. Controls the process, recovering the JAVASCRIPT values, running the code and returning the answer for the web page.
    Input:  const char * data -> JSON like string witht the JAVASCRIPT properties.
    Output: sgx_status_t -> Enclave status, depending on whether errors occurred during the execution or not
*/
sgx_status_t ecall_init_MuJS(const char * data)
{
    javaScriptData * jsData;
    sgx_status_t ret = SGX_SUCCESS;
    const char * retMUJS;
    int retSignature = 0;
    int retEncryption=0;
    std::string messageChrome;

    /*Get the struct containing all the properties given in the JSON string*/
    jsData=getJavaScriptData(data);
    if (data == NULL ) {
        return SGX_ERROR_UNEXPECTED;
    }

    /*If it is encryption mode, decrypt the data first*/
    if(isEncrypted()){
        std::string encryptedString = std::string(jsData->encryption.begin(), jsData->encryption.end());
        std::vector <uint8_t> codeHex;

        /*Get the hex values from a string into a uint8_t vector*/
        retEncryption = getEncryptionFromString(encryptedString, &codeHex);
        if(retEncryption==0){
            return SGX_ERROR_UNEXPECTED;
        }

        /*Separate the secret from the MAC value*/
        std::vector <uint8_t> functionHexEncrypted;
        for(int i=0; i<codeHex.size()-16; i++){
            functionHexEncrypted.push_back(codeHex[i]);
        }
        
        uint8_t mac [16] = {0};
        for(int i=0; i<16; i++){
            mac[i]=codeHex[functionHexEncrypted.size()+i];
        }

        /*Decrypt the secret*/
        std::vector <uint8_t> functionHexDecrypted;
        retEncryption = decryptSecret(functionHexEncrypted, functionHexEncrypted.size(), mac, &functionHexDecrypted);
        if(retEncryption==0) {          
            return SGX_ERROR_UNEXPECTED;
        } else if (retEncryption==-1){
            return SGX_ERROR_UNEXPECTED;
        }

        /*Cast the decrypted value from hex to ASCII*/
        std::vector <char> text;
        for(int i=0; i<functionHexDecrypted.size(); i++){
            text.push_back((char) functionHexDecrypted[i]);
        }
        
        /*Separate the function code from the MAINFUNCTION value*/
        std::string full_text = std::string(text.begin(), text.end());
        std::size_t lastFound = full_text.find_last_of(";");
        std::string code_text = full_text.substr(0, lastFound);
        std::string mainFunction_text = full_text.substr(lastFound+1);
        for(int i=0;i<code_text.length();i++){
            jsData->code.push_back(code_text[i]);
        }
        for(int i=0;i<mainFunction_text.length();i++){
            jsData->functionName.push_back(mainFunction_text[i]);
        }
    }
    
    /*Get signature from string to uint32_t hex values*/
    std::string signatureString = std::string(jsData->signature.begin(), jsData->signature.end());
    sgx_ec256_signature_t * p_signature = new (sgx_ec256_signature_t);
    retSignature = getSignatureFromString(signatureString, p_signature);
    if(retSignature==0){
        return SGX_ERROR_UNEXPECTED;
    }

    /*Check signature (code;functionName)*/
    std::string toVerify = std::string(jsData->code.begin(), jsData->code.end());
    toVerify += std::string(jsData->mainFunctionName.begin(), jsData->functionName.end());
    retSignature=checkSignature(toVerify, p_signature);
    if(retSignature==0) {
        return SGX_ERROR_UNEXPECTED;
    } else if (retSignature==-1){
        return SGX_ERROR_UNEXPECTED;
    }

    /*Start MuJS*/
    js_State *J = js_newstate(NULL, NULL, JS_STRICT);
    /*Load scripts*/
    js_loadstring(J, "", std::string(jsData->code.begin(), jsData->code.end()).c_str());
    js_pushglobal(J);    
    js_call(J, 0); /* execute the script function that defines mainFunction */        
    js_getglobal(J, std::string(jsData->functionName.begin(), jsData->functionName.end()).c_str()); /* get the  mainFunction object */ 
    js_pushglobal(J);
    /*Push variables to MuJS*/
    for(int i=0; i<(jsData->vars.size()); i++) {
            std::string variable = std::string(jsData->vars[i].value.begin(), jsData->vars[i].value.end());
            if( jsData->vars[i].type == TYPE_INT ){
                    js_pushnumber(J, a2d(variable.c_str()));
            }
            else if( jsData->vars[i].type == TYPE_STRING) {
                    js_pushstring(J, variable.c_str());
            }
            else if( jsData->vars[i].type == TYPE_BOOLEAN) {
                    if( variable.compare("true") == 0 ){
                            js_pushboolean(J, 1);
                    }
                    else if( variable.compare("false") == 0 ){
                            js_pushboolean(J, 0);
                    }
                    else {
                        return SGX_ERROR_UNEXPECTED;
                    }
            }
            else{ 
                return SGX_ERROR_UNEXPECTED;
            }
    }
    js_call(J, jsData->vars.size()); /* call with data->vars.size() arguments */
    retMUJS = js_tostring(J, -1); /* read return value */
    /*Modify the result to JSON like string*/
    messageChrome = createJSONresponse(std::string(retMUJS));
    if(messageChrome=="") {
        return SGX_ERROR_UNEXPECTED;
    }
    /*Send the result to the web page*/
    ocall_outputMuJS(messageChrome.c_str());
    js_pop(J, 1); /* pop return value to clean up stack */
    js_freestate(J);
    return ret;
}

/*A2D*/
/*
    Transforms a given number in string format to double.
    Input:  const char *s -> string with the number.
    Output: double -> number of the string in double format
*/
double a2d(const char *s)
{
        double sign=1;
        double num=0; 
        if(*s == '-') {
                sign = -1;
                s++;
        }
        while(*s)
        {
                num=((*s)-'0')+num*10;
                s++;
        }
        return num*sign;
}

/*A2I*/
/*
    Transforms a given number in string format to int.
    Input:  const char *s -> string with the number.
    Output: int -> number of the string in int format
*/
int a2i(const char *s)
{
        int sign=1;
        int num=0;
        if(*s == '-') {
                sign = -1;
                s++;
        }
        while(*s)
        {
                num=((*s)-'0')+num*10;
                s++;
        }
        return num*sign;
}

/*UINT32TOA*/
/*
    Transforms a given vector of numbers in uint32_t (hex) format to ASCII values.
    Input:  uint32_t data -> vector of values to transform to ASCII.
    Output: std::vector<char> *string -> vector of characters generated from the hex values
*/
void uint32toa(uint32_t data, std::vector<char> *string) {
  int8_t i;
  char array [10];
  for(int i=0; i<10; i++){
    array[i]='n';
  }
  array[0]='0';
  array[1]='x';                     
  for(i=9; i>=2 && data>0; i--) {
    if(data%16<10) 
    {
      array[i]=(char) ((data % 16) +'0');
    }
    else{  
      array[i]=(char) ((data % 16) +'W');
    }
    data /= 16;
  }
  for(int i=0;i<10;i++){
    if(array[i]!='n') string->push_back(array[i]);
  }
}

/*UINT8TOA*/
/*
    Transforms a given vector of numbers in uint8_t (hex) format to ASCII values.
    Input:  uint8_t data -> vector of values to transform to ASCII.
    Output: std::vector<char> *string -> vector of characters generated from the hex values
*/
void uint8toa(uint8_t data, std::vector<char> *string) {
  int8_t i;
  char array [4];
  for(int i=0; i<4; i++){
    array[i]='n';
  }
  array[0]='0';
  array[1]='x';                     
  for(i=3; i>=2 && data>0; i--) {
    if(data%16<10) 
    {
      array[i]=(char) ((data % 16) +'0');
    }
    else{  
      array[i]=(char) ((data % 16) +'W');
    }
    data /= 16;
  }
  for(int i=0;i<4;i++){
    if(array[i]!='n') string->push_back(array[i]);
  }
}

/*GET VARIABLE INFO*/
/*
    Given a JSON like string with VARIABLE properties (ORDER, TYPE, VALUE), return a vector of "variable" format with all the properties set.
    Input:  std::string variables -> JSON like string with VARIABLE properties
    Output: std::vector<variable> * -> vector of variable generated from the string values, 
                                        if any property missing or error in the JSON formatting NULL pointer returned
*/
std::vector<variable> * getVariableInfo(std::string variables)
{
    bool wordFound = false, typeAux=false, orderAux=false, valueAux=false;
    int countWord=0, countVariable=0;
    int order=-1, type=-1;
    std::string variableInfo, word ="", str="";
    std::vector<variable> * returnValue = new (std::vector<variable>);
    for(int e=0; e<variables.length(); e++){
        if(variables[e]=='{'){
            countVariable=0;
            while( ((e+countVariable)<variables.length()) && (variables[e+countVariable]!='}') ){
                countVariable++;
            }
            variableInfo = variables.substr(e, countVariable);

            variable * returnVariable = new (variable);
            for(int i=0; i<variableInfo.length(); i++){
                if(variableInfo[i]=='"'){
                    i++;
                    if(!wordFound){
                        countWord=0;
                        while( ((i+countWord)<variableInfo.length()) && (variableInfo[i+countWord]!='"') ){
                            countWord++;
                        }
                        word = variableInfo.substr(i, countWord);
                        wordFound=true;
                    }
                    else{
                        countWord=0;
                        while( ((i+countWord)<variableInfo.length()) && (variableInfo[i+countWord]!='"') ){
                            countWord++;
                        }
                        str = variableInfo.substr(i, countWord);
                        /*ORDER*/
                        if( word.compare(ORDER) == 0 ){
                            returnVariable->order=a2i(str.c_str());
                            orderAux = true;
                        }
                        /*TYPE*/
                        else if( word.compare(TYPE) == 0 ){
                                if( str.compare(valueINT) == 0 ) returnVariable->type=TYPE_INT;
                                else if( str.compare(valueSTR) == 0 ) returnVariable->type=TYPE_STRING;
                                else if( str.compare(valueBOOL) == 0 ) returnVariable->type=TYPE_BOOLEAN;
                                else return NULL;
                                typeAux = true;
                        /*VALUE*/
                        }
                        else if( word.compare(VALUE) == 0 ){
                                std::copy(str.begin(), str.end(), std::back_inserter(returnVariable->value));
                                valueAux = true;
                        }
                        else{
                                return NULL;
                        }
                        wordFound=false;
                    }
                    i+=countWord;
                }
            }
            if( !valueAux || !typeAux || !orderAux ){
                return NULL;
            }
            returnValue->push_back(*returnVariable);
            valueAux=false;
            typeAux=false;
            orderAux=false;
        }
    }

    if(returnValue->size()==0) return NULL;
    return returnValue;
}

/*GET JAVASCRIPT DATA*/
/*
    Given a JSON like string with JAVASCRIPT properties (CODE, SIGNATURE, ENCRYPTION, MAINFUNCTION, VARIABLES), return a pointer to a "javaScriptData" format with all the properties set.
    Input:  std::string jsonData -> JSON like string with JAVASCRIPT properties
    Output: javaScriptData * -> pointer to the struct containing all the properties given in the JSON string, 
                                        if any property missing or error in the JSON formatting NULL pointer returned
*/
javaScriptData * getJavaScriptData(std::string jsonData){
        javaScriptData * returnValue = new (javaScriptData);
        bool nameFound = false, variableExpected=false, codeAux=false, signatureAux=false, functionNameAux=false, encryptionAux=false;
        std::string name = "", str = "";
        int countWord=0;
        for (int i = 0; i < jsonData.length(); i++){
            if(jsonData[i]=='"' && !variableExpected){
                i++;
                if(!nameFound){
                    countWord=0;
                    while( ((i+countWord)<jsonData.length()) && (jsonData[i+countWord]!='"') ){
                        countWord++;
                    }
                    name = jsonData.substr(i, countWord);

                    nameFound=true;
                    /*VARIABLE*/
                    if( name.compare(variableName) == 0 ) variableExpected=true;
                }
                else{
                    countWord=0;
                    while( ((i+countWord)<jsonData.length()) && (jsonData[i+countWord]!='"') ){
                        countWord++;
                    }
                    str = jsonData.substr(i, countWord);
                    /*CODE*/
                    if( name.compare(codeName) == 0 ){
                        if(isEncrypted()) return NULL;
                        std::copy(str.begin(), str.end(), std::back_inserter(returnValue->code));
                        codeAux = true;
                    }
                    /*MAINFUNCTION*/
                    else if( name.compare(mainFunctionName) == 0 ){
                        if(isEncrypted()) return NULL;
                        std::copy(str.begin(), str.end(), std::back_inserter(returnValue->functionName));
                        functionNameAux = true;
                    }
                    /*SIGNATURE*/
                    else if( name.compare(signatureName) == 0 ){
                        std::copy(str.begin(), str.end(), std::back_inserter(returnValue->signature));
                        signatureAux = true;
                    }
                    /*ENCRYPTION*/
                    else if( name.compare(encryptionName) == 0 ){
                        if(!isEncrypted()) return NULL;
                        std::copy(str.begin(), str.end(), std::back_inserter(returnValue->encryption));
                        encryptionAux = true;
                    }
                    else {
                        return NULL;
                    }
                    nameFound=false;
                }
                i+=countWord;
            }
            /*VARIABLE PROPERTIES*/
            else if( jsonData[i]=='[' && variableExpected ){
                i++;
                countWord=0;
                while( ((i+countWord)<jsonData.length()) && (jsonData[i+countWord]!=']') ){
                        countWord++;
                }
                str = jsonData.substr(i, countWord);
                std::vector<variable> * aux = getVariableInfo(str);
                if(aux == NULL){
                    return NULL;
                }
                if(aux->size()==0){
                    return NULL;
                }
                for(int e=0; e<aux->size(); e++){
                    returnValue->vars.push_back((*aux)[e]);
                }
                variableExpected=false;
                nameFound=false;
                i+=countWord;
            }
        }
        if(!isEncrypted())
        {
            /*CODE, SIGNATURE AND MAINFUNCTION required*/
            if( !codeAux || !signatureAux || !functionNameAux ) 
                return NULL;
        }
        else
        {
            /*ENCRYPTION AND SIGNATURE REQUIRED*/
            if( !encryptionAux || !signatureAux)
                return NULL;
        }
        /*Order the variables by ORDER property*/
        std::sort(returnValue->vars.begin(), returnValue->vars.end(), orderVariables());
        /*Check there exists a variable per ORDER value (0,1,2,3,...)*/
        for (int i=0; i<returnValue->vars.size(); i++){
                if(returnValue->vars[i].order!=i) return NULL;
        }
        return returnValue;
}

/*CREATE JSON RESPONSE*/
/*
    Generates the JSON like string (Encrypted/Signed) to be sent to the web page.
    Input:  std::string value -> value to be added to the JSON like string.
    Output: std::string -> string containin a JSON like value
*/
std::string createJSONresponse(std::string value){
        int ret = 0;
        sgx_ec256_signature_t * output = new (sgx_ec256_signature_t);
        
        /*Sign value*/
        ret=signData(value, output);
        if(ret==0){
            return "";
        }
        
        /*Signature values to string*/
        std::vector <char> signature_vector;
        for(int i=0; i<8; i++){
            uint32toa(output->x[i], &signature_vector);
        }
        for(int i=0; i<8; i++){
            uint32toa(output->y[i], &signature_vector);
        }
        std::string signature = std::string(signature_vector.begin(), signature_vector.end());
        
        /*If it is encryption mode, also encrypt the value*/
        if(isEncrypted())
        {
            std::vector <uint8_t> textHexDecrypted;
            std::vector <uint8_t> textHexEncrypted;
            int value_len = value.length();
            /*Fill the uint8_t vector with the value chars casted to hex values*/
            for(int i=0; i<value_len;i++){
                textHexDecrypted.push_back((uint8_t) value[i]);
            }

            /*Encrypt value*/
            ret = encryptPlaintext(textHexDecrypted, &textHexEncrypted);
            if(ret==0){
                return "";
            }
            if(ret==-1){
                return "";
            }

            /*Encrypted value to string*/
            std::vector <char> encryption_vector;
            for(int i=0; i<textHexEncrypted.size(); i++){
                uint8toa(textHexEncrypted[i], &encryption_vector);
            }
            std::string encryption = std::string(encryption_vector.begin(), encryption_vector.end());
            
            /*Return the JSON like function for encryption mode*/
            return "{\"ENCRYPTION\":\""+encryption+"\",\"SIGNATURE\":\""+signature+"\"}";
        }
        else
        {
            /*Return the JSON like function for signature mode*/
            return "{\"VALUE\":\""+value+"\",\"SIGNATURE\":\""+signature+"\"}";
        }
}

/*GET SIGNATURE FROM STRING*/
/*
    Convert a string with hex values (0x) to a signature struct
    Input:  std::string signatureData -> string containing the hex values.
    Output: int -> 1 if correct, 0 if error
            sgx_ec256_signature_t * output -> pointer to the signature with all the values, the struct must be initialized by the caller
*/
int getSignatureFromString(std::string signatureData, sgx_ec256_signature_t * output)
{
    std::string hex;
    bool found=false;
    int countFoundx = 0, countFoundy=0;
    int start=0;
    for(int i=1; i<signatureData.length();i++){
        if(signatureData.substr(i-1,2).compare("0x")==0){
            start=i+1;
            i++;
            while(signatureData.substr(i-1,2).compare("0x")!=0 &&
                            i<=signatureData.length()) 
                i++;
            hex=signatureData.substr(start, i-1-start);
            if(countFoundx< (sizeof(output->x)/sizeof(output->x[0])) ){
                output->x[countFoundx] = (uint32_t) strtol(hex.c_str(), NULL, 16);
                countFoundx++;
            }
            else if (countFoundy<(sizeof(output->y)/sizeof(output->y[0])) ) {
                output->y[countFoundy] = (uint32_t) strtol(hex.c_str(), NULL, 16);
                countFoundy++;
            }
            else {
                i=signatureData.length()+1;
            }
            if(!found) found=true;
            i--;
        }
    }
    if(!found) return 0;
    return 1;
}

/*GET ENCRYPTION FROM STRING*/
/*
    Convert a string with hex values (0x) to a uint8_t vector
    Input:  std::string code -> string containing the hex values.
    Output: int -> 1 if correct, 0 if error
            std::vector <uint8_t> * codeHex -> pointer to the vector with all the values, the vector must be initialized by the caller
*/
int getEncryptionFromString(std::string code, std::vector <uint8_t> * codeHex)
{
    std::string hex;
    bool found=false;
    int start=0;
    for(int i=1; i<code.length();i++){
        if(code.substr(i-1,2).compare("0x")==0){
            start=i+1;
            i++;
            while(code.substr(i-1,2).compare("0x")!=0 &&
                            i<=code.length()) 
                i++;
            hex=code.substr(start, i-1-start);
            codeHex->push_back((uint8_t) strtol(hex.c_str(), NULL, 16));
            if(!found) found=true;
            i--;
        }
    }
    if(!found) return 0;
    return 1;
}