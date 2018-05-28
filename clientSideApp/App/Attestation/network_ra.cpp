/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */



#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "network_ra.h"

int host_port= 1101;
const char* host_name="127.0.0.1";
struct sockaddr_in my_addr;
int hsock;

/*Functions to get and receive data through the socket hsock*/
int receiveUint8_t(int hsock, uint8_t *data){
    int bytecount;
    int buffer_len = 1;
    memset(data, 0, buffer_len);
    if((bytecount = recv(hsock, (char *) data, buffer_len, 0))== -1){
        fprintf(stderr, "Error receiving data %d\n", errno);
        return -1;
    }
    return 0;
}

int receiveUint32_t(int hsock, uint32_t *data){
    int bytecount;
    int buffer_len = 2;
    memset(data, 0, buffer_len);
    if((bytecount = recv(hsock, (char *) data, buffer_len, 0))== -1){
        fprintf(stderr, "Error receiving data %d\n", errno);
        return -1;
    }
    return 0;
}

int sendUint8_t(int hsock, uint8_t data){
    int bytecount;
    int buffer_len = 1;
    if((bytecount = send(hsock, (char *) &data, buffer_len, 0))== -1){
        fprintf(stderr, "Error receiving data %d\n", errno);
        return -1;
    }
    //printf("Sent 0x%x\n", data);
    return 0;
}

int sendUint32_t(int hsock, uint32_t data){
    int bytecount;
    int buffer_len = 2;
    if((bytecount = send(hsock, &data, buffer_len, 0))== -1){
        fprintf(stderr, "Error receiving data %d\n", errno);
        return -1;
    }
    //printf("Sent 0x%x\n", data);
    return 0;
}
/*SEND REQUEST*/
/*
    Send request message to the Service Provider.
    Input:  int hsock -> socket to the Service Provider
            const ra_samp_request_header_t *data -> pointer to the data to be sent
    Output: int -> 0 if correct, -1 if incorrect
*/
int sendRequest (int hsock, const ra_samp_request_header_t *data){
    int i=0;
    /*TYPE*/
    //printf("Sending TYPE\n");
    if(sendUint8_t(hsock, data->type)==-1){
        printf("\n Error with SEND REQUEST TYPE");
        return -1;
    }
    /*SIZE*/
    //printf("Sending SIZE\n");
    if(sendUint32_t(hsock, data->size)==-1){
        printf("\n Error with SEND REQUEST SIZE");
        return -1;
    }
    /*ALGIN*/
    //printf("Sending ALIGN\n");
    for(i=0; i<3; i++){
        if(sendUint8_t(hsock, data->align[i])==-1){
            printf("\n Error with SEND REQUEST ALIGN");
            return -1;
        }
    }
    /*BODY*/
    //printf("Sending BODY\n");
    for(i=0; i<data->size; i++){
        if(sendUint8_t(hsock, data->body[i])==-1){
            printf("\n Error with SEND REQUEST BODY");
            return -1;
        }
    }
    return 0;
}

/*RECEIVE RESPONSE*/
/*
    Receive response message from the Service Provider.
    Input: int hsock -> socket to the Service Provider
    Output: ra_samp_response_header_t * -> pointer to the response message where data will be stored
*/
ra_samp_response_header_t * receiveResponse (int hsock){
    int i=0;
    /*TYPE*/
    uint8_t type = '1';
    if(receiveUint8_t(hsock, &type)==-1){
        printf("\n Error with RECEIVE RESPONSE TYPE");
        return 0;
    }
    /*STATUS*/
    uint8_t status [2] = {'1'};
    for(i=0; i<2; i++){
        if(receiveUint8_t(hsock, status+i)==-1){
            printf("\n Error with REVEIVE RESPONSE STATUS");
            return 0;
        }
    }
    /*SIZE*/
    uint32_t size = '0';
    if(receiveUint32_t(hsock, &size)==-1){
        printf("\n Error with RECEIVE RESPONSE SIZE");
        return 0;
    }
    /*ALGIN*/
    uint8_t align [1] = {'1'};
    for(i=0; i<1; i++){
        if(receiveUint8_t(hsock, &align[i])==-1){
            printf("\n Error with REVEIVE RESPONSE ALIGN");
            return 0;
        }
    }
    /*BODY*/
    uint8_t body [size] = {'0'};
    for(i=0; i<size; i++){
        if(receiveUint8_t(hsock, &body[i])==-1){
            printf("\n Error with RECEIVE RESPONSE BODY");
            return 0;
        }
    }
    ra_samp_response_header_t *data_full = (ra_samp_response_header_t*) calloc (1,sizeof(ra_samp_response_header_t)+sizeof(uint8_t [size]));
    data_full->type=type;
    //printf("type %d\n", data_full->type);
    data_full->status[0]=status[0];
    data_full->status[1]=status[1];
    //printf("status %d\n", data_full->status[0]);
    //printf("status %d\n", data_full->status[1]);
    data_full->size=size;
    //printf("size %d\n", data_full->size);
    data_full->align[0]=align[0];
    //printf("align %d\n", data_full->align[0]);
    for(i=0; i<size; i++){
        data_full->body[i]=body[i];
        //printf("body 0x%x\n", data_full->body[i]);
    }
    return data_full;
}

/*RA FREE NETWORK RESPONSE BUFFER*/
/*
    Free memory area.
    Input:  ra_samp_response_header_t *resp -> pointer to the area to be freed
    Output: 
*/
void ra_free_network_response_buffer(ra_samp_response_header_t *resp)
{
    if(resp!=NULL)
    {
        free(resp);
    }
}

/*RA NETWORK SEND RECEIVE*/
/*
    Manage the message exchange
    Input:  const char *server_url -> url of the server to be contacted (not used in this development)
    Output: int -> 0 if correct
*/
int ra_network_send_receive(const char *server_url,
    const ra_samp_request_header_t *p_req,
    ra_samp_response_header_t **p_resp)
{
    int ret=0;
    
    int size=0;
    sendRequest(hsock, p_req);
    if(p_req->type!=TYPE_RA_MSG0 && p_req->type!=TYPE_RA_PK){
        *p_resp=receiveResponse(hsock); 
    }
    return ret;
}

/*INITIALIZE CONNECTION*/
/*
    Initialize the connection socket to the Service Provider
    Input:  
    Output: int -> 0 if correct, -1 if incorrect
*/
int initialize_connection(){
    int * p_int;
    int err;
    hsock = socket(AF_INET, SOCK_STREAM, 0);
    if(hsock == -1){
        printf("Error initializing socket %d\n",errno);
        return -1;
    }
    p_int = (int*)malloc(sizeof(int));
    *p_int = 1;
    if( (setsockopt(hsock, SOL_SOCKET, SO_REUSEADDR, (char*)p_int, sizeof(int)) == -1 )||
        (setsockopt(hsock, SOL_SOCKET, SO_KEEPALIVE, (char*)p_int, sizeof(int)) == -1 ) ){
            printf("Error setting options %d\n",errno);
            free(p_int);
            return -1;
        }
    free(p_int);
    my_addr.sin_family = AF_INET ;
    my_addr.sin_port = htons(host_port);
    memset(&(my_addr.sin_zero), 0, 8);
    my_addr.sin_addr.s_addr = inet_addr(host_name);
    if( connect( hsock, (struct sockaddr*)&my_addr, sizeof(my_addr)) == -1 ){
        if((err = errno) != EINPROGRESS){
            fprintf(stderr, "Error connecting socket %d\n", errno);
            return -1;
        }
    }
    return 0;
}

/*CLOSE CONNECTION*/
/*
    Closes connection to the Service Provider
    Input: 
    Output:
*/
void close_connection(){
    close(hsock);
}