#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "network_ra.h"

#define USAGE "encryptedDataServer (0=signature, 1=encrypted)"
void* SocketHandler(void*);

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
        if((bytecount = recv(hsock, data, buffer_len, 0))== -1){
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
        if((bytecount = send(hsock, (char *) &data, buffer_len, 0))== -1){
                fprintf(stderr, "Error receiving data %d\n", errno);
                return -1;
        }
	//printf("Sent 0x%x\n", data);
        return 0;
}

ra_samp_request_header_t * receiveRequest (int hsock){
	int i=0;
	/*TYPE*/
	uint8_t type = '1';
	if(receiveUint8_t(hsock, &type)==-1){
		printf("\n Error with RECEIVE REQUEST TYPE");
		return 0;
	}
	/*SIZE*/
	uint32_t size = '0';
	if(receiveUint32_t(hsock, &size)==-1){
		printf("\n Error with RECEIVE REQUEST SIZE");
		return 0;
	}
	/*ALGIN*/
	uint8_t align [3] = {'1'};
	for(i=0; i<3; i++){
		if(receiveUint8_t(hsock, align+i)==-1){
		 	printf("\n Error with REVEIVE REQUEST ALIGN");
		 	return 0;
		}
	}
	/*BODY*/
	uint8_t body [size] = {'0'};
	for(i=0; i<size; i++){
		if(receiveUint8_t(hsock, &body[i])==-1){
		 	printf("\n Error with RECEIVE REQUEST BODY");
		 	return 0;
		}
	}
	ra_samp_request_header_t *data_full = (ra_samp_request_header_t*) calloc (1,sizeof(ra_samp_request_header_t)+sizeof(uint8_t [size]));
	data_full->type=type;
	//printf("type %d\n", data_full->type);
	data_full->size=size;
	//printf("size %d\n", data_full->size);
	data_full->align[0]=align[0];
	data_full->align[1]=align[1];
	data_full->align[2]=align[2];
	//printf("align %d\n", data_full->align[0]);
	//printf("align %d\n", data_full->align[1]);
	//printf("align %d\n", data_full->align[2]);
	for(i=0; i<size; i++){
		data_full->body[i]=body[i];
		//printf("body 0x%x\n", data_full->body[i]);
	}
	return data_full;
}

int sendRespone (int hsock, ra_samp_response_header_t *data){
	int i=0;
	/*TYPE*/
	if(sendUint8_t(hsock, data->type)==-1){
		printf("\n Error with SEND RESPONSE TYPE");
		return -1;
	}
	/*STATUS*/
	for(i=0; i<2; i++){
		if(sendUint8_t(hsock, data->status[i])==-1){
		 	printf("\n Error with SEND RESPONSE STATUS");
		 	return -1;
		}
	}
	/*SIZE*/
	if(sendUint32_t(hsock, data->size)==-1){
		printf("\n Error with SEND RESPONSE SIZE");
		return -1;
	}
	/*ALGIN*/
	for(i=0; i<1; i++){
		if(sendUint8_t(hsock, data->align[i])==-1){
		 	printf("\n Error with SEND RESPONSE ALIGN");
		 	return -1;
		}
	}
	/*BODY*/
	for(i=0; i<data->size; i++){
		if(sendUint8_t(hsock, data->body[i])==-1){
		 	printf("\n Error with SEND RESPONSE BODY");
		 	return -1;
		}
	}
	return 0;
}

int main(int argc, char * argv[])
{
	int host_port= 1101;
	struct sockaddr_in my_addr;
	int hsock;
	int * p_int ;
	int err;
	socklen_t addr_size = 0;
	int* csock;
	sockaddr_in sadr;
	pthread_t thread_id=0;
	if(argc<2) {
		printf("%s\n", USAGE);
		return 0;
	}
	if(*argv[1]=='1') {
		if(!setEncrypted()){
			printf("Error with setting Encrypted boolean\n");
			return 0;
		}
		printf("Server started ENCRYPTION MODE\n");
	}
	else{
		printf("Server started SIGNATURE MODE\n");
	}
	hsock = socket(AF_INET, SOCK_STREAM, 0);
	if(hsock == -1){
		printf("Error initializing socket %d\n", errno);
		goto FINISH;
	}
	p_int = (int*)malloc(sizeof(int));
	*p_int = 1;
	if( (setsockopt(hsock, SOL_SOCKET, SO_REUSEADDR, (char*)p_int, sizeof(int)) == -1 )||
		(setsockopt(hsock, SOL_SOCKET, SO_KEEPALIVE, (char*)p_int, sizeof(int)) == -1 ) ){
			printf("Error setting options %d\n", errno);
			free(p_int);
			goto FINISH;
	}
	free(p_int);
	my_addr.sin_family = AF_INET ;
	my_addr.sin_port = htons(host_port);
	memset(&(my_addr.sin_zero), 0, 8);
	my_addr.sin_addr.s_addr = INADDR_ANY ;
	if( bind( hsock, (sockaddr*)&my_addr, sizeof(my_addr)) == -1 ){
		fprintf(stderr,"Error binding to socket, make sure nothing else is listening on this port %d\n",errno);
		goto FINISH;
	}
	if(listen( hsock, 10) == -1 ){
		fprintf(stderr, "Error listening %d\n",errno);
		goto FINISH;
	}
	//Now lets do the server stuff
	addr_size = sizeof(sockaddr_in);
	while(true){
		printf("waiting for a connection\n");
		csock = (int*)malloc(sizeof(int));
		if((*csock = accept( hsock, (sockaddr*)&sadr, &addr_size))!= -1){
			printf("---------------------\nReceived connection from %s\n",inet_ntoa(sadr.sin_addr));
			pthread_create(&thread_id,0,&SocketHandler, (void*)csock );
			pthread_detach(thread_id);
		}
		else{
			fprintf(stderr, "Error accepting %d\n", errno);
		}
	}
FINISH:
;
}

void * SocketHandler(void* lp){
	int ret = 0;
	int *csock = (int*)lp;
	int bytecount;
	do{
		ra_samp_response_header_t *bufferForResponse = NULL;
		ra_samp_request_header_t *bufferForRequest = NULL;
		bufferForRequest=receiveRequest(*csock);
		//printf("\n\t----REQUEST RECEIVED-------\n");
		//if(bufferForRequest==NULL||bufferForRequest==0) printf("The request buffer is NULL\n\n");
		ret = ra_network_send_receive("someText",bufferForRequest, &bufferForResponse);
        if(ret==-1){
                printf("\nError, ra_network_send_receive\n");
                ret=6;
        }
		//if(bufferForResponse==NULL) printf("The buffer is NULL\n\n");
        if(bufferForRequest->type!=TYPE_RA_MSG0 && bufferForRequest->type!=TYPE_RA_PK)
		{
			sendRespone(*csock, bufferForResponse);
		}
	}while(ret<4);
FINISH:
	free(csock);
	return 0;
}
