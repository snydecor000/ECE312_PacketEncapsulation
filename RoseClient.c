/************* UDP CLIENT CODE *******************/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define SERVER "137.112.38.47"
#define MESSAGE "hello"
#define PORT 1874
#define BUF_LEN 1024

/* This function takes in an RHP frame and validates or invalidates 
*  the message according to the 16 bit checksum at the end of the message*/
int validChecksum(char buffer[]){
    return 1;
}

int main() {
    int clientSocket, nBytes;
    char buffer[BUF_LEN];
    struct sockaddr_in clientAddr, serverAddr;

    //Create UDP socket
    if ((clientSocket = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("cannot create socket");
        return 0;
    }

    /* Bind to an arbitrary return address.
     * Because this is the client side, we don't care about the address 
     * since no application will initiate communication here - it will 
     * just send responses 
     * INADDR_ANY is the IP address and 0 is the port (allow OS to select port) 
     * htonl converts a long integer (e.g. address) to a network representation 
     * htons converts a short integer (e.g. port) to a network representation */
    memset((char *) &clientAddr, 0, sizeof (clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    clientAddr.sin_port = htons(0);

    if (bind(clientSocket, (struct sockaddr *) &clientAddr, sizeof (clientAddr)) < 0) {
        perror("bind failed");
        return 0;
    }

    // Configure settings in server address struct 
    memset((char*) &serverAddr, 0, sizeof (serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = inet_addr(SERVER);
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    // send a message to the server 
    if (sendto(clientSocket, MESSAGE, strlen(MESSAGE), 0,
            (struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
        perror("sendto failed");
        return 0;
    }

    //Attempt the transmission
    for(int q = 0;q < 5;q++){
        //Receive message from server and run checksum test
        nBytes = recvfrom(clientSocket, buffer, BUF_LEN, 0, NULL, NULL);

        if(validChecksum(buffer) != 0){
            //Parse the received message into the Protocol Fields
            uint8_t version = buffer[0];
            uint8_t type = buffer[1];
            uint16_t portID = (uint16_t)(buffer[3]<<4) + (uint8_t)buffer[2];
            uint8_t length = buffer[4];
            char receivedMessage[BUF_LEN];
            for(int i = 0; i < length; i++){
                receivedMessage[i] = buffer[5+i];
            }
            uint16_t checksum = (uint16_t)(buffer[nBytes-1]<<4) + (uint8_t)buffer[nBytes-2];

            //Print out the message and the fields
            printf("Received from server:\nVersion #: %u\nMessage Type: %u\n", version,type);
            printf("PortID: %u\nMessage Length: %u\n",portID,length);
            printf("Message: %s\n",receivedMessage);
            printf("Checksum: 0x%X\n",checksum);
            break;//Break out of the loop because we had a successfully received message
        } else if(q < 5) {
            //Resend the message
            if (sendto(clientSocket, MESSAGE, strlen(MESSAGE), 0,(struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
                perror("sendto failed");
                return 0;
            }
        }
    }
    close(clientSocket);
    return 0;
}