/************* UDP CLIENT CODE *******************/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define SERVER "137.112.38.47"
#define MESSAGE "hello\0"
#define PORT 1874
#define BUF_LEN 1024

/* This function takes in an RHP frame and validates or invalidates 
*  the message according to the 16 bit checksum at the end of the message*/
int validChecksum(char buffer[],int numBytes){
    //convert the character array to an array of 16 bit values
    uint16_t newBuffer[numBytes/2];
    for(int i = 0;i < numBytes/2;i++){
        newBuffer[i] = (uint16_t)(buffer[2*i+1]<<8) + (uint8_t)buffer[2*i];
    }

    uint32_t sum = 0;//Value of the sum of all the 16 bit words in the frame

    for(int i = 0;i < numBytes/2;i++){
        sum = sum + newBuffer[i];
        //If there was an overflow, then add 1 to sum
        if(sum>>16 == 1){
            sum = (uint16_t)(sum + 1);
        }
    }
    
    //If the sum equals FFFF, then the frame is valid.  Else, return with a fail message
    if(sum == 0xFFFF){
        return 1;
    } else {
        printf("Received message had invalid Checksum\n");
        return 0;
    }
}

/* This function takes in an RHP frame and makes the checksum value for 
*  the message */
uint16_t makeChecksum(char buffer[],int numBytes){
    //convert the character array to an array of 16 bit values
    uint16_t newBuffer[numBytes/2];
    for(int i = 0;i < numBytes/2;i++){
        newBuffer[i] = (uint16_t)(buffer[2*i+1]<<8) + (uint8_t)buffer[2*i];
    }

    uint32_t sum = 0;//Value of the sum of all the 16 bit words in the frame

    for(int i = 0;i < numBytes/2;i++){
        sum = sum + newBuffer[i];
        //If there was an overflow, then add 1 to sum
        if(sum>>16 == 1){
            sum = (uint16_t)(sum + 1);
        }
    }
    
    sum = ~((uint16_t)sum);
    return sum;
}

//Returns the length of the frame in bytes
int packRHPFrame(char *frame,char payload[], uint8_t type, uint16_t portID){
    uint8_t version = 5;
    uint8_t length = 0;
    while(payload[length] != '\0'){
        length++;
    }
    length++;
    memcpy(&frame[0], &version,sizeof(version));
    memcpy(&frame[1], &type,sizeof(type));
    memcpy(&frame[2],&portID,sizeof(portID));
    memcpy(&frame[4],&length,sizeof(length));
    for(int i = 0;i < length;i++){
        frame[5+i] = payload[length-1-i];
        //printf("%c\n", payload[length-1-i]);
    }

    if(((5+length)%2) != 0){
        frame[5+length]= (char)0x00;
        length++;
        //printf("OHELL\n");
    }

    uint16_t cSum = makeChecksum(frame,5+length);
    memcpy(&frame[5+length],&cSum,sizeof(cSum));

    return 7+length;
}

/* This function takes in an RHP frame and extracts and displays all the relevant information*/
void parseRHPFrame(char buffer[], int numBytes){
    //Parse the received message into the Protocol Fields
    uint8_t version = buffer[0];
    uint8_t type = buffer[1];
    uint16_t portID = (uint16_t)(buffer[3]<<8) + (uint8_t)buffer[2];
    uint8_t length = buffer[4];
    char receivedMessage[BUF_LEN];
    for(int i = 0; i < length; i++){
        receivedMessage[i] = buffer[5+i];
    }
    uint16_t checksum = (uint16_t)(buffer[numBytes-1]<<8) + (uint8_t)buffer[numBytes-2];

    //Print out the message and the fields
    printf("Received from server:\nVersion #: %u\nMessage Type: %u\n", version,type);
    printf("PortID: %u\nMessage Length: %u\n",portID,length);
    printf("Message: %s\n",receivedMessage);
    printf("Checksum: 0x%X\n",checksum);
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

    char RHPMessage[BUF_LEN];
    int numSendBytes = packRHPFrame(&RHPMessage,MESSAGE,2,223);
    //parseRHPFrame(RHPMessage,14);
    //printf("Checksum Test: %i",validChecksum(RHPMessage,14));

    // send a message to the server 
    if (sendto(clientSocket, RHPMessage, numSendBytes, 0,(struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
        perror("sendto failed");
        return 0;
    }
    printf("RHP Message sent: %s\n",MESSAGE);

    //Loop to attempt the transmission 5 times
    for(int q = 0;q < 5;q++){
        //Receive message from server and run checksum test
        

        nBytes = recvfrom(clientSocket, buffer, BUF_LEN, 0, NULL, NULL);

        //If the checksum is valid, then display the message.  If not, resend our message 
        if(validChecksum(buffer,nBytes) != 0){
            parseRHPFrame(buffer,nBytes);
            printf("Num Bytes: %i\n",nBytes);
            break;//Break out of the loop because we had a successfully received message
        } else if(q < 5) {
            //Resend the message
            if (sendto(clientSocket, RHPMessage, numSendBytes, 0,(struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
                perror("sendto failed");
                return 0;
            }
            printf("RHP Message sent: %s\n",MESSAGE);
        }
    }

    close(clientSocket);
    return 0;
}