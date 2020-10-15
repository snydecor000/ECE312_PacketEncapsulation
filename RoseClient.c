/*
*   Tristen Foisy and Cory Snyder
*   ECE312-01 
*   Project 2: Packet Ecapsulation
*   
*   In this project we were required to implement 2 protocols 
*   directly above UDP: RPH, and RHMP.  
*
*   RHP, or Rose-Hulman Protocol, is the lower of the two protocols, 
*   with fields: version, type, portID, length, payload, buffer, and checksum
*   RHP frames are always an even number of characters long, and the checksum
*   is a 16-bit checksum of the whole frame.  RHP frames can be one of 2 types:
*   A Control Message (where the payload is an ascii character string)
*   A RHMP Message (where the payload is an RHMP Frame)
*   
*   We created functions validateChecksum() and makeChecksum() to handle the 
*   sending and recieving checksum calculations.
*
*   RHP Frames are creating using the function packRHPFrame() and
*   RHP Frames are decoded and printed to the console with parseRHPFrame()
*
*   RHMP, or Rose-Hulman Message Protocol, is the higher of the two protocols,
*   with fields: type, srcPort, dstPort, length, and payload.
*   RHMP Frames can be one of 4 types:
*   An ID Request (with no payload)
*   An ID Response (where the payload is a 32-bit unsigned integer identifier)
*   A Message Request (with no payload)
*   A Message Response (where the payload is an ascii character string)
*
*   
*/

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define SERVER "137.112.38.47"
#define PORT 1874
#define BUF_LEN 1024
//Our CM numbers
#define TristenCM 223
#define CoryCM 514
//Destination RHMP Port
#define DEST_PORT 105
//RHP Message Types
#define RHP_CONTROL 2
#define RHMP_MESSAGE 8
//RHMP Message Types
#define ID_REQUEST 2
#define MESSAGE_REQUEST 4
#define ID_RESPONSE 6
#define MESSAGE_RESPONSE 8

/* This function takes in an RHP frame and validates or invalidates 
*  the message according to the 16 bit checksum at the end of the message.
*  It will return 0 if it failed, and 1 if the frame passed CRC. */
int validateChecksum(char buffer[],int numBytes){
    //convert the frame character array to an array of 16 bit values
    uint16_t newBuffer[numBytes/2];
    for(int i = 0;i < numBytes/2;i++){
        newBuffer[i] = (uint16_t)(buffer[2*i+1]<<8) + (uint8_t)buffer[2*i];
    }

    uint32_t sum = 0;//Value of the sum of all the 16 bit words in the frame

    //Loop through, adding the 16 bit values to each other
    for(int i = 0;i < numBytes/2;i++){
        sum = sum + newBuffer[i];
        //If there was an overflow, then add 1 to sum and get rid of the overflow
        if(sum>>16 == 1){
            sum = (uint16_t)(sum + 1);
        }
    }
    
    //If the sum equals FFFF, then the frame is valid.  Else, return with a fail message
    if(sum == 0xFFFF){
        return 1;
    } else {
        printf("Received message had invalid Checksum\n\n");
        return 0;
    }
}

/* This function takes in an RHP frame and returns the checksum value for 
*  the message */
uint16_t makeChecksum(char buffer[],int numBytes){
    //convert the frame character array to an array of 16 bit values
    uint16_t newBuffer[numBytes/2];
    for(int i = 0;i < numBytes/2;i++){
        newBuffer[i] = (uint16_t)(buffer[2*i+1]<<8) + (uint8_t)buffer[2*i];
    }

    uint32_t sum = 0;//Value of the sum of all the 16 bit words in the frame

    //Loop through, adding the 16 bit values to each other
    for(int i = 0;i < numBytes/2;i++){
        sum = sum + newBuffer[i];
        //If there was an overflow, then add 1 to sum and get rid of the overflow
        if(sum>>16 == 1){
            sum = (uint16_t)(sum + 1);
        }
    }
    //Return the ones compliment of the final sum value
    sum = ~((uint16_t)sum);
    return sum;
}

/*  This function takes arguments for an RHP packet and constructs the header, adds 
*   the payload, and attaches the checksum to the end.
*
*   It is passed, by reference a character array of the RHP frame where 
*   the results will be stored, and the payload of the RHP frame.  It is also passed
*   the RHP type, and the destination port ID.  
*/
int packRHPFrame(char *frame,char payload[], uint8_t type, uint16_t portID){
    uint8_t version = 5;
    uint8_t length = 0;

    //Get the length of the payload in bytes
    while(payload[length] != '\0'){
        length++;
    }
    //Add the \0 to the end of the string only if it is a control message
    if(type == RHP_CONTROL){
        length++;
    }


    //Construct the header in little endian format
    memcpy(&frame[0],&version,sizeof(version));
    memcpy(&frame[1],&type,sizeof(type));
    memcpy(&frame[2],&portID,sizeof(portID));
    memcpy(&frame[4],&length,sizeof(length));

    //Add the payload in reverse order to match the little endianness
    if(type == RHP_CONTROL){
        for(int i = 0;i < length;i++){
            frame[5+i] = payload[length-1-i];
        }
    } else if(type == RHMP_MESSAGE){
        for(int i = 0;i < length;i++){
            frame[5+i] = payload[i];
        }
    }


    //Add an 8-bit buffer if it is not an even number of bytes
    if(((5+length)%2) != 0){
        frame[5+length]= (char)0x00;
        length++;
    }

    //Add the checksum to the end
    uint16_t cSum = makeChecksum(frame,5+length);
    memcpy(&frame[5+length],&cSum,sizeof(cSum));

    //Return the total length of the frame in bytess
    return 7+length;
}

/*  This function takes in an RHP frame, and extracts and displays all 
*   the relevant information
*/
void parseRHPFrame(char buffer[], int numBytes){
    //Parse the received message into the RHP protocol Fields. Assume Little Endianness
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
    printf("Received from server:\nVersion #: %u\nRHP Message Type: %u\n", version,type);
    printf("PortID: %u\nMessage Length: %u\n",portID,length);

    //If this is a Control Message using only RHP, display the message 
    if(type == RHP_CONTROL){
        printf("Control Message: %s\n",receivedMessage);
        printf("Checksum: 0x%X\n",checksum);
    }
    //If this is a RHMP Message, parse the RHMP frame
    if(type == RHMP_MESSAGE){
        printf("This is a RHMP Message\n");
        parseRHMPFrame(receivedMessage);
        printf("Checksum: 0x%X\n",checksum);
    }
}

void packRHMPFrame(char *frame,char payload[], uint8_t type, uint16_t srcPort, uint16_t dstPort) {
    frame[0] = (type & 0x0F) | (uint8_t)((srcPort & 0x000F)<<4);
    frame[1] = (uint8_t)((srcPort & 0x0FF0) >> 4);
    frame[2] = (uint8_t)((uint8_t)((dstPort & 0x003F) << 2) | (uint8_t)((srcPort & 0x3000) >> 12));
    frame[3] = (uint8_t)((dstPort & 0x3FC0) >> 6);

    if(type == MESSAGE_RESPONSE){
        uint8_t length = 0;

        //Get the length of the payload in bytes
        while(payload[length] != '\0'){
            length++;
        }
        length++;

        frame[4] = length;

        //Add the payload in reverse order to match the little endianness
        for(int i = 0;i < length;i++){
            frame[5+i] = payload[length-1-i];
        }
    } else if(type == ID_RESPONSE) {
        uint8_t length = 4;
        for(int i = 0;i < length;i++){
            frame[4+i] = payload[length-1-i];
        }
    } else {
        //No Payload
    }
}

void parseRHMPFrame(char buffer[]){
    uint8_t type = (buffer[0] & 0x0F);
    uint16_t srcPort = (uint16_t)((buffer[0] & 0xF0)>>4) | (uint16_t)(buffer[1]<<4) | (uint16_t)((buffer[2] & 0x03)<<12);
    uint16_t dstPort = (uint16_t)((buffer[2] & 0xFC)>>2) | (uint16_t)(buffer[3]<<6);

    //Print out the message and the fields
    printf("RHMP Message Type: %u\n", type);
    printf("Source Port: %u\nDestination Port: %u\n",srcPort,dstPort);

    if(type == MESSAGE_RESPONSE){
        uint8_t length = buffer[4];
        printf("Length: %u\n",length);

        char receivedMessage[BUF_LEN];
        for(int i = 0; i < length; i++){
            receivedMessage[i] = buffer[5+i];
        }

        printf("RHMP Message: %s\n",receivedMessage);
    } else if(type == ID_RESPONSE){
        uint32_t id = buffer[4] + (buffer[5]<<8) + (buffer[6]<<16) + (buffer[7]<<24);
        printf("RHMP ID Response: %u\n",id);
    }
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


    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //Sends the first RHP Control Message: "hello\0"

    char message1[] = "hello\0";
    char RHPMessage1[BUF_LEN];
    int numSendBytes1 = packRHPFrame(&RHPMessage1,message1,RHP_CONTROL,CoryCM);
    //parseRHPFrame(RHPMessage,14);
    //printf("Checksum Test: %i",validateChecksum(RHPMessage,14));

    // send the message to the server 
    if (sendto(clientSocket, RHPMessage1, numSendBytes1, 0,(struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
        perror("sendto failed");
        return 0;
    }

    printf("RHP Control Message sent: %s\n",message1);

    //Loop to attempt the transmission 5 times
    for(int q = 0;q < 5;q++){
        //Receive message from server
        nBytes = recvfrom(clientSocket, buffer, BUF_LEN, 0, NULL, NULL);

        //If the checksum is valid, then display the message.  If not, resend our message 
        if(validateChecksum(buffer,nBytes) != 0){
            parseRHPFrame(buffer,nBytes);
            printf("Num Bytes: %i\n",nBytes);
            break;//Break out of the loop because we had a successfully received message
        } else if(q < 5) {
            //Resend the message
            if (sendto(clientSocket, RHPMessage1, numSendBytes1, 0,(struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
                perror("sendto failed");
                return 0;
            }
            printf("RHP Control Message sent: %s\n",message1);
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    //Sends the first RHMP Request Message

    char RHMPMessage2[BUF_LEN];
    char RHPMessage2[BUF_LEN];
    
    
    packRHMPFrame(&RHMPMessage2,"", ID_REQUEST, CoryCM, DEST_PORT);
    parseRHMPFrame(RHMPMessage2);
    int numSendBytes2 = packRHPFrame(&RHPMessage2,RHMPMessage2,RHMP_MESSAGE,312);
    //parseRHPFrame(RHPMessage,14);
    //printf("Checksum Test: %i",validateChecksum(RHPMessage,14));

    // send the message to the server 
    if (sendto(clientSocket, RHPMessage2, numSendBytes2, 0,(struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
        perror("sendto failed");
        return 0;
    }

    printf("RHMP ID Request Message sent\n");

    //Loop to attempt the transmission 5 times
    for(int q = 0;q < 5;q++){
        //Receive message from server
        nBytes = recvfrom(clientSocket, buffer, BUF_LEN, 0, NULL, NULL);

        //If the checksum is valid, then display the message.  If not, resend our message 
        if(validateChecksum(buffer,nBytes) != 0){
            parseRHPFrame(buffer,nBytes);
            printf("Num Bytes: %i\n",nBytes);
            break;//Break out of the loop because we had a successfully received message
        } else if(q < 5) {
            //Resend the message
            if (sendto(clientSocket, RHPMessage2, numSendBytes2, 0,(struct sockaddr *) &serverAddr, sizeof (serverAddr)) < 0) {
                perror("sendto failed");
                return 0;
            }
            printf("RHMP ID Request Message sent\n");
        }
    }

    close(clientSocket);
    return 0;
}