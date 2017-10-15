#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unistd.h>
#include <pthread.h>

void *receiver(void *args);
void *sender(void *args);

bool isConnected;

void *status;

pthread_t receiver_thread, sender_thread;

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    if (argc <= 1) {
        // server mode
//        printf("Hello World\n");
        int sockfd, port = 1234;
        struct sockaddr_in serv_addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            printf("can't opening socket\n");
            return 1;
        }
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *) &serv_addr,
                 sizeof(serv_addr)) < 0) {
            printf("can't binding\n");
            return 1;
        }
        listen(sockfd, 5);
        while (true) {
            isConnected = false;
            int newsockfd, client_size;
            char buffer[1000];
            struct sockaddr_in cli_addr;
            client_size = sizeof(cli_addr);
//            printf("choy\n");
            newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &client_size);
            if (newsockfd < 0) {
                printf("looooooooy\n");
                continue;
            }
//            printf("boy\n");
            isConnected = true;
//            printf("In main(server): creating receiver thread \n");
            int rc = pthread_create(&receiver_thread, NULL, receiver, (void *)newsockfd);
            if (rc){
                printf("ERROR; return code from pthread_create() is %d\n", rc);
                exit(-1);
            }
//            printf("moy\n");
//            printf("In main(server): creating sender thread \n");
            rc = pthread_create(&sender_thread, NULL, sender, (void *)newsockfd);
            if (rc){
                printf("ERROR; return code from pthread_create() is %d\n", rc);
                exit(-1);
            }
//            printf("hoy\n");
            rc = pthread_join(receiver_thread, &status);
            if (rc) {
                printf("ERROR; return code from pthread_join() is %d\n", rc);
                exit(-1);
            }
//            printf("client disconnected\n");
            pthread_cancel(sender_thread);
            close(newsockfd);
        }
    } else if (argc == 3) {
        // client mode
//        printf("Hello World: %s %s\n", argv[1], argv[2]);
        int sockfd, port;

        struct sockaddr_in serv_addr;
        struct hostent *server;

        char buffer[1000];
        if (argc < 3) {
            printf("what??\n");
            exit(0);
        }
        port = atoi(argv[2]);
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            printf("can't opening socket\n");
            return 0;
        }
        server = gethostbyname(argv[1]);
        if (server == NULL) {
            printf("no host\n");
            return 0;
        }
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        bcopy((char *) server->h_addr,
              (char *) &serv_addr.sin_addr.s_addr,
              server->h_length);
        serv_addr.sin_port = htons(port);
        if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
            printf("CAN'T CONNECT");
            return 0;
        } else{
            isConnected = true;
        }

//        printf("In main(client): creating receiver thread \n");
        int rc = pthread_create(&receiver_thread, NULL, receiver, (void *) sockfd);
        if (rc) {
            printf("ERROR; return code from pthread_create() is %d\n", rc);
            exit(-1);
        }
//        printf("In main(client): creating sender thread \n");
        rc = pthread_create(&sender_thread, NULL, sender, (void *)sockfd);
        if (rc){
            printf("ERROR; return code from pthread_create() is %d\n", rc);
            exit(-1);
        }
        rc = pthread_join(receiver_thread, &status);
        if (rc) {
            printf("ERROR; return code from pthread_join() is %d\n", rc);
            exit(-1);
        }
//        printf("yekishoon kheili khoobe..\n");
        pthread_cancel(sender_thread);
        close(sockfd);
        return 0;
    } else {
        // error
        printf("Unknown argument\n");
    }
}

void *receiver(void *args) {
    int n;
    int sockfd = (int) args;
    char buffer[1000];
    while (isConnected) {
        bzero(buffer, 1000);
        n = read(sockfd, buffer, 999);
//        buffer = ntohl(buffer);
        if (n < 0) {
            printf("ERROR reading from socket");
        }
        if (n == 0) {
//            printf("shoooooooorrr\n");
            isConnected = false;
            break;
        }
//        if (buffer[0] == '\0') {
////            printf("choooooo\n");
//            break;
//        }
        printf("%s", buffer);
//        fflush(stdout);
    }
//    printf("22222222222222222\n");
}

void *sender(void *args) {
    int n;
    int sockfd = (int) args;
    char buffer[1000];
    char the_end[1] = {'\0'};
    while (isConnected) {
//        printf("Please enter the message: ");
        bzero(buffer, 1000);
        n = fgets(buffer, 999, stdin);
//        printf("n: %d\n", n);
//        printf("len: %d - buffer: %s\n", strlen(buffer), buffer);
        if (n == NULL) {
//            printf("choooooo\n");
//            buffer[0] = '\0';
//            buffer = htonl(buffer);
//            n = write(sockfd, buffer, 1);
            if (feof(stdin) != 0) {
//                printf("choooooo\n");
                pthread_cancel(receiver_thread);
                close(sockfd);
                break;
            }
        } else if (strlen(buffer) == 1) {
//            buffer = htonl(buffer);
            n = write(sockfd, buffer, strlen(buffer));
        } else {
//            buffer[strlen(buffer) - 1] = '\0';
            n = write(sockfd, buffer, strlen(buffer));
        }
//        printf("n: %d\n", n);
    }
//    printf("111111111111111\n");
}


