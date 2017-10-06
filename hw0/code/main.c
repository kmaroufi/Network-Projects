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

int main(int argc, char ** argv)
{
	if(argc <= 1) {
		// server mode
		printf("Hello World\n");
	}
	else if(argc == 3) {
		// client mode
		printf("Hello World: %s %s\n", argv[1], argv[2]);
	}
	else {
		// error
		printf("Unknown argument\n");
	}
}
