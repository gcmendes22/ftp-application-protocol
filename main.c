#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_SIZE 256

typedef struct utl {
  int port;
  char ip[MAX_SIZE];
  char user[MAX_SIZE];
  char password[MAX_SIZE];
  char host[MAX_SIZE];
  char path[MAX_SIZE];
  char filename[MAX_SIZE];
} url_t;

char* get_ip(char* host) {
  struct hostent *h = gethostbyname(host);
  if (h == NULL) {
    herror("gethostbyname");
    return -1;
  }

  printf("Host name  : %s\n", h->h_name);
  printf("IP Address : %s\n", inet_ntoa(*((struct in_addr *)h->h_addr)));
  return inet_ntoa(*((struct in_addr *)h->h_addr));
}

int connect_socket(const char* ip, int port) {
    struct sockaddr_in server_addr;

    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);  // 32 bit Internet address network byte ordered
    server_addr.sin_port = htons(port);  // Server TCP port must be network byte ordered

    // Open a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) {
      perror("socket()");
      return -1;
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
      perror("connect()");
      return -1;
    }

    return sockfd;
}

url_t 

int main(int argc, const char* argv[]) {
  //ftp://[<user>:<password>@]<host>/<url-path>
  struct url* url_parameters;
  url_parameters.host = "192.168.28.96";

  char* ip = get_ip(host);
  int sockfd = connect_socket(ip, port);

  return 0;
}