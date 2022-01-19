#include <stdio.h>
#include <regex.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>


#define BUFSIZE 2048
#define MAXLEN 1024
#define TRUE 1
#define FALSE 0
#define ERROR -1

struct url_t {
  char ip[MAXLEN];
  char host[MAXLEN];
  char user[MAXLEN];
  char password[MAXLEN];
  char path[MAXLEN];
  char filename[MAXLEN];
  int port;
};

struct ftp_t {
  int socket_fd;
  int data_fd;
};
  
/* Variable to store URL parameters */
struct url_t* url;

/* Variable to store FTP file descriptors */
struct ftp_t* ftp;

/* REGEX for URL parsing */
const char* URL_REGEX = "^ftp://(([a-zA-Z][^:]*):([^@]+)@)?(([a-z0-9:]+[.]?)+)/(([^/]+[/])*)([^/]+)$";

int url_init(struct url_t* url);

int url_parse(struct url_t* url, char* input);

void url_print(struct url_t* url);

char* url_get_ip();

int url_set_ip_int(int* ip);

int url_set_ip_char(char* ip);

int url_set_port(int* port);

int ftp_send_command(char* command);

int ftp_read_command_response(char* command);

int ftp_open_connection();

int ftp_authenticate();

int ftp_change_directory();

int ftp_switch_passive_mode();

int ftp_retrieve_file();

int ftp_download_file();

FILE* ftp_copy_file();

int ftp_disconnect();

int main(int argc, char* argv[]) {
  /* Bad program arguments */
  if(argc != 2) {
    printf("Error: Invalid arguments format.\nUsage: ./main ftp://[<user>:<password>@]<host>/<url-path>\n");
    return ERROR;
  }

  /* Copying URL string to input variable */
  char input[BUFSIZE];
  memcpy(input, argv[1], BUFSIZE);

  /* Initializing URL connection parameters */
  url = malloc(sizeof(struct url_t));
  if(url_init(url) == ERROR) {
    printf("Error: Cannot initialize connection parameters. Url passed in parameter cannot be null.\n");
    return ERROR;
  }
  /* Parsing URL provided to URL settings parameters */
  url_parse(url, input);

  /* Printing URL parameters */
  url_print(url);

  /* Opening socket connection */
  ftp->socket_fd = ftp_open_connection();
  if(ftp->socket_fd == ERROR) {
    printf("Error: Cannot open FTP conection.\n");
    return ERROR;
  }

  /* Login into user account */
  int login_response = ftp_authenticate();
  
  if(login_response == ERROR) {
    printf("Error: Cannot login into your account.\n");
    return ERROR;
  }

  if(login_response == FALSE) {
    printf("Error: Username or password are incorrect.\n");
    return ERROR;
  }

  /* Change to respective directory passed in URL */
  int cwd_response = ftp_change_directory(ftp->socket_fd, url->path);
  if(cwd_response == ERROR) {
    printf("Error: Cannot switch to the respective directory %s/%s.\n", url->path, url->filename);
    return ERROR;
  }

  /* Get in passive mode */
  int pasv_response = ftp_switch_passive_mode();
  if(pasv_response == ERROR) {
    printf("Error: Cannot switch to passive mode.\n");
    return ERROR;
  }

  /* Reconnecting, but this time with passive mode */
  ftp->data_fd = ftp_open_connection();
  if(ftp->socket_fd == ERROR) {
    printf("Error: Cannot open the data connection.\n");
    return ERROR;
  }

  /* Retrieve a copy of the file */
  int retr_response = ftp_retrieve_file();
  if(retr_response == ERROR) {
    printf("Error: Cannot retrieve a copy of the file.\n");
    return ERROR;
  }
  
  /* Download file */
  printf("Downloading...\n");
  int download_response = ftp_download_file();
  if(download_response == ERROR) {
    printf("Error: Cannot retrieve a copy of the file.\n");
    return ERROR;
  }
  printf("The download was successful.\n");

  /* Cleaning all structures and disconnecting from server */
  ftp_disconnect();
  int disc_response = ftp_disconnect();
  if(disc_response == ERROR) {
    printf("Error: Cannot disconnect from the server with success.\n");
    return ERROR;
  }
  
  return TRUE;
}

int url_init(struct url_t* url) {
  if(url == NULL) return ERROR;

  memset(url->ip, 0, MAXLEN);
  memset(url->host, 0, MAXLEN);
  memset(url->user, 0, MAXLEN);
  memset(url->password, 0, MAXLEN);
  memset(url->path, 0, MAXLEN);
  memset(url->filename, 0, MAXLEN);
  url->port = 21;
  
  return TRUE;
}

int url_parse(struct url_t* url, char* input) {
  regex_t* regex;
  int is_compiled;

  /* Compile regular expression */
  if((is_compiled = regcomp(regex, URL_REGEX, REG_EXTENDED | REG_NEWLINE)) != 0) {
    printf("Error: Cannot compile regex expression.\n");
    return ERROR;
  }

  /* provisory */
  strcpy(url->user, strlen("root") == 0 ? "root" : "none");
  strcpy(url->password, strlen("none") == 0 ? "none" : "none");
  strcpy(url->host, "192.168.86.23");
  strcpy(url->filename, "file");
  strcpy(url->path, "pathname");

  url_set_ip_char(url_get_ip());

  return TRUE;
}

void url_print(struct url_t* url) {
  printf("URL connection parameters:\n\n");
  printf("IP: %s\n", url->ip);
  printf("User: %s\n", url->user);
  printf("Password: %s\n", url->password);
  printf("Host: %s\n", url->host);
  printf("Filename: %s\n", url->filename);
  printf("Path: %s\n", url->path);
  putchar('\n');
}

char* url_get_ip() {
  struct hostent *h = gethostbyname(url->host);
  if (h == NULL) {
    herror("gethostbyname");
    return NULL;
  }

  return inet_ntoa(*((struct in_addr *)h->h_addr));
}

int url_set_ip_int(int* ip) {
  if(ip == NULL) return ERROR;
  sprintf(url->ip, "%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
  return TRUE;
}

int url_set_ip_char(char* ip) {
  if(ip == NULL) return ERROR;
  strcpy(url->ip, ip);
  return TRUE;
}

int url_set_port(int* port) {
  if(port == NULL) return ERROR;
  url->port = port[0] * 256 + port[1];
  return TRUE;
}

int ftp_send_command(char* command) {
  int status;
  if((status = write(ftp->socket_fd, command, strlen(command))) <= 0) return ERROR;

  return status;
}

int ftp_read_command_response(char* command) {
  int length = strlen(command);
  FILE* fp;
  
  if(((fp = fdopen(ftp->socket_fd, "r")) < 0)) return ERROR;

  /* Reset the actual command and store it with the response of the command on the server */
  do {
    memset(command, 0, length);
    command = fgets(command, length, fp);
  } while((command[0] >= '1' && command[0] <= '5') || command[3] != ' ');

  return TRUE;
}

int ftp_open_connection() {
    struct sockaddr_in server_addr;

    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(url->ip);  // 32 bit Internet address network byte ordered
    server_addr.sin_port = htons(url->port);  // Server TCP port must be network byte ordered

    // Open a TCP socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_fd < 0) {
      perror("socket()");
      return ERROR;
    }

    // Connect to the server
    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
      perror("connect()");
      return ERROR;
    }

    return socket_fd;
}

int ftp_authenticate() {
  char user_command[BUFSIZE];
  char password_command[BUFSIZE];
  int bytes_sent, bytes_read;

  /* Creating command USER <user> */
  sprintf(user_command, "USER %s\r\n", url->user);

  /* Send the command to the FTP server */
  if((bytes_sent = ftp_send_command(user_command)) == ERROR) {
    printf("Error: Cannot send the command %s.\n", user_command);
    return ERROR;
  }

  /* Get the response of the command sent to the FTP server */
  if((bytes_read = ftp_read_command_response(user_command)) == ERROR)
    return FALSE;

  /* Creating command PASS <password> */
  sprintf(user_command, "PASS %s\r\n", url->password);

  /* Send the command to the FTP server */
  if((bytes_sent = ftp_send_command(password_command)) == ERROR) {
    printf("Error: Cannot send the command %s.\n", password_command);
    return ERROR;
  }

  /* Get the response of the command sent to the FTP server */
  if((bytes_read = ftp_read_command_response(password_command)) == ERROR)
    return ERROR;

  return TRUE;
}

int ftp_change_directory() {
  char cwd_command[BUFSIZE];
  int bytes_sent, bytes_read;

  /* Creating command CWD <pathname> */
  sprintf(cwd_command, "CWD %s\r\n", url->path);

  /* Send the command to the FTP server */
  if((bytes_sent = ftp_send_command(cwd_command)) == ERROR) {
    printf("Error: Cannot send the command %s.\n", cwd_command);
    return ERROR;
  }

  /* Get the response of the command sent to the FTP server */
  if((bytes_read = ftp_read_command_response(cwd_command)) == ERROR)
    return ERROR;
  
  return TRUE;
}

int ftp_switch_passive_mode() {
  char pasv_command[BUFSIZE] = "PASV\r\n";
  int bytes_sent, bytes_read;
  int ip[4];
  int port[23];

  /* Send the command to the FTP server */
  if((bytes_sent = ftp_send_command(pasv_command)) == ERROR) {
    printf("Error: Cannot send the command %s.\n", pasv_command);
    return ERROR;
  }

  /* Get the response of the command sent to the FTP server */
  if((bytes_read = ftp_read_command_response(pasv_command)) == ERROR)
    return ERROR;
  
  /* Passing the response to the buffer */
  sscanf(pasv_command, "227 Entering Passive Mode (%d, %d, %d, %d, %d, %d)", &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]);

  /* Setting new IP and PORT into connection settings */
  url_set_ip_int(ip);
  url_set_port(port);

  return TRUE;
}

int ftp_retrieve_file() {
  char retr_command[BUFSIZE];
  int bytes_sent, bytes_read;

  /* Creating command RETR <pathname> */
  sprintf(retr_command, "RETR %s\r\n", url->filename);

  /* Send the command to the FTP server */
  if((bytes_sent = ftp_send_command(retr_command)) == ERROR) {
    printf("Error: Cannot send the command %s.\n", retr_command);
    return ERROR;
  }

  /* Get the response of the command sent to the FTP server */
  if((bytes_read = ftp_read_command_response(retr_command)) == ERROR)
    return ERROR;
  
  return TRUE;
}

int ftp_download_file() {
  FILE* fp;

  /* Create new file to copy the file on the server */
  if(fopen(url->filename, "w") == NULL) return ERROR;

  fp = ftp_copy_file();
  if(!fp) return ERROR;

  fclose(fp);

  return TRUE;  
}

FILE* ftp_copy_file() {
  FILE* fp;
  char* buffer[BUFSIZE];
  int bytes_read, bytes_sent;

  while((bytes_read = read(ftp->data_fd, buffer, MAXLEN))) {
    if(bytes_read < 0) {
      return NULL;
    }

    if((bytes_sent = fwrite(buffer, bytes_read, 1, fp)) < 0) {
      return NULL;
    }
  }

  return fp;
}

int ftp_disconnect() {
  char disc_command[BUFSIZE];
  int bytes_sent;
  
  sprintf(disc_command, "QUIT\r\n");
  if((bytes_sent = ftp_send_command(disc_command)) == ERROR)
    return ERROR;
  
  close(ftp->data_fd);
  close(ftp->data_fd);
  free(url);
  free(ftp);

  return TRUE;
}