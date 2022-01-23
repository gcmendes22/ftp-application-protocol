#include <stdio.h>
#include <regex.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
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
#define REGEX_AUTH "ftp://([([A-Za-z0-9])*:([A-Za-z0-9])*@])*([A-Za-z0-9.~-])+/([[A-Za-z0-9/~._-])+";

#define REGEX_NO_AUTH "ftp://([A-Za-z0-9.~-])+/([[A-Za-z0-9/~._-])+";


/* Auxiliar functions */

char* substring_char(char* string, char ch);

int is_auth_mode(char* input);

int string_match_regex(regex_t* regex, char* regex_expression, char* string, int length);

int set_username(char* offset_string, char* string);

int set_password(char* offset_string, char* string);

int set_hostname(char* offset_string, char* string);

int set_pathname(char* offset_string, char* string);

/* URL and FTP functions */

// @brief Alloc default values to URL fields
// @param url URL struct to initialize
// @return int: TRUE if success, ERROR if error
int url_init(struct url_t* url);

// @brief Parse URL passed as parameter to URL settings
// @param input URL in string form
// @return int: TRUE if success, ERROR if error
int url_parse(char* input);

// @brief Print URL settings
// @return void
void url_print();

// @brief Get IP based on hostname
// @return char*: IP if success, NULL if error
char* url_get_ip();

// @brief Set an array of ints into a URL IP
// @param ip IP in array of ints
// @return TRUE if success, ERROR if error
int url_set_ip_int(int* ip);

// @brief Set a string (ip format) into a URL IP
// @return TRUE if success, ERROR if error
int url_set_ip_char(char* ip);

// @brief Convert to PORT and set into URL settings
// @return TRUE if success, ERROR if error
int url_set_port(int* port);

// @brief Send commands to FTP server
// @return TRUE if success, ERROR if error 
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

  ftp = malloc(sizeof(struct ftp_t));

  /* Initializing URL connection parameters */
  url = malloc(sizeof(struct url_t));
  if(url_init(url) == ERROR) {
    printf("Error: Cannot initialize connection parameters. Url passed in parameter cannot be null.\n");
    return ERROR;
  }
  
  /* Parsing URL provided to URL settings parameters */
  url_parse(input);

  /* Opening socket connection */
  ftp->socket_fd = ftp_open_connection();
  if(ftp->socket_fd == ERROR) {
    printf("[-] Error: Cannot open FTP conection.\n");
    return ERROR;
  }
  printf("[+] Opened connection successfuly.\n");

  char* user = strlen(url->user) != 0 ? url->user : "anonymous";
  char* password = strlen(url->password) != 0 ? url->password : "anon";
  strcpy(url->user, user);
  strcpy(url->password, password);
  
  /* Printing URL parameters */
  url_print(url);
  
  /* Login into user account */
  int login_response = ftp_authenticate();
  
  if(login_response == ERROR) {
    printf("[-] Error: Cannot login into your account.\n");
    return ERROR;
  }

  if(login_response == FALSE) {
    printf("[-] Error: Username or password are incorrect.\n");
    return ERROR;
  }
  printf("[+] Login was successful.\n");

  /* Get in passive mode */
  int pasv_response = ftp_switch_passive_mode();
  if(pasv_response == ERROR) {
    printf("[-] Error: Cannot switch to passive mode.\n");
    return ERROR;
  }
  printf("[+] Switched to passive mode\n");
   
  /* Reconnecting, but this time with passive mode */
  ftp->data_fd = ftp_open_connection();
  if(ftp->socket_fd == ERROR) {
    printf("[-] Error: Cannot open the data connection.\n");
    return ERROR;
  }
  printf("[+] Opened data connection.\n");

  /* Change to respective directory passed in URL */
  int cwd_response = ftp_change_directory();

  if(cwd_response == ERROR) {
    printf("[-] Error: Cannot switch to the respective directory %s/%s.\n", url->path, url->filename);
    return ERROR;
  }
  printf("[+] Switched to the respective directory.\n");

  /* Retrieve a copy of the file */
  int retr_response = ftp_retrieve_file();
  if(retr_response == ERROR) {
    printf("[-] Error: Cannot retrieve a copy of the file.\n");
    return ERROR;
  }
  printf("[+] File was retrived.\n");
  
  /* Download file */
  printf("[+] Downloading...\n");
  int download_response = ftp_download_file();
  if(download_response == ERROR) {
    printf("[-] Error: Cannot download the file.\n");
    return ERROR;
  }
  printf("[+] The download was successful.\n");

  /* Cleaning all structures and disconnecting from server */

  int disc_response = ftp_disconnect();
  if(disc_response == ERROR) {
    printf("[-] Error: Cannot disconnect from the server with success.\n");
    return ERROR;
  }
  printf("[+] Leaving program...\n");
  return TRUE;
}

void delay(int number_of_seconds)
{
    // Converting time into milli_seconds
    int milli_seconds = 1000 * number_of_seconds;
  
    // Storing start time
    clock_t start_time = clock();
  
    // looping till required time is not achieved
    while (clock() < start_time + milli_seconds)
        ;
}

char* substring_char(char* string, char ch) {
	char* substring = (char*) malloc(strlen(string));

	int length = strlen(string) - strlen(strcpy(substring, strchr(string, ch)));

	substring[length] = '\0';
	strncpy(substring, string, length);
	strcpy(string, string + strlen(substring) + 1);

	return substring;
}

int is_auth_mode(char* input) {
    return input[6] == '[' ? TRUE : FALSE;
}

int string_match_regex(regex_t* regex, char* regex_expression, char* string, int length) {
  int status;
  size_t nmatch = length;
  regmatch_t pmatch[nmatch];
  
  if((status = regcomp(regex, regex_expression, REG_EXTENDED)) != 0) return ERROR;
  if((status = regexec(regex, string, nmatch, pmatch, REG_EXTENDED)) != 0) return ERROR;

  return TRUE;
}

int set_username(char* offset_string, char* string) {
  if(offset_string == NULL || string == NULL) return ERROR;
  
  strcpy(string, string + 1);
  strcpy(offset_string, substring_char(string, ':'));
  memcpy(url->user, offset_string, strlen(offset_string));
  return TRUE;
}

int set_password(char* offset_string, char* string) {
  if(offset_string == NULL || string == NULL) return ERROR;

  strcpy(offset_string, substring_char(string, '@'));
  memcpy(url->password, offset_string, strlen(offset_string));
  strcpy(string, string + 1);
  return TRUE;
}

int set_hostname(char* offset_string, char* string) {
  if(offset_string == NULL || string == NULL) return ERROR;
  
  strcpy(offset_string, substring_char(string, '/'));
	memcpy(url->host, offset_string, strlen(offset_string));
  return TRUE;
}

int set_pathname(char* offset_string, char* string) {
  if(offset_string == NULL || string == NULL) return ERROR;

  char* pathname = (char*) malloc(strlen(string));
  int path_begin = 1;
  while (strchr(string, '/')) {
    offset_string = substring_char(string, '/');

    if (path_begin) {
      path_begin = 0;
      strcpy(pathname, offset_string);
    } else strcat(pathname, offset_string);

    strcat(pathname, "/");
  }
  strcpy(url->path, pathname);
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

int url_parse(char* input) {
  char* aux_url_string, *offset_string, *active_expression;
  regex_t* regex;
  int user_pass_mode;

  offset_string = (char*) malloc(strlen(input));
  aux_url_string = (char*) malloc(strlen(input));

  memcpy(aux_url_string, input, strlen(input));

  if(is_auth_mode(input) == TRUE) {
    active_expression = (char*) REGEX_AUTH;
  } else {
    active_expression = (char*) REGEX_NO_AUTH;
  }

  regex = (regex_t*) malloc(sizeof(regex_t));

  if(string_match_regex(regex, active_expression, aux_url_string, strlen(input)) == ERROR) return ERROR;

  free(regex);

  strcpy(aux_url_string, aux_url_string + 6);

  if (is_auth_mode(input) == TRUE) {
    set_username(offset_string, aux_url_string);
    set_password(offset_string, aux_url_string);
  }

  set_hostname(offset_string, aux_url_string);

  set_pathname(offset_string, aux_url_string);

  strcpy(url->filename, aux_url_string);

  free(aux_url_string);
  free(offset_string);

  url_set_ip_char(url_get_ip()); 

  return TRUE;
}

void url_print() {

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
  url->port = (port[0] * 256) + port[1];
  printf("%d %d\n", port[0], port[1]);
  return TRUE;
}

int ftp_send_command(char* command) {
  int status;

  if((status = write(ftp->socket_fd, command, strlen(command))) <= 0) return ERROR;

  return status;
}

int ftp_read_command_response(char* command) {
  int length = strlen(command);
  delay(100);
  FILE* fp;
  
  if(((fp = fdopen(ftp->socket_fd, "r")) < 0)) return ERROR;
  /* Reset the actual command and store it with the response of the command on the server */
  do {
    memset(command, 0, length);
    command = fgets(command, BUFSIZE, fp);
    printf("%s", command);
  } while(!(command[0] >= '1' && command[0] <= '5') || command[3] != ' ');

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
  sprintf(password_command, "PASS %s\r\n", url->password);

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
    printf("%d\n", bytes_sent);
  /* Get the response of the command sent to the FTP server */
  if((bytes_read = ftp_read_command_response(cwd_command)) == ERROR)
    return ERROR;

  return TRUE;
}

int ftp_switch_passive_mode() {
  char pasv_command[BUFSIZE] = "PASV\r\n";
  int bytes_sent, bytes_read;
  int ip[4];
  int port[2];

  /* Send the command to the FTP server */
  if((bytes_sent = ftp_send_command(pasv_command)) == ERROR)
    return ERROR;

  /* Get the response of the command sent to the FTP server */
  if((bytes_read = ftp_read_command_response(pasv_command)) == ERROR)
    return ERROR;

  /* Passing the response to the buffer */
  
  sscanf(pasv_command, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)", &ip[0], &ip[1], &ip[2], &ip[3], &port[0], &port[1]);
  memset(pasv_command, 0, sizeof(pasv_command));
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
  if((bytes_read = ftp_read_command_response(retr_command)) == ERROR) {
    
     return ERROR;
  }
   
  
  return TRUE;
}

int ftp_download_file() {
  FILE* fp;
  char buf[MAXLEN];
  int bytes_read;

  /* Create new file to copy the file on the server */
  if((fp = fopen(url->filename, "w")) == NULL) {
    printf("Error: Cannot opening file\n");
    return ERROR;
  }

  while((bytes_read = read(ftp->data_fd, buf, MAXLEN)) != 0) {
    if (bytes_read < 0) return ERROR;
    if((bytes_read = fwrite(buf, bytes_read, 1, fp)) < 0) return ERROR;
  }

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
  char disc_command[BUFSIZE] = "QUIT\r\n";
  int bytes_sent;
  
  if((bytes_sent = ftp_send_command(disc_command)) == ERROR)
    return ERROR;
  
  close(ftp->data_fd);
  close(ftp->socket_fd);
  free(url);
  free(ftp);

  return TRUE;
}