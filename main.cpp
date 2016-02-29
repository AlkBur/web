#include <iostream>
#include "unistd.h"
#include <string.h>
#include <cstdlib>
#include <cstdio>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include <netinet/tcp.h>

#include <sys/stat.h>

#include <sys/sendfile.h>

#define maxThreadsCount 4
#define maxConnectionsCount 100

#define EVENTS_BUFF_SZ 256

struct globalArgs_t {
    std::string ip;         /* параметр -h */
    std::string directory;  /* параметр -d */
    int port;               /* параметр -p */
};

globalArgs_t globalArgs = {"127.0.0.1", "./", 8080};
std::string s404 = "HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\n\r\n";

static int ep_fd;

int handle_request(int clientfd)
{
   char readbuff[512];
   struct sockaddr_in addr;
   socklen_t addrlen = sizeof(addr);
   ssize_t n;

   if ((n = recv(clientfd, readbuff, sizeof(readbuff) - 1, 0)) < 0) {
       return -1;
   }

   if (n == 0) {
       return 0;
   }

   readbuff[n] = '\0';

   char* save_ptr;
   char* command_line = strtok_r(readbuff, "\r\n", &save_ptr);
   if( command_line == NULL )
   {
       //std::cout << "No comamnd line found in " << readbuff << "\n";
       return 0;
   }
   char* method = strtok_r(command_line, "\t ", &save_ptr);
   if( method == NULL )
   {
       //std::cout << "No comamnd (GET) found in " << command_line << "\n";
       return 0;
   }
   //std::cout << "method :" << method << ":\n";
   char* uri = strtok_r(NULL, "\t ", &save_ptr);
   if( uri == NULL )
   {
       //std::cout << "No URI found in " << command_line << "\n";
       return 0;
   }
   //std::cout << "URI :" << uri << ":\n";
   char* file_path = strtok_r(uri, "?", &save_ptr);
   if( file_path == NULL )
   {
       //std::cout << "No file path found in URI" << uri << "\n";
       return 0;
   }
   if( *file_path == '/' )
   {
       ++file_path;
   }
   int file_d = open(file_path, O_RDONLY);
   if( file_d >= 0 )
   {
       struct stat file_stat;
       fstat(file_d, &file_stat);
       const char replay_header_template[] =
               "HTTP/1.0 200 OK\r\n"
               "Content-Type: text/html\r\n"
               "Content-Length: %lu\r\n\r\n";
       char header_buf[4096];
       int header_size = snprintf(header_buf, 4095, replay_header_template, file_stat.st_size);

       ssize_t sent;
       if ((sent = send(clientfd, header_buf, n, 0)) < 0) {
           return -1;
       }
       sendfile(clientfd, file_d, NULL, file_stat.st_size);
   }
   else
   {
       return -1;
   }
   return 0;
}

void *server_thread(void *fd) {
    //std::cout << "Create thread" << std::endl;

    int *sock = (int *)fd;
    int localSock = *sock;

    struct epoll_event ev, *events;
    ep_fd = epoll_create(maxConnectionsCount);
    events = (struct epoll_event *)malloc(sizeof(struct epoll_event) * EVENTS_BUFF_SZ);
    if (events == NULL) {
        //perror("malloc failed when attempting to allocate events buffer");
        pthread_exit(NULL);
    }

    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLET;
    ev.data.fd = localSock;
    if (epoll_ctl(ep_fd, EPOLL_CTL_ADD,localSock, &ev) < 0) {
        //perror("epoll_ctl failed");
        pthread_exit(NULL);
    }

    while (1) {
        //std::cout << "epoll_wait" << std::endl;
        int num_fds = epoll_wait(ep_fd, events, EVENTS_BUFF_SZ, -1);
        if (events->events & (EPOLLHUP | EPOLLERR)) {
            //std::cerr << "epoll: EPOLLERR" << std::endl;
            close(events->data.fd);
            continue;
        };
        //std::cout << "data.fd" << events->data.fd << std::endl;
        if (events->data.fd == localSock) {

            struct sockaddr remote_addr;
            socklen_t addr_size = sizeof(remote_addr);

            int connection = accept(localSock, &remote_addr, &addr_size);
            if (connection == -1) {
                //perror("connection");
                continue;
            };
            fcntl(connection, F_SETFL,O_NONBLOCK | fcntl(connection, F_GETFL, 0));
            ev.data.fd = connection;
            epoll_ctl(ep_fd, EPOLL_CTL_ADD, connection, &ev);
            continue;
        }else{\
            if (handle_request(events->data.fd) == -1) {
                //fprintf(stderr, "Error handling request: %s\n", strerror(errno));
                send(events->data.fd, s404.c_str(), s404.length(), 0);
            }
            close(events->data.fd);
        }
    };
}

void main_prog() {
    /* Создание нового потокового сокета */
    int sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

    int optval = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int)) < 0)
        return;
        //std::cerr << "Cannot set SO_REUSEADDR option "
        //       << "on listen socket " << strerror(errno) << std::endl;

    optval = 1;
    if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(int)) < 0)
        return;
        //std::cerr << "Cannot set TCP_NODELAY option "
        //       << "on listen socket " << strerror(errno) << std::endl;


    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(globalArgs.port);
    if(globalArgs.ip.empty() || globalArgs.ip == "127.0.0.1")
        serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    else
        serveraddr.sin_addr.s_addr = inet_addr(globalArgs.ip.c_str());

    if (bind(sock, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        //std::cerr << "bind failed " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 64) < 0) {
        //std::cerr << "listen " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }


    pthread_t th[maxThreadsCount];
    for(int t_cnt = 0; t_cnt < maxThreadsCount; t_cnt++ ) {
        int status = pthread_create(&th[t_cnt], nullptr, (void*(*)(void *)) server_thread,(void *)&sock);
        if( status != 0 ) {
            //perror( "pthread_create" );
            exit(EXIT_FAILURE);
        }
    };
    pause();
}

void daemonize() {
    int pid;

    pid = fork();
    switch(pid) {
        case 0:
            setsid();
            chdir("/");

            close(0);
            close(1);
            close(2);


            main_prog();
        case -1:
        std::cout << "Error fork";
        break;
        default:
            break;
    }
}



int main(int argc, char* argv[])
{
    std::cout << "Параметры запуска:";
    for(int i=1; i<argc; i++)
        std::cout << " " << argv[i];
    std::cout << std::endl;


    const char *optString = "h:p:d:";
    int opt = 0;
    //	opterr=0; //если нужно запретить ошибки
    while ( (opt = getopt(argc,argv,optString)) != -1) {
        switch (opt) {
        case 'h':
            globalArgs.ip = optarg;
            break;
        case 'p':
            globalArgs.port = atoi(optarg);
            break;
        case 'd':
            globalArgs.directory = optarg;
            break;
        case '?':
            //std::cerr << "Error found !" << optarg << std::endl;
            break;
        default:
            break;
        }
    }

    daemonize();

    return 0;
}

