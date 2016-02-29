#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <string>
#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#include <sys/sendfile.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
#include <signal.h>

//#define SERVERPORT 1111
#define SERVERBACKLOG 10
#define THREADSNO 20
#define EVENTS_BUFF_SZ 256

static int serversock;
static int epoll_fd;
static pthread_t threads[THREADSNO];

struct globalArgs_t {
    std::string ip;         /* параметр -h */
    std::string directory;  /* параметр -d */
    int port;               /* параметр -p */
};

globalArgs_t globalArgs = {"127.0.0.1", "/home/alk/C++/WebServer", 8080};
std::string s404 = "HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\n\r\n";



void Sendrequest404(int &clientfd){
    send(clientfd, s404.c_str(), s404.length(), 0);
}

int accept_new_client(void)
{

   int clientsock;
   struct sockaddr_in addr;
   socklen_t addrlen = sizeof(addr);
   if ((clientsock = accept(serversock, (struct sockaddr *)&addr, &addrlen)) < 0) {
       return -1;
   }

   char ip_buff[INET_ADDRSTRLEN + 1];
   if (inet_ntop(AF_INET, &addr.sin_addr, ip_buff, sizeof(ip_buff)) == NULL) {
       close(clientsock);
       return -1;
   }

   //printf("*** [%p] Client connected from %s:%d\n", (void *)pthread_self(), ip_buff, ntohs(addr.sin_port));

   struct epoll_event epevent;
   epevent.events = EPOLLIN | EPOLLET;
   epevent.data.fd = clientsock;

   if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, clientsock, &epevent) < 0) {
       perror("epoll_ctl(2) failed attempting to add new client");
       close(clientsock);
       return -1;
   }

   return 0;
}

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

    //printf("readbuff %s\n", readbuff);

   char* save_ptr;
   char* command_line = strtok_r(readbuff, "\r\n", &save_ptr);
   if( command_line == NULL )
   {
       Sendrequest404(clientfd);
       return 0;
   }

   char* method = strtok_r(command_line, "\t ", &save_ptr);
   if( method == NULL )
   {
       Sendrequest404(clientfd);
       return 0;
   }
   char* uri = strtok_r(NULL, "\t ", &save_ptr);
   if( uri == NULL )
   {
       Sendrequest404(clientfd);
       return 0;
   }
   //std::cout << "URI :" << uri << ":\n";
   char* file_path = strtok_r(uri, "?", &save_ptr);
   if( file_path == NULL )
   {
       Sendrequest404(clientfd);
       return 0;
   }

   std::string sUsedFileName = file_path;


   if(sUsedFileName.empty()){
       //return -1;
       sUsedFileName = "/index.html";
   }else if (sUsedFileName[sUsedFileName.size()-1]=='/'){
       sUsedFileName += "index.html";
   }

   sUsedFileName = globalArgs.directory + sUsedFileName;

   struct stat buf;
   if(stat(sUsedFileName.c_str(), &buf)!=0){
       //perror("stat");
       //syslog(LOG_ERR, "stat");
       Sendrequest404(clientfd);
       return 0;
   }
    if (buf.st_mode & S_IFDIR){
        //syslog(LOG_ERR, "S_IFDIR");
        Sendrequest404(clientfd);
        return 0;
    }


   //syslog(LOG_ERR, sUsedFileName.c_str());
    //printf("open\n");

    int NewHandle = open(sUsedFileName.c_str(), O_RDONLY);
    if(NewHandle==-1){
        Sendrequest404(clientfd);
        return 0;
    }
    int NewSize = lseek(NewHandle, 0, SEEK_SET);
    if (NewSize == -1 || (NewSize = lseek(NewHandle, 0, SEEK_END)) == -1 || lseek(NewHandle, 0, SEEK_SET) == -1)
    {
        close(NewHandle);
        Sendrequest404(clientfd);
        return 0;
    }

    struct stat file_stat;
    fstat(NewHandle, &file_stat);
    const char replay_header_template[] =
            "HTTP/1.0 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Content-Length: %lu\r\n\r\n";
    char header_buf[4096];
    int header_size = snprintf(header_buf, 4095, replay_header_template, file_stat.st_size);

    ssize_t sent;
    if ((sent = send(clientfd, header_buf, header_size, 0)) < 0) {
        return -1;
    }

    off_t Offset = 0;
    sendfile(clientfd, NewHandle, &Offset, NewSize-Offset);

    //printf("sendfile2\n");

   return 0;
}

void *worker_thr(void *args)
{
   struct epoll_event *events = (struct epoll_event *)malloc(sizeof(*events) * EVENTS_BUFF_SZ);
   if (events == NULL) {
       perror("malloc(3) failed when attempting to allocate events buffer");
       pthread_exit(NULL);
   }

   int events_cnt;
   while ((events_cnt = epoll_wait(epoll_fd, events, EVENTS_BUFF_SZ, -1)) > 0) {
       int i;
       for (i = 0; i < events_cnt; i++) {
           assert(events[i].events & EPOLLIN);

           if (events[i].data.fd == serversock) {
               if (accept_new_client() == -1) {
                   fprintf(stderr, "Error accepting new client: %s\n", strerror(errno));
               }
           } else {
               if (handle_request(events[i].data.fd) == -1) {
                   fprintf(stderr, "Error handling request: %s\n", strerror(errno));
               }
               //printf("close\n");
               close(events[i].data.fd);
           }
       }
   }

   if (events_cnt == 0) {
       fprintf(stderr, "epoll_wait(2) returned 0, but timeout was not specified...?");
   } else {
       perror("epoll_wait(2) error");
   }

   free(events);

   return NULL;
}

int main_prog()
{
   if ((serversock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
       perror("socket(2) failed");
       exit(EXIT_FAILURE);
   }

   struct sockaddr_in serveraddr;
   serveraddr.sin_family = AF_INET;
   serveraddr.sin_port = htons(globalArgs.port);
   serveraddr.sin_addr.s_addr = INADDR_ANY;

   if (bind(serversock, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
       perror("bind(2) failed");
       exit(EXIT_FAILURE);
   }

   if (listen(serversock, SERVERBACKLOG) < 0) {
       perror("listen(2) failed");
       exit(EXIT_FAILURE);
   }

   if ((epoll_fd = epoll_create(1)) < 0) {
       perror("epoll_create(2) failed");
       exit(EXIT_FAILURE);
   }

   struct epoll_event epevent;
   epevent.events = EPOLLIN | EPOLLET;
   epevent.data.fd = serversock;

   if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, serversock, &epevent) < 0) {
       perror("epoll_ctl(2) failed on main server socket");
       exit(EXIT_FAILURE);
   }

   int i;
   for (i = 0; i < THREADSNO; i++) {
       if (pthread_create(&threads[i], NULL, worker_thr, NULL) < 0) {
           perror("pthread_create(3) failed");
           exit(EXIT_FAILURE);
       }
   }

   /* main thread also contributes as worker thread */
   worker_thr(NULL);

   return 0;
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
    struct sigaction sa;
    sigset_t newset;
    sigemptyset(&newset);
    sigaddset(&newset, SIGHUP);
    sigprocmask(SIG_BLOCK, &newset, 0);


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
