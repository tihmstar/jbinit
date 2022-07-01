#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <termios.h>
#include <sys/clonefile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <mach/mach.h>

#define true 1
#define false 0

kern_return_t bootstrap_register(mach_port_t, char *, mach_port_t);

typedef  void *posix_spawnattr_t;
typedef  void *posix_spawn_file_actions_t;
int posix_spawn(pid_t *, const char *,const posix_spawn_file_actions_t *,const posix_spawnattr_t *,char *const __argv[],char *const __envp[]);

int openLogTCP(){
  int err = 0;
  int serverfd = 0;
  struct sockaddr_in servaddr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = htonl(INADDR_ANY),
      .sin_port = htons(3333)
  };

  if (!((serverfd = socket(AF_INET, SOCK_STREAM, 0))>0)){
    printf("Failed to creat server socket\n");
    return -1;
  }
  printf("[TCPLog] Socket ok\n");

  if (!(err = bind(serverfd, (struct sockaddr*)&servaddr, sizeof(servaddr)))){
    printf("Failed to bind socket with error=%d errno=%d (%s)\n",err,errno,strerror(errno));
    return -1;
  }
  printf("[TCPLog] Bind ok\n");

  if ((err = listen(serverfd, 100))){
    printf("Failed to listen on socket with error=%d errno=%d (%s)\n",err,errno,strerror(errno));
    return -1;
  }
  printf("[TCPLog] Listen ok\n");

  int connfd = 0;
  struct sockaddr_in client = {};
  ssize_t len = 0;
  if (!((connfd = accept(serverfd, (struct sockaddr*)&client, (socklen_t*)&len))>0)){
    printf("Failed to accept client\n");
    return -1;
  }
  printf("[TCPLog] Accepted client connection!\n");

  close(0);
  close(1);
  close(2);

  dup2(connfd,0);
  dup2(connfd,1);
  dup2(connfd,2);
  dprintf(connfd,"Hello from TCP!\n");
error:
  return err;
}

int run(const char *cmd, char * const *args){
    int pid = 0;
    int retval = 0;
    char printbuf[0x1000] = {};
    for (char * const *a = args; *a; a++) {
        size_t csize = strlen(printbuf);
        if (csize >= sizeof(printbuf)) break;
        snprintf(printbuf+csize,sizeof(printbuf)-csize, "%s ",*a);
    }

    retval = posix_spawn(&pid, cmd, NULL, NULL, args, NULL);
    printf("Execting: %s (posix_spawn returned: %d)\n",printbuf,retval);
    {
        int pidret = 0;
        printf("waiting for '%s' to finish...\n",printbuf);
        retval = waitpid(pid, &pidret, 0);
        printf("waitpid for '%s' returned: %d\n",printbuf,retval);
        return pidret;
    }
    return retval;
}

int loadDaemons(void){
  DIR *d = NULL;
  struct dirent *dir = NULL;

  if (!(d = opendir("/Library/LaunchDaemons/"))){
    printf("Failed to open dir with err=%d (%s)\n",errno,strerror(errno));
    return -1;
  }

  while ((dir = readdir(d))) { //remove all subdirs and files
      if (strcmp(dir->d_name, ".") == 0 || strcmp(dir->d_name, "..") == 0) {
          continue;
      }
      char *pp = NULL;
      asprintf(&pp,"/Library/LaunchDaemons/%s",dir->d_name);

      {
        const char *args[] = {
          "/bin/launjctl",
          "load",
          pp,
          NULL
        };
        run(args[0],args);
      }
      free(pp);
  }
  closedir(d);
  return 0;
}

int deployFiles(const char *binary, const char *data){
  int err = 0;
  int serverfd = 0;
  struct sockaddr_in servaddr = {
      .sin_family = AF_INET,
      .sin_addr.s_addr = htonl(INADDR_ANY),
      .sin_port = htons(7777)
  };

  if (!((serverfd = socket(AF_INET, SOCK_STREAM, 0))>0)){
    printf("Failed to creat server socket\n");
    return -1;
  }
  printf("[deployFiles] Socket ok\n");

  if (!(err = bind(serverfd, (struct sockaddr*)&servaddr, sizeof(servaddr)))){
    printf("Failed to bind socket with error=%d errno=%d (%s)\n",err,errno,strerror(errno));
    return -1;
  }
  printf("[deployFiles] Bind ok\n");

  if ((err = listen(serverfd, 100))){
    printf("Failed to listen on socket with error=%d errno=%d (%s)\n",err,errno,strerror(errno));
    return -1;
  }
  printf("[deployFiles] Listen ok\n");

  int connfd = 0;
  struct sockaddr_in client = {};
  ssize_t len = 0;
  if (!((connfd = accept(serverfd, (struct sockaddr*)&client, (socklen_t*)&len))>0)){
    printf("Failed to accept client\n");
    return -1;
  }
  printf("[deployFiles] Accepted client connection for binary!\n");

  {
    int fd_bin = -1;
    if ((fd_bin = open(binary, O_CREAT | O_WRONLY | O_TRUNC, 0755)) == -1) {
      printf("failed to open '%s'\n",binary);
      return -1;
    }
    char buf[0x400];
    size_t len = 0;
    size_t didRead = 0;
    while ((len = read(connfd, buf, sizeof(buf))) > 0) {
      didRead += len;
        write(fd_bin, buf, len);
    }
    printf("wrote %d bytes binary\n",didRead);
    chmod(binary,0755);
    close(fd_bin);
  }

  if (!((connfd = accept(serverfd, (struct sockaddr*)&client, (socklen_t*)&len))>0)){
    printf("Failed to accept client\n");
    return -1;
  }
  printf("[deployFiles] Accepted client connection for data!\n");

  {
    int fd_bin = -1;
    if ((fd_bin = open(data, O_CREAT | O_WRONLY | O_TRUNC, 0755)) == -1) {
      printf("failed to open '%s'\n",data);
      return -1;
    }
    char buf[0x400];
    size_t len = 0;
    size_t didRead = 0;
    while ((len = read(connfd, buf, sizeof(buf))) > 0) {
      didRead += len;
        write(fd_bin, buf, len);
    }
    printf("wrote %d bytes data\n",didRead);
    close(fd_bin);
  }

  const char *args[] = {
    binary,
    "--preserve-permissions",
    "-xkvf",
    data,
    "-C",
    "/",
    NULL
  };
  run(args[0],args);

  {
    char *args[]= {
                  "/bin/sh",
                  "/prep_bootstrap.sh",
                  NULL
              };
    run(args[0],args);
  }

  loadDaemons();

  // sleep(20);
  // {
  //   char *args[]= {
  //                 "/bin/sh",
  //                 "/usr/libexec/sshd-keygen-wrapper",
  //                 "-p",
  //                 "2223",
  //                 NULL
  //             };
  //   run(args[0],args);
  // }

  printf("deployFiles ok!\n");

error:
  if (err) {
    printf("deployFiles FAILED %d\n",err);
  }
    return err;
}


int giveTFP0AccessToSandboxedProcesses(void){
  task_t kernel_task = MACH_PORT_NULL;
  kern_return_t ret = task_for_pid(mach_task_self(), 0, &kernel_task);
  printf("task_for_pid=0x%08x\n",ret);
  printf("kernel_task=0x%08x\n",kernel_task);
  ret = bootstrap_register(bootstrap_port, "jb-global-tfp0", kernel_task);
  printf("bootstrap_register=0x%08x\n",ret);
  return 0;
}

int main(int argc, char **argv){
  unlink(argv[0]);
  setvbuf(stdout, NULL, _IONBF, 0);

  // giveTFP0AccessToSandboxedProcesses();

  loadDaemons();

  openLogTCP();
  printf("Hello from jbloader!\n");

  deployFiles("/bin/tar","/tmp/data.tar.gz");

  printf("Bye from jbloader!\n");
  return 0;
}
