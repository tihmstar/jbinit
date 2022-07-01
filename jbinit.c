
#include <stdint.h>
#include "printf.h"

asm(
  ".globl __dyld_start\n"
  ".align 4\n"
  "__dyld_start:\n"
  "movn x8, #0xf\n"
  "mov x7, sp\n"
  "and x7, x7, x8\n"
  "mov sp, x7\n"
  "bl _main\n"
  "movz x16, #0x1\n"
  "svc #0x80\n"
);

#define STDOUT_FILENO 1
#define getpid() msyscall(20)
#define exit(err) msyscall(1,err)
#define fork() msyscall(2)
#define puts(str) write(STDOUT_FILENO,str,sizeof(str)-1)

typedef uint32_t kern_return_t;
typedef uint32_t mach_port_t;
typedef uint64_t mach_msg_timeout_t;
// typedef uint64_t size_t;

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR   2
#define O_CREAT         0x00000200      /* create if nonexistant */

#define SEEK_SET    0
#define SEEK_CUR    1
#define SEEK_END    2

#define PROT_NONE       0x00    /* [MC2] no permissions */
#define PROT_READ       0x01    /* [MC2] pages can be read */
#define PROT_WRITE      0x02    /* [MC2] pages can be written */
#define PROT_EXEC       0x04    /* [MC2] pages can be executed */

#define MAP_FILE        0x0000  /* map from file (default) */
#define MAP_ANON        0x1000  /* allocated from memory, swap space */
#define MAP_ANONYMOUS   MAP_ANON
#define MAP_SHARED      0x0001          /* [MF|SHM] share changes */
#define MAP_PRIVATE     0x0002          /* [MF|SHM] changes are private */


#define	MNT_RDONLY	0x00000001
#define	MNT_LOCAL	  0x00001000
#define MNT_ROOTFS      0x00004000      /* identifies the root filesystem */
#define MNT_UNION       0x00000020
#define MNT_UPDATE      0x00010000      /* not a real mount, just an update */
#define MNT_NOBLOCK     0x00020000      /* don't block unmount if not responding */
#define MNT_RELOAD      0x00040000      /* reload filesystem data */
#define MNT_FORCE       0x00080000      /* force unmount or readonly change */


__attribute__((naked)) kern_return_t thread_switch(mach_port_t new_thread,int option, mach_msg_timeout_t time){
  asm(
    "movn x16, #0x3c\n"
    "svc 0x80\n"
    "ret\n"
  );
}

__attribute__((naked)) uint64_t msyscall(uint64_t syscall, ...){
  asm(
    "mov x16, x0\n"
    "ldp x0, x1, [sp]\n"
    "ldp x2, x3, [sp, 0x10]\n"
    "ldp x4, x5, [sp, 0x20]\n"
    "ldp x6, x7, [sp, 0x30]\n"
    "svc 0x80\n"
    "ret\n"
  );
}

void sleep(int secs){
  thread_switch(0,2,secs*1000);
}

int sys_dup2(int from, int to){
  return msyscall(90,from,to);
}

int stat(void *path, void *ub){
  return msyscall(188,path,ub);
}

int mkdir(void *path, int mode){
  return msyscall(136,path,mode);
}

int chroot(void *path){
  return msyscall(61,path);
}

int mount(char *type, char *path, int flags, void *data){
  return msyscall(167,type,path,flags,data);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, uint64_t offset){
  return (void*)msyscall(197,addr,length,prot,flags,fd,offset);
}

uint64_t read(int fd, void* cbuf, size_t nbyte){
  return msyscall(3,fd,cbuf,nbyte);
}

uint64_t write(int fd, void* cbuf, size_t nbyte){
  return msyscall(4,fd,cbuf,nbyte);
}

int close(int fd){
  return msyscall(6,fd);
}

int open(void *path, int flags, int mode){
  return msyscall(5,path,flags,mode);
}

int execve(char *fname, char *const argv[], char *const envp[]){
  return msyscall(59,fname,argv,envp);
}


void _putchar(char character){
  static size_t chrcnt = 0;
  static char buf[0x100];
  buf[chrcnt++] = character;
  if (character == '\n' || chrcnt == sizeof(buf)){
    write(STDOUT_FILENO,buf,chrcnt);
    chrcnt = 0;
  }
}


void spin(){
  puts("jbinit DIED!\n");
  while (1){
    sleep(5);
  }
}

void memcpy(void *dst, void *src, size_t n){
  uint8_t *s =(uint8_t *)src;
  uint8_t *d =(uint8_t *)dst;
  for (size_t i = 0; i<n; i++) *d++ = *s++;
}

void memset(void *dst, int c, size_t n){
  uint8_t *d =(uint8_t *)dst;
  for (size_t i = 0; i<n; i++) *d++ = c;
}

int main(){
  int fd_console = open("/dev/console",O_RDWR,0);
  sys_dup2(fd_console,0);
  sys_dup2(fd_console,1);
  sys_dup2(fd_console,2);
  char statbuf[0x400];

  puts("================ Hello from jbinit ================ \n");

  puts("Checking for roots\n");
  {
    while (stat("/dev/disk0s1s1", statbuf)) {
      puts("waiting for roots...\n");
      sleep(1);
    }
  }
  puts("Got rootfs\n");

  {
    char *path = "/dev/md0";
    int err = mount("apfs","/",MNT_UPDATE, &path);
    if (!err) {
      puts("remount rdisk OK\n");
    }else{
      puts("remount rdisk FAIL\n");
    }
  }

  puts("Got opening jb.dylib\n");
  int fd_dylib = 0;
  fd_dylib = open("/jb.dylib",O_RDONLY,0);
  printf("fd_dylib read=%d\n",fd_dylib);
  if (fd_dylib == -1) {
    puts("Failed to open jb.dylib for reading");
    spin();
  }
  size_t dylib_size = msyscall(199,fd_dylib,0,SEEK_END);
  printf("dylib_size=%d\n",dylib_size);
  msyscall(199,fd_dylib,0,SEEK_SET);

  puts("reading jb.dylib\n");
  void *dylib_data = mmap(NULL, (dylib_size & ~0x3fff) + 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
  printf("dylib_data=0x%016llx\n",dylib_data);
  if (dylib_data == (void*)-1) {
    puts("Failed to mmap");
    spin();
  }
  int didread = read(fd_dylib,dylib_data,dylib_size);
  printf("didread=%d\n",didread);
  close(fd_dylib);


  puts("Got opening jbloader\n");
  int fd_jbloader = 0;
  fd_jbloader = open("/sbin/launchd",O_RDONLY,0);
  printf("fd_jbloader read=%d\n",fd_jbloader);
  if (fd_jbloader == -1) {
    puts("Failed to open fd_jbloader for reading");
    spin();
  }
  size_t jbloader_size = msyscall(199,fd_jbloader,0,SEEK_END);
  printf("jbloader_size=%d\n",jbloader_size);
  msyscall(199,fd_jbloader,0,SEEK_SET);

  puts("reading jbloader\n");
  void *jbloader_data = mmap(NULL, (jbloader_size & ~0x3fff) + 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
  printf("jbloader_data=0x%016llx\n",jbloader_data);
  if (jbloader_data == (void*)-1) {
    puts("Failed to mmap");
    spin();
  }
  didread = read(fd_jbloader,jbloader_data,jbloader_size);
  printf("didread=%d\n",didread);
  close(fd_jbloader);

  {
    char buf[0x100];
    struct mounarg {
      char *path;
      uint64_t _null;
      uint64_t mountAsRaw;
      uint32_t _pad;
      char snapshpt[0x100];
    } arg = {
      "/dev/disk0s1s1",
      0,
      1, //1 mount without snapshot, 0 mount snapshot
      0,
    };
    int err = 0;
retry_rootfs_mount:
    puts("mounting rootfs\n");
    err = mount("apfs","/",0, &arg);
    if (!err) {
      puts("mount rootfs OK\n");
    }else{
      printf("mount rootfs FAILED with err=%d!\n",err);
      sleep(1);
      // spin();
    }


    if (stat("/private/", statbuf)) {
      printf("stat /private/ FAILED with err=%d!\n",err);
      sleep(1);
      goto retry_rootfs_mount;
    }else{
      puts("stat /private/ OK\n");
    }
  }

  puts("mounting devfs\n");
  {
    char *path = "devfs";
    int err = mount("devfs","/dev/",0, path);
    if (!err) {
      puts("mount devfs OK\n");
    }else{
      printf("mount devfs FAILED with err=%d!\n",err);
      spin();
    }
  }

  puts("deploying jb.dylib\n");
  fd_dylib = open("/jb.dylib",O_WRONLY | O_CREAT,0755);
  printf("jb write fd=%d\n",fd_dylib);
  if (fd_dylib == -1) {
    puts("Failed to open /jb.dylib for writing");
    spin();
  }
  int didwrite = write(fd_dylib,dylib_data,dylib_size);
  printf("didwrite=%d\n",didwrite);
  close(fd_dylib);

  {
    int err = 0;
    if ((err = stat("/jb.dylib", statbuf))) {
      printf("stat /jb.dylib FAILED with err=%d!\n",err);
      spin();
    }else{
      puts("stat /jb.dylib OK\n");
    }
  }

  printf("done deploying /jbloader!\n");

  puts("deploying jbloader\n");
  fd_jbloader = open("/jbloader",O_WRONLY | O_CREAT,0755);
  printf("jbloader write fd=%d\n",fd_jbloader);
  if (fd_jbloader == -1) {
    puts("Failed to open /jbloader for writing");
    spin();
  }
  didwrite = write(fd_jbloader,jbloader_data,jbloader_size);
  printf("didwrite=%d\n",didwrite);
  close(fd_jbloader);

  {
    int err = 0;
    if ((err = stat("/jbloader", statbuf))) {
      printf("stat /jbloader FAILED with err=%d!\n",err);
      spin();
    }else{
      puts("stat /jbloader OK\n");
    }
  }

  printf("done deploying /jbloader!\n");

  {
    int err = 0;
    if ((err = stat("/sbin/launchd", statbuf))) {
      printf("stat /sbin/launchd FAILED with err=%d!\n",err);
    }else{
      puts("stat /sbin/launchd OK\n");
    }
  }

  puts("Closing console, goodbye!\n");

  /*
    Launchd doesn't like it when the console is open already!
  */
  for (size_t i = 0; i < 10; i++) {
    close(i);
  }

  {
    char **argv = (char **)dylib_data;
    char **envp = argv+2;
    char *strbuf = (char*)(envp+2);
    argv[0] = strbuf;
    argv[1] = NULL;
    memcpy(strbuf,"/sbin/launchd",sizeof("/sbin/launchd"));
    strbuf += sizeof("/sbin/launchd");
    envp[0] = strbuf;
    envp[1] = NULL;

    char envvars[] = "DYLD_INSERT_LIBRARIES=/jb.dylib";
    memcpy(strbuf,envvars,sizeof(envvars));
    int err = execve(argv[0],argv,envp);
    if (err) {
      printf("execve FAILED with err=%d!\n",err);
      spin();
    }
  }

  puts("FATAL: shouldn't get here!\n");
  spin();

  return 0;
}
