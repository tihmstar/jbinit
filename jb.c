
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/mount.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdarg.h>
#include <mach/mach.h>

int sandbox_check_by_audit_token(audit_token_t au, const char *operation, int sandbox_filter_type, ...);

typedef  void *posix_spawnattr_t;
typedef  void *posix_spawn_file_actions_t;
int posix_spawn(pid_t *, const char *,const posix_spawn_file_actions_t *,const posix_spawnattr_t *,char *const __argv[],char *const __envp[]);

typedef void* xpc_object_t;
typedef void* xpc_type_t;
typedef void* launch_data_t;
typedef bool (^xpc_dictionary_applier_t)(const char *key, xpc_object_t value);

xpc_object_t xpc_dictionary_create(const char * const *keys, const xpc_object_t *values, size_t count);
void xpc_dictionary_set_uint64(xpc_object_t dictionary, const char *key, uint64_t value);
void xpc_dictionary_set_string(xpc_object_t dictionary, const char *key, const char *value);
int64_t xpc_dictionary_get_int64(xpc_object_t dictionary, const char *key);
xpc_object_t xpc_dictionary_get_value(xpc_object_t dictionary, const char *key);
bool xpc_dictionary_get_bool(xpc_object_t dictionary, const char *key);
void xpc_dictionary_set_fd(xpc_object_t dictionary, const char *key, int value);
void xpc_dictionary_set_bool(xpc_object_t dictionary, const char *key, bool value);
const char *xpc_dictionary_get_string(xpc_object_t dictionary, const char *key);
void xpc_dictionary_set_value(xpc_object_t dictionary, const char *key, xpc_object_t value);
xpc_type_t xpc_get_type(xpc_object_t object);
bool xpc_dictionary_apply(xpc_object_t xdict, xpc_dictionary_applier_t applier);
int64_t xpc_int64_get_value(xpc_object_t xint);
char *xpc_copy_description(xpc_object_t object);
void xpc_dictionary_set_int64(xpc_object_t dictionary, const char *key, int64_t value);
const char *xpc_string_get_string_ptr(xpc_object_t xstring);
xpc_object_t xpc_array_create(const xpc_object_t *objects, size_t count);
xpc_object_t xpc_string_create(const char *string);
size_t xpc_dictionary_get_count(xpc_object_t dictionary);
void xpc_array_append_value(xpc_object_t xarray, xpc_object_t value);

#define XPC_ARRAY_APPEND ((size_t)(-1))
#define XPC_ERROR_CONNECTION_INVALID XPC_GLOBAL_OBJECT(_xpc_error_connection_invalid)
#define XPC_ERROR_TERMINATION_IMMINENT XPC_GLOBAL_OBJECT(_xpc_error_termination_imminent)
#define XPC_TYPE_ARRAY (&_xpc_type_array)
#define XPC_TYPE_BOOL (&_xpc_type_bool)
#define XPC_TYPE_DICTIONARY (&_xpc_type_dictionary)
#define XPC_TYPE_ERROR (&_xpc_type_error)
#define XPC_TYPE_STRING (&_xpc_type_string)


extern const struct _xpc_dictionary_s _xpc_error_connection_invalid;
extern const struct _xpc_dictionary_s _xpc_error_termination_imminent;
extern const struct _xpc_type_s _xpc_type_array;
extern const struct _xpc_type_s _xpc_type_bool;
extern const struct _xpc_type_s _xpc_type_dictionary;
extern const struct _xpc_type_s _xpc_type_error;
extern const struct _xpc_type_s _xpc_type_string;

#define DYLD_INTERPOSE(_replacment,_replacee) \
__attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

/*
  Workaround for _wrong_ "rd=md0" detection patch.

  Ideally you want to patch the kernel to look for "dd=md0" (or something along the lines)
  instead of "rd=md0". That is to pass those kind of checks in several userspace daemons.
  This is especially problematic in iOS 16 dyld.
  However i haven't implemented that kernelpatch yet, that's why here i just patch launchd.

  Don't forget to also do the _normal_ "rd=md0" patches in kernel, so that kexts don't think we are
  in restore mode.
*/
int my_sysctlbyname(const	char *name, void *oldp,	size_t *oldlenp, void *newp, size_t newlen){
    int ret = sysctlbyname(name, oldp, oldlenp, newp, newlen);
    if (oldp) {
      char *tgt = strnstr(oldp, "rd=md0", oldlenp ? *oldlenp : 0);
      if (tgt){
        memset(tgt, ' ', 6);
      }
    }
    return ret;
}
DYLD_INTERPOSE(my_sysctlbyname, sysctlbyname);


/*
  Launch our Daemon *correctly*
*/
xpc_object_t my_xpc_dictionary_get_value(xpc_object_t dict, const char *key){
  xpc_object_t retval = xpc_dictionary_get_value(dict,key);
  if (strcmp(key,"LaunchDaemons") == 0) {
    xpc_object_t submitJob = xpc_dictionary_create(NULL, NULL, 0);
    xpc_object_t programArguments = xpc_array_create(NULL, 0);

    xpc_array_append_value(programArguments, xpc_string_create("/jbloader"));

    xpc_dictionary_set_bool(submitJob, "KeepAlive", false);
    xpc_dictionary_set_bool(submitJob, "RunAtLoad", true);
    xpc_dictionary_set_string(submitJob, "UserName", "root");
    xpc_dictionary_set_string(submitJob, "Program", "/jbloader");
    xpc_dictionary_set_string(submitJob, "Label", "jbloader");
    xpc_dictionary_set_value(submitJob, "ProgramArguments", programArguments);

    xpc_dictionary_set_value(retval, "/System/Library/LaunchDaemons/net.tihmstar.jbloader.plist", submitJob);
  }
  return retval;
}
DYLD_INTERPOSE(my_xpc_dictionary_get_value, xpc_dictionary_get_value);

/*
  Every single process is allowed to lookup bootstrap ports starting with "jb-global-"
  This is inteded to pass tfp0 to sandboxed processes used for debugging kernel stuff with Xcode.

  Additionally, every sandboxed process is allowed to lookup and register bootstrap ports starting with "jb-global-unsandbox-".
  This can be used for registering bootstrap ports from sandboxed processes and looking them up in other sandboxed processes.
*/
int my_sandbox_check_by_audit_token(audit_token_t au, const char *operation, int sandbox_filter_type, ...) {
    va_list a;
    va_start(a, sandbox_filter_type);
    const char *name = va_arg(a, const char *);
    const void *arg2 = va_arg(a, void *);
    const void *arg3 = va_arg(a, void *);
    const void *arg4 = va_arg(a, void *);
    const void *arg5 = va_arg(a, void *);
    const void *arg6 = va_arg(a, void *);
    const void *arg7 = va_arg(a, void *);
    const void *arg8 = va_arg(a, void *);
    const void *arg9 = va_arg(a, void *);
    const void *arg10 = va_arg(a, void *);
    va_end(a);
    if (name && operation) {
        if (strcmp(operation, "mach-lookup") == 0) {
            if (strncmp((char *)name, "jb-global-", sizeof("jb-global-")-1) == 0) {
                  return 0;
            }
        }else if (strcmp(operation, "mach-register") == 0) {
            if (strncmp((char *)name, "jb-global-unsandbox-", sizeof("jb-global-unsandbox-")-1) == 0) {
                return 0;
            }
        }
    }
    return sandbox_check_by_audit_token(au, operation, sandbox_filter_type, name, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}
DYLD_INTERPOSE(my_sandbox_check_by_audit_token, sandbox_check_by_audit_token);

__attribute__((constructor))
static void customConstructor(int argc, const char **argv){
  int fd_console = open("/dev/console",O_RDWR,0);
  dprintf(fd_console,"================ Hello from jb.dylib ================ \n");
  unlink("/jb.dylib");
  dprintf(fd_console,"========= Goodbye from jb.dylib constructor ========= \n");
  close(fd_console);
}
