/*!
 * \file	SyscallNames.hpp
 * \brief	
 * \author	Alexis Lucazeau - lucaze_b@epitech.eu
 * \version	0.1
 * \date	01/24/2012 11:53:37 AM
 *
 * more description...
 */

char *(syscall[256]) = {
  "exit", "fork", "read", "write", "open", "close", "waitpid", "creat",
  "link", "unlink", "execve", "chdir", "time", "mknod", "chmod",
  "lchown", "break", "oldstat", "lseek", "getpid", "mount", "umount",
  "setuid", "getuid", "stime", "ptrace", "alarm", "oldfstat", "pause",
  "utime", "stty", "gtty", "access", "nice", "ftime", "sync", "kill",
  "rename", "mkdir", "rmdir", "dup", "pipe", "times", "prof", "brk",
  "setgid", "getgid", "signal", "geteuid", "getegid", "acct", "umount2",
  "lock", "ioctl", "fcntl", "mpx", "setpgid", "ulimit", "oldolduname",
  "umask", "chroot", "ustat", "dup2", "getppid", "getpgrp", "setsid",
  "sigaction", "sgetmask", "ssetmask", "setreuid", "setregid",
  "sigsuspend", "sigpending", "sethostname", "setrlimit", "getrlimit",
  "getrusage", "gettimeofday", "settimeofday", "getgroups", "setgroups",
  "select", "symlink", "oldlstat", "readlink", "uselib", "swapon",
  "reboot", "readdir", "mmap", "munmap", "truncate", "ftruncate",
  "fchmod", "fchown", "getpriority", "setpriority", "profil", "statfs",
  "fstatfs", "ioperm", "socketcall", "syslog", "setitimer", "getitimer",
  "stat", "lstat", "fstat", "olduname", "iopl", "vhangup", "idle",
  "vm86old", "wait4", "swapoff", "sysinfo", "ipc", "fsync", "sigreturn",
  "clone", "setdomainname", "uname", "modify_ldt", "adjtimex",
  "mprotect", "sigprocmask", "create_module", "init_module",
  "delete_module", "get_kernel_syms", "quotactl", "getpgid", "fchdir",
  "bdflush", "sysfs", "personality", "afs_syscall", "setfsuid",
  "setfsgid", "_llseek", "getdents", "_newselect", "flock", "msync",
  "readv", "writev", "getsid", "fdatasync", "_sysctl", "mlock",
  "munlock", "mlockall", "munlockall", "sched_setparam",
  "sched_getparam", "sched_setscheduler", "sched_getscheduler",
  "sched_yield", "sched_get_priority_max", "sched_get_priority_min",
  "sched_rr_get_interval", "nanosleep", "mremap", "setresuid",
  "getresuid", "vm86", "query_module", "poll", "nfsservctl",
  "setresgid", "getresgid", "prctl", "rt_sigreturn", "rt_sigaction",
  "rt_sigprocmask", "rt_sigpending", "rt_sigtimedwait",
  "rt_sigqueueinfo", "rt_sigsuspend", "pread", "pwrite", "chown",
  "getcwd", "capget", "capset", "sigaltstack", "sendfile", "getpmsg",
  "putpmsg", "vfork", "ugetrlimit", "mmap2", "truncate64",
  "ftruncate64", "stat64", "lstat64", "fstat64", "lchown32", "getuid32",
  "getgid32", "geteuid32", "getegid32", "setreuid32", "setregid32",
  "getgroups32", "setgroups32", "fchown32", "setresuid32",
  "getresuid32", "setresgid32", "getresgid32", "chown32", "setuid32",
  "setgid32", "setfsuid32", "setfsgid32", "pivot_root", "mincore",
  "madvise", "getdents64", "fcntl64", 0, "security", "gettid",
  "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr",
  "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr",
  "removexattr", "lremovexattr", "fremovexattr", "tkill", "sendfile64",
  "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
  "get_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit",
  "io_cancel", "fadvise64", 0, "exit_group", "lookup_dcookie"
};
