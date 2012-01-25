
#include <string.h>
#include <iostream>
#include <iomanip>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include "Tracer.hpp"

static int calls = 0;
static int rets = 0;

std::string Tracer::_syscall[256] = {
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
    "madvise", "getdents64", "fcntl64", "", "security", "gettid",
    "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr",
    "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr",
    "removexattr", "lremovexattr", "fremovexattr", "tkill", "sendfile64",
    "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area",
    "get_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit",
    "io_cancel", "fadvise64", "", "exit_group", "lookup_dcookie"
};


Tracer::Tracer(Options& opt) :
    _options(opt),
    _lastEip(0),
    _lastCall(0)
{

}

Tracer::~Tracer()
{

}

void Tracer::launch()
{
    if (this->_elf.loadSymTable(this->_options.getCommand()[0]))
    {
        std::cout << "Dumping symbol table :" << std::endl;
        this->_elf.printSymTable();
        char** command = this->_options.getCommand();
        if (command != 0)
        {
            std::cout << "Forking process..." << std::endl;
            this->_launchCommandProcess(command);
        }
        else
        {
            std::cout << "Attaching process..." << std::endl;
        }
    }
    else
        std::cerr << "Loading Elf SymTable failure" << std::endl;
}

void Tracer::_runChild(char** command)
{
    long res = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (res == -1)
        std::cerr << "Setting tracing on failed" << std::endl;
    else if (execvp(command[0], command)== -1)
        std::cerr << "exec failed: " << strerror(errno) << std::endl;
    exit(EXIT_FAILURE);
}

bool Tracer::_isCall()
{
    return (CALLE8(this->_lastEip) || CALL9A(this->_lastEip) || CALLFF(this->_lastEip));
}

bool Tracer::_isRet()
{
    return (RET(this->_lastEip));
}

bool Tracer::_handleSysCalls(struct user_regs_struct & data)
{
    if ((this->_lastEip & 0xffff) == 0x80cd)
    {
        if (data.eax > 255 && data.eax < 1)
            return (false);
        std::cout
            << "SYSCALL " << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << data.eax
            << " : " << this->_syscall[data.eax - 1]
            << std::endl;
        return (true);
    }
    return (false);
}

void Tracer::_handleCalls(struct user_regs_struct & data)
{
    if (this->_lastCall)
    {
        if (this->_elf.getType(data.eip) == STT_FUNC)
        {
            if (this->_callStack.begin() == this->_callStack.end())
            {
                std::cout
                    << "CALL at 0x" << std::uppercase << std::hex << this->_lastCall
                    << " to " << this->_elf.getSymbol(data.eip)
                    << std::endl;
            }
            else
            {
                std::cout
                    << "CALL at 0x"
                    << std::setfill('0') << std::setw(8) << std::uppercase << std::hex
                    << this->_lastCall
                    << " in " << this->_callStack.back()
                    << " to " << this->_elf.getSymbol(data.eip)
                    << std::endl;
            }
            this->_callStack.push_back(this->_elf.getSymbol(data.eip));
            calls++;
        }
        this->_lastCall = 0;
    }
}

void Tracer::_analyzeEip(struct user_regs_struct & data)
{
    this->_lastEip = ptrace(PTRACE_PEEKTEXT, this->_options.getPid(), data.eip, NULL);
    if (this->_lastEip != -1)
    {
        if (!this->_handleSysCalls(data))
        {
            this->_handleCalls(data);
            if (this->_isCall())
                this->_lastCall = data.eip;
            if (this->_isRet() && this->_callStack.begin() != this->_callStack.end())
            {
                if (this->_callStack.back().compare("main") != 0)
                {
                    rets++;
                    std::cout << "RET " << std::hex << this->_lastEip
                        << " eax:" << data.eax << std::endl;
                    this->_callStack.pop_back();
                }
            }
        }
    }
    else
        std::cerr << "Couldn't get eip content with ptrace" << std::endl;
}

void Tracer::_runTracer()
{
    bool end = false, signaled = false;
    int status = 0;
    struct user_regs_struct data;

    std::cout << "Tracing..." << std::endl;
    while (!end)
    {
        wait(&status);
        if (!(end = WIFEXITED(status)))
        {
            if (WIFSTOPPED(status))
            {
                if (!signaled && WSTOPSIG(status) == SIGTRAP)
                    signaled = true;
                else if (signaled)
                {
                    end = (ptrace(PTRACE_GETREGS, this->_options.getPid(), NULL, &data) == -1) ?
                        true : false;
                    if (!end)
                        this->_analyzeEip(data);
                    else
                        std::cerr << "Getting child regs with ptrace failed" << std::endl;
                }
            }
            if (!end)
            {
                end = (ptrace(PTRACE_SINGLESTEP, this->_options.getPid(), NULL, NULL) == -1) ?
                    true : false;
            }
        }
    }
    std::cout << "calls: " << calls << " rets: " << rets << std::endl;
}

bool Tracer::_launchCommandProcess(char** command)
{
    pid_t pid = fork();
    if (pid == -1)
        return false;
    if (pid == 0)
    {
        this->_runChild(command);
    }
    else
    {
        this->_options.setPid(pid);
        handle_signals(pid);
        this->_runTracer();
    }
    return true;
}

