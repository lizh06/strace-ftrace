
#include <string.h>
#include <iostream>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>

#include "Tracer.hpp"

unsigned int getOpcode()
{
    __asm__ (
        "jmp .start\n\t"
        ".opcodeval:\n\t"
        "call 0x0\n\t"
        ".start:\n\t"
        "push .opcodeval\n\t"
        "pop eax"
    );
}

Tracer::Tracer(Options& opt) :
    _options(opt)
{
}

Tracer::~Tracer()
{

}

void Tracer::launch()
{
    char** command = this->_options.getCommand();
    if (command != 0)
    {
        std::cout << "need to fork !" << std::endl;
        this->_launchCommandProcess(command);
    }
    else
    {
        std::cout << "need to attach on a pid !" << std::endl;
    }
}

bool Tracer::_launchCommandProcess(char** command)
{
    long res;
    pid_t pid = fork();
    if (pid == -1)
        return false;
    if (pid == 0)
    {
        res = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (res == -1)
            std::cerr << "Setting tracing on failed" << std::endl;
        else if (execvp(command[0], command)== -1)
            std::cerr << "exec failed: " << strerror(errno) << std::endl;
        exit(EXIT_FAILURE);
    }
    else
    {
        this->_options.setPid(pid);
        std::cout << "trace" << std::endl;
        bool end = false;
        while (!end)
        {
            wait(NULL);
            struct user_regs_struct regs;
            res = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            if (res != -1)
            {
                long opcode = -1;// ptrace(PTRACE_PEEKTEXT, pid, regs.eip, NULL);
                if (opcode != -1)
                {
                    if ((opcode & 0xFFFF) == 0x80CD)
                    {
                        std::cout << "op OK" << std::endl;
                        // if (regs.eax == SYS_close)
                           //  std::cout << "close !" << std::endl;
                    }
                }
                else
                    std::cerr << "Couldn't get opcode with ptrace" << std::endl;
            }
            else
                std::cerr << "Getting child regs with ptrace failed" << std::endl;
            res = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            if (res == -1)
                end = true;
        }
    }
    return true;
}

