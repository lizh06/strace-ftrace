
#include <string.h>
#include <iostream>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "Tracer.hpp"

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
    pid_t pid = fork();
    if (pid == -1)
        return false;
    if (pid == 0)
    {
        int res = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
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
            long orig_eax = ptrace(PTRACE_PEEKUSER, this->_options.getPid(), sizeof(long) * 11, NULL);
            if (orig_eax == -1)
                std::cerr << "ptrace peek user failed: " << strerror(errno) << std::endl;
            else
            {
                if (orig_eax > 0 && orig_eax < 150)
                    std::cout << "system call: " << orig_eax << "\t" << strerror(errno) << std::endl;
            }
            int res = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            if (res == -1)
                end = true;
        }
    }
    return true;
}

