#include <iostream>
#include <string.h>
#include "signals.hpp"
#include "Tracer.hpp"

static int child_pid = 0;

void sigHandler(int signum)
{
    std::cout << "SIGINT sent to process " << std::dec << child_pid << std::endl;
    if (kill(child_pid, signum) == -1)
        std::cerr << "error" << strerror(errno) << std::endl;
}

void handle_signals(int p)
{
    child_pid = p;
    signal(SIGINT, sigHandler);
}

