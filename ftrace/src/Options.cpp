
#include <iostream>
#include "Options.hpp"

Options::Options() :
    _pid(0),
    _command(0)
{

}

Options::Options(int ac, char** av) :
    _pid(0),
    _command(0)
{
    this->parseArgs(ac, av);
}

Options::~Options()
{

}

void Options::_printUsage(char* progName)
{
    std::cerr << "Usage:\t" << progName << " -p pid" << std::endl;
    std::cerr << "\t" << progName << " command" << std::endl;
}

void Options::parseArgs(int ac, char** av)
{
    if (ac > 1)
    {
        std::string arg(av[1]);
        if (arg[0] == '-')
        {
            if (arg.compare("-p") == 0)
            {
                if (ac > 2)
                {
                    this->_pid = atoi(av[2]);
                }
                else
                {
                    std::cerr << "-p take one argument" << std::endl;
                    this->_printUsage(av[0]);
                }
            }
            else if (arg.compare("--help") == 0 || arg.compare("-h") == 0)
            {
                this->_printUsage(av[0]);
            }
            else
            {
                std::cerr << "Argument not supported: " << arg << std::endl;
                this->_printUsage(av[0]);
            }
        }
        else
        {
            this->_command = av + 1;
        }
    }
    else
    {
        this->_printUsage(av[0]);
    }
}

pid_t Options::getPid() const
{
    return this->_pid;
}

void Options::setPid(pid_t pid)
{
    this->_pid = pid;
}

char** Options::getCommand() const
{
    return this->_command;
}

