
#ifndef OPTIONS_HPP__
# define OPTIONS_HPP__

# include <sys/types.h>

class Options
{
    public:
        Options();
        Options(int ac, char **av);
        virtual ~Options();

    public:
        pid_t getPid() const;
        void setPid(pid_t pid);
        char** getCommand() const;
        void parseArgs(int ac, char** av);

    private:
        void _printUsage(char* progName);

    private:
        pid_t _pid;
        char** _command;
};

#endif // OPTIONS_HPP__
