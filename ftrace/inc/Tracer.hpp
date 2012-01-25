
#ifndef TRACER_HPP__
# define TRACER_HPP__

# include <string>
# include <sys/user.h>
# include <sys/ptrace.h>
# include "Options.hpp"
# include "ElfParser.hpp"
# include "signals.hpp"

class Tracer
{
    public:
        Tracer(Options& opt);
        virtual ~Tracer();

        void launch();

    private:
        bool _launchCommandProcess(char** command);
        void _runChild(char** command);
        void _runTracer();
        void _analyzeEip(struct user_regs_struct & data);
        bool _handleSysCalls(struct user_regs_struct & data);
        void _handleCalls(struct user_regs_struct & data);
        bool _isCall();
        bool _isRet();


    private:
        Options& _options;
        int _lastEip;
        int _lastCall;
        std::vector<std::string> _callStack;
        static std::string _syscall[256];
        ElfParser _elf;
};

# define RET(op) ((op & 0xff) == 0xcb || (op & 0xff) == 0xc3)
# define SYSCALL(op) ((op & 0xffff) == 0x80cd)
# define CALLE8(op) ((op & 0xff) == 0xe8)
# define CALL9A(op) ((op & 0xff) == 0x9a)
# define CALLFF(op) ((op & 0xff) == 0xff)

#endif // TRACER_HPP__
