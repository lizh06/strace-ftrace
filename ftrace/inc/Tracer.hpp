
#ifndef TRACER_HPP__
# define TRACER_HPP__

# include "Options.hpp"

class Tracer
{
    public:
        Tracer(Options& opt);
        virtual ~Tracer();

        void launch();

    private:
        bool _launchCommandProcess(char** command);

    private:
        Options& _options;
};

#endif // TRACER_HPP__
