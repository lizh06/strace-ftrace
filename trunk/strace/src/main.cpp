
#include "Options.hpp"
#include "Tracer.hpp"

int main(int ac, char ** av)
{
    Options opt(ac, av);
    Tracer tracer(opt);
    tracer.launch();
    return (0);
}

