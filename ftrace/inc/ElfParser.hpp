/*!
 * \file	ElfParser.hpp
 * \brief	ElfParser Class
 * \author	Alexis Lucazeau - lucaze_b@epitech.eu
 * \version	0.1
 * \date	01/24/2012 12:44:40 PM
 *
 * more description...
 */

#ifndef ELFPARSER_HPP__
# define ELFPARSER_HPP__

#include <string>
#include <string.h>
#include <gelf.h>
#include <vector>

class ElfParser
{
    public:
        typedef struct s_symInfo
        {
            unsigned int addr;
            std::string name;
            int type;
        } SymInfo;

    public:
        ElfParser();
        virtual ~ElfParser();

    public:
        bool loadSymTable(std::string file);
        void printSymTable();
        int getType(unsigned int addr);
        std::string getSymbol(unsigned int addr);

    private:
        Elf * _initElfHandle(int fd);
        void _fetchSymbols();
        std::string _cleanName(char * name);

    private:
        Elf_Scn * _scn;
        Elf * _e;
        Elf32_Shdr * _shdr;
        std::vector<SymInfo> _symTable;
};

#endif // ELFPARSER_HPP__
