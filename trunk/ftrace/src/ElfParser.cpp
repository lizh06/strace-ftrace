/*!
 * \file	ElfParser.cpp
 * \brief	ElfParser Class
 * \author	Alexis Lucazeau - lucaze_b@epitech.eu
 * \version	0.1
 * \date	01/24/2012 12:47:27 PM
 *
 * more description...
 */

#include <iostream>
#include <iomanip>
#include <sys/types.h>
#include <fcntl.h>
#include "ElfParser.hpp"

ElfParser::ElfParser() :
    _scn(NULL),
    _e(NULL),
    _shdr(NULL)
{

}

ElfParser::~ElfParser()
{

}

Elf * ElfParser::_initElfHandle(int fd)
{
    Elf * e = NULL;
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        std::cerr << "elf_version: " << elf_errmsg(-1) << std::endl;
        return (NULL);
    }
    if (!(e = elf_begin(fd, ELF_C_READ, NULL)))
    {
        std::cerr << "elf_begin: " << elf_errmsg(-1) << std::endl;
        return (NULL);
    }
    return (e);
}

std::string ElfParser::_cleanName(char * name)
{
    int i = 0;
    if (name == NULL)
        return ("");
    while (name[i])
    {
        if (name[i] < 31 || name[i] == 127)
            name[i] = '_';
        else if (name[i] == '.')
            name[i] = '_';
        ++i;
    }
    return (name);
}

void    ElfParser::_fetchSymbols()
{
    unsigned int i;
    Elf_Data * data;
    GElf_Sym sym;

    i = 0;
    data = NULL;
    if (!(data = elf_getdata(this->_scn, NULL)) || !(data->d_size))
        std::cerr << "elf_getdata: no data" << std::endl;
    else
    {
        while (i < this->_shdr->sh_size / this->_shdr->sh_entsize)
        {
            if (gelf_getsym(data, i, &sym))
            {
                SymInfo info;
                info.addr = sym.st_value;
                info.name = this->_cleanName(elf_strptr(this->_e, this->_shdr->sh_link, sym.st_name));
                info.type = ELF32_ST_TYPE(sym.st_info);
                this->_symTable.push_back(info);
            }
            ++i;
        }
    }
}

void ElfParser::printSymTable()
{
    std::vector<SymInfo>::iterator it = this->_symTable.begin();
    std::vector<SymInfo>::iterator itEnd = this->_symTable.end();

    while (it != itEnd)
    {
        std::cout
            << "[name=" << it->name << "] "
            << "[type=" << it->type << "] "
            << "[addr=0x" << std::uppercase << std::setfill('0') << std::setw(8) << std::hex << it->addr << "] "
            << std::endl;
        ++it;
    }
}

int ElfParser::getType(unsigned int addr)
{
    std::vector<SymInfo>::iterator it = this->_symTable.begin();
    std::vector<SymInfo>::iterator itEnd = this->_symTable.end();

    while (it != itEnd)
    {
        if (it->addr == addr)
            return (it->type);
        ++it;
    }
    return (-1);
}

std::string ElfParser::getSymbol(unsigned int addr)
{
    std::vector<SymInfo>::iterator it = this->_symTable.begin();
    std::vector<SymInfo>::iterator itEnd = this->_symTable.end();

    while (it != itEnd)
    {
        if (it->addr == addr)
            return (it->name);
        ++it;
    }
    return ("");
}

bool ElfParser::loadSymTable(std::string file)
{
    int fd;
    bool found = false;

    fd = open(file.c_str(), O_RDONLY);
    if (fd != -1)
    {
        if ((this->_e = this->_initElfHandle(fd)) != NULL)
        {
            while ((this->_scn = elf_nextscn(this->_e, this->_scn)))
            {
                if ((this->_shdr = elf32_getshdr(this->_scn)) == NULL)
                {
                    std::cerr << "Shdr not found" << std::endl;
                    continue;
                }
                if (this->_shdr->sh_type == SHT_SYMTAB || this->_shdr->sh_type == SHT_DYNAMIC)
                {
                    std::cout << "SymTable found" << std::endl;
                    this->_fetchSymbols();
                    found = true;
                }
            }
        }
        else
            std::cerr << "Elf initialization failed" << std::endl;
    }
    else
        std::cerr << "open: " << strerror(errno) << std::endl;
    if (fd != -1 && close(fd) == -1)
        std::cerr << "Closing file '" << file << "' failed" << std::endl;
    return (found);
}

