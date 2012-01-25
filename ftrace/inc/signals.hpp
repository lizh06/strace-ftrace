/*!
 * \file	signals.hpp
 * \brief	
 * \author	Alexis Lucazeau - lucaze_b@epitech.eu
 * \version	0.1
 * \date	01/25/2012 04:07:07 AM
 *
 * more description...
 */

#ifndef SIGNALS_HPP__
# define DIGNALS_HPP__

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>

void sigHandler(int signum);
void handle_signals(int p);

#endif // SIGNALS_HPP__

