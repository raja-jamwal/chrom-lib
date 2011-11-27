/*
	Firefox_hook (C) Raja Jamwal 2011, <www.experiblog.co.cc> <linux1@zoho.com>
	Distributed under GNU LGPL License

	Firefox_hook is a example code for Chrom Library, Firefox_hook log every
	HTTP/HTTPS requests that firefox makes

    Chrom, is API/Funtion interception/hijacking library for windows systems
    Copyright (C) 2011  Raja Jamwal

	This file is part of Chrom.

    Chrom is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Foobar is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Chrom.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "stdafx.h"

Hook Firefox; // use chrom library

DWORD PR_Write_H (DWORD *fd,  void *buf,DWORD amount); // this is our overiding-function
typedef DWORD (*prWrite)(DWORD*,void*,DWORD); // defination of our original function

prWrite prw = NULL; // create a orginal function, we later point this to orginal function
					// address

char log_file[]="c://log.txt"; // logfile

// this will log our data
int write_log(char * log, char * data)
{
	ofstream fout(log, ios::app);fout << data;fout.close();
	return TRUE;
}

// initialize hooking, this adds the jump instruction to orginal function address
int create_hooks()
{
	// Override PR_Write function in nspr4.dll with our PR_Write_H, 
	// Note nspr4.dll must already be
	// loaded in process space
	Firefox.Initialize("PR_Write", "nspr4.dll", PR_Write_H);
	// Write jump instruction on orginal function address
	Firefox.Start();
	return TRUE;
}

// our overriding function
DWORD PR_Write_H (DWORD *fd,  void *buf,DWORD amount){
	// reset hooks, this will replace the jump instruction to original data
	Firefox.Reset();
    // point prw(function) to original function
	prw = (prWrite)Firefox.original_function;
    // log the headers
	write_log(log_file, (char*) buf);
	// call the real PR_Write function
	DWORD ret = prw(fd, buf, amount);
	// again place the jump instruction on the original function
	Firefox.Place_Hook();
	return ret;
}
