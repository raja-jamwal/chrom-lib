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

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		create_hooks();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

