// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <windows.h>
#include "types.h"

using namespace System;
using namespace System::Runtime::InteropServices;

#define DEBUG

// Macros
#define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)
#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

BOOL write_header(Pdump_context dc);
BOOL write_directories(Pdump_context dc);
BOOL write_system_info_stream(Pdump_context dc);
Pmodule_info write_module_list_stream(Pdump_context dc);
PMiniDumpMemoryDescriptor64 write_memory64_list_stream(Pdump_context dc, Pmodule_info module_list);
Pmodule_info find_modules(HANDLE hProcess, wchar_t* important_modules[], int number_of_important_modules, BOOL is_lsass);


namespace MiniDump {
	
	[ComVisible(true)]
	public ref class MiniDump
	{
		public:
			void DumpPid(int pid, String ^output_file);

	};
}

