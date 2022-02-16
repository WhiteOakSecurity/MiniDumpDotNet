// SPDX-License-Identifier: Apache-2.0
#include <stdio.h>

#include "minidump.h"
#include "types.h"
#include "externs.h"
#include "utils.h"

using namespace System;

void MiniDump::MiniDump::DumpPid(int pid, String ^output_file)
{
	
	ULONG32 Signature;
	SHORT   Version;
	SHORT   ImplementationVersion;
	BOOL    success;

	IntPtr pNativeStr = Marshal::StringToHGlobalAnsi(output_file);
	char* dump_name = static_cast<char*>(pNativeStr.ToPointer());

	// Configure valid MiniDump signature
	Signature = MINIDUMP_SIGNATURE;
	Version = MINIDUMP_VERSION;
	ImplementationVersion = MINIDUMP_IMPL_VERSION;

	success = enable_debug_priv();
	if (!success) {
		printf(
			"Could not enable 'SeDebugPrivilege'\n"
		);
		return;
	}

	HANDLE hProcess;
	if (pid) {
		hProcess = GetProcessHandle(pid);
	}

	if (!hProcess) {
		return;
	}

	// allocate a chuck of memory to write the dump
	SIZE_T RegionSize = DUMP_MAX_SIZE;
	PVOID BaseAddress = allocate_memory(&RegionSize);
	if (!BaseAddress) {
		NtClose(hProcess); hProcess = NULL;
		return;
	}

	// Setup Dump Context
	dump_context dc;
	dc.hProcess = hProcess;
	dc.BaseAddress = BaseAddress;
	dc.rva = 0;
	dc.DumpMaxSize = RegionSize;
	dc.Signature = Signature;
	dc.Version = Version;
	dc.ImplementationVersion = ImplementationVersion;

	success = FetchMiniDump(&dc);

	// close the handle
	NtClose(hProcess); hProcess = NULL; dc.hProcess = NULL;

	if (success)
	{
		success = write_file(
			dump_name,
			(char*)dc.BaseAddress,
			dc.rva
		);
	}

	erase_dump_from_memory(&dc);

	return;
}
