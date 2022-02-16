// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <windows.h>
#include "types.h"

typedef struct _linked_list
{
    struct _linked_list* next;
} linked_list, *Plinked_list;

BOOL FetchMiniDump(Pdump_context dc);
HANDLE GetProcessHandle(DWORD dwPid);
BOOL enable_debug_priv(void);
void free_linked_list(PVOID head);
PVOID allocate_memory(PSIZE_T RegionSize);
void erase_dump_from_memory(Pdump_context dc);
BOOL write_file(char fileName[], char fileData[], ULONG32 fileLength);