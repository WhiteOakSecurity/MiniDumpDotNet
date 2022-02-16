// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <windows.h>

#define LSASRV_DLL L"lsasrv.dll"
#define LDR_POINTER_OFFSET 0x18
#define MODULE_LIST_POINTER_OFFSET 0x20

#define PROCESSOR_ARCHITECTURE AMD64

// 70 MiB
#define DUMP_MAX_SIZE 0x4600000
// 900 KiB
#define CHUNK_SIZE 0xe1000

enum ProcessorArchitecture
{
	AMD64 = 9,
	INTEL = 0,
};

#define SIZE_OF_HEADER 32
#define SIZE_OF_DIRECTORY 12
#define SIZE_OF_SYSTEM_INFO_STREAM 48
#define SIZE_OF_MINIDUMP_MODULE 108


typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _module_info
{
	struct _module_info* next;
	ULONG64 dll_base;
	ULONG32 size_of_image;
	char dll_name[256];
	ULONG32 name_rva;
	ULONG32 TimeDateStamp;
	ULONG32 CheckSum;
} module_info, *Pmodule_info;

/* definitions from memoryapi.h */
#define MEM_COMMIT 0x1000
//#define MEM_IMAGE 0x1000000
#define MEM_MAPPED 0x40000
#define PAGE_NOACCESS 0x01
#define PAGE_GUARD 0x100
/* definitions from memoryapi.h */

/* definitions from wdm.h */
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

/* definitions from wdm.h */

/* definitions from ntstatus.h */
#define STATUS_SUCCESS 0
#define STATUS_PARTIAL_COPY 0x8000000D
#define STATUS_ACCESS_DENIED 0xC0000022
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A
#define STATUS_NO_MORE_ENTRIES 0x8000001A
#define STATUS_INVALID_CID 0xC000000B
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

/* definitions from ntstatus.h */

/* definitions from winternl.h */
#define 	FILE_OVERWRITE_IF   0x00000005
#define 	FILE_SYNCHRONOUS_IO_NONALERT   0x00000020

typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void *PPS_POST_PROCESS_INIT_ROUTINE;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, *PPEB;

typedef LONG KPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation,
	ObjectTypeInformation
} OBJECT_INFORMATION_CLASS;
/* definitions from winternal.h */

/* definitions from verrsrc.h */
typedef struct _VsFixedFileInfo
{
	ULONG32 dwSignature;
	ULONG32 dwStrucVersion;
	ULONG32 dwFileVersionMS;
	ULONG32 dwFileVersionLS;
	ULONG32 dwProductVersionMS;
	ULONG32 dwProductVersionLS;
	ULONG32 dwFileFlagsMask;
	ULONG32 dwFileFlags;
	ULONG32 dwFileOS;
	ULONG32 dwFileType;
	ULONG32 dwFileSubtype;
	ULONG32 dwFileDateMS;
	ULONG32 dwFileDateLS;
} VsFixedFileInfo, *PVsFixedFileInfo;

/* definitions from verrsrc.h */

/* definitions from minidumpapiset.h */

#define MINIDUMP_SIGNATURE 0x504d444d
#define MINIDUMP_VERSION 42899
#define MINIDUMP_IMPL_VERSION 0

typedef struct _MiniDumpHeader
{
	ULONG32       Signature;
	SHORT         Version;
	SHORT         ImplementationVersion;
	ULONG32       NumberOfStreams;
	ULONG32       StreamDirectoryRva;
	ULONG32       CheckSum;
	ULONG32       Reserved;
	ULONG32       TimeDateStamp;
	ULONG32       Flags;
} MiniDumpHeader, *PMiniDumpHeader;

typedef struct _MiniDumpDirectory
{
	ULONG32       StreamType;
	ULONG32       DataSize;
	ULONG32       Rva;
} MiniDumpDirectory, *PMiniDumpDirectory;

typedef struct _dump_context
{
	HANDLE  hProcess;
	PVOID   BaseAddress;
	ULONG32 rva;
	SIZE_T  DumpMaxSize;
	ULONG32 Signature;
	SHORT   Version;
	SHORT   ImplementationVersion;
} dump_context, *Pdump_context;

//#pragma pack(1)
typedef struct _MiniDumpSystemInfo
{
	SHORT ProcessorArchitecture;
	SHORT ProcessorLevel;
	SHORT ProcessorRevision;
	char    NumberOfProcessors;
	char    ProductType;
	ULONG32 MajorVersion;
	ULONG32 MinorVersion;
	ULONG32 BuildNumber;
	ULONG32 PlatformId;
	ULONG32 CSDVersionRva;
	SHORT SuiteMask;
	SHORT Reserved2;
	ULONG64 ProcessorFeatures1;
	ULONG64 ProcessorFeatures2;

} MiniDumpSystemInfo, *PMiniDumpSystemInfo;

typedef struct _MiniDumpLocationDescriptor
{
	ULONG32 DataSize;
	ULONG32 rva;
} MiniDumpLocationDescriptor, *PMiniDumpLocationDescriptor;

typedef struct _MiniDumpModule
{
	ULONG64 BaseOfImage;
	ULONG32 SizeOfImage;
	ULONG32 CheckSum;
	ULONG32 TimeDateStamp;
	ULONG32 ModuleNameRva;
	VsFixedFileInfo VersionInfo;
	MiniDumpLocationDescriptor CvRecord;
	MiniDumpLocationDescriptor MiscRecord;
	ULONG64 Reserved0;
	ULONG64 Reserved1;
} MiniDumpModule, *PMiniDumpModule;

typedef struct _MiniDumpMemoryDescriptor64
{
	struct _MiniDumpMemoryDescriptor64* next;
	ULONG64 StartOfMemoryRange;
	ULONG64 DataSize;
	DWORD   State;
	DWORD   Protect;
	DWORD   Type;
} MiniDumpMemoryDescriptor64, *PMiniDumpMemoryDescriptor64;

enum StreamType
{
	SystemInfoStream = 7,
	ModuleListStream = 4,
	Memory64ListStream = 9,
};

typedef enum _MINIDUMP_TYPE {
	MiniDumpNormal,
	MiniDumpWithDataSegs,
	MiniDumpWithFullMemory,
	MiniDumpWithHandleData,
	MiniDumpFilterMemory,
	MiniDumpScanMemory,
	MiniDumpWithUnloadedModules,
	MiniDumpWithIndirectlyReferencedMemory,
	MiniDumpFilterModulePaths,
	MiniDumpWithProcessThreadData,
	MiniDumpWithPrivateReadWriteMemory,
	MiniDumpWithoutOptionalData,
	MiniDumpWithFullMemoryInfo,
	MiniDumpWithThreadInfo,
	MiniDumpWithCodeSegs,
	MiniDumpWithoutAuxiliaryState,
	MiniDumpWithFullAuxiliaryState,
	MiniDumpWithPrivateWriteCopyMemory,
	MiniDumpIgnoreInaccessibleMemory,
	MiniDumpWithTokenInformation,
	MiniDumpWithModuleHeaders,
	MiniDumpFilterTriage,
	MiniDumpWithAvxXStateContext,
	MiniDumpWithIptTrace,
	MiniDumpScanInaccessiblePartialPages,
	MiniDumpFilterWriteCombinedMemory,
	MiniDumpValidTypeFlags
} MINIDUMP_TYPE;
/* definitions from minidumpapiset.h */

/* definitions from ntdef.h */

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define 	OBJ_CASE_INSENSITIVE   0x00000040

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif
/* definitions from ntdef.h */

/* definitions from ntifs.h */
typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;
/* definitions from ntifs.h */

/* definitions from ntldr.h */
struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];                             //0x0
		struct
		{
			struct _RTL_BALANCED_NODE* Left;                                //0x0
			struct _RTL_BALANCED_NODE* Right;                               //0x8
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;                                                    //0x10
			UCHAR Balance : 2;                                                //0x10
		};
		ULONGLONG ParentValue;                                              //0x10
	};
};

enum _LDR_DLL_LOAD_REASON
{
	LoadReasonStaticDependency = 0,
	LoadReasonStaticForwarderDependency = 1,
	LoadReasonDynamicForwarderDependency = 2,
	LoadReasonDelayloadDependency = 3,
	LoadReasonDynamicLoad = 4,
	LoadReasonAsImageLoad = 5,
	LoadReasonAsDataLoad = 6,
	LoadReasonEnclavePrimary = 7,
	LoadReasonEnclaveDependency = 8,
	LoadReasonPatchImage = 9,
	LoadReasonUnknown = -1
};

struct LDR_DATA_TABLE_ENTRY
{
	//struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	PVOID DllBase;                                                          //0x30
	PVOID EntryPoint;                                                       //0x38
	ULONG32 SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	union
	{
		UCHAR FlagGroup[4];                                                 //0x68
		ULONG Flags;                                                        //0x68
		struct
		{
			ULONG PackagedBinary : 1;                                         //0x68
			ULONG MarkedForRemoval : 1;                                       //0x68
			ULONG ImageDll : 1;                                               //0x68
			ULONG LoadNotificationsSent : 1;                                  //0x68
			ULONG TelemetryEntryProcessed : 1;                                //0x68
			ULONG ProcessStaticImport : 1;                                    //0x68
			ULONG InLegacyLists : 1;                                          //0x68
			ULONG InIndexes : 1;                                              //0x68
			ULONG ShimDll : 1;                                                //0x68
			ULONG InExceptionTable : 1;                                       //0x68
			ULONG ReservedFlags1 : 2;                                         //0x68
			ULONG LoadInProgress : 1;                                         //0x68
			ULONG LoadConfigProcessed : 1;                                    //0x68
			ULONG EntryProcessed : 1;                                         //0x68
			ULONG ProtectDelayLoad : 1;                                       //0x68
			ULONG ReservedFlags3 : 2;                                         //0x68
			ULONG DontCallForThreads : 1;                                     //0x68
			ULONG ProcessAttachCalled : 1;                                    //0x68
			ULONG ProcessAttachFailed : 1;                                    //0x68
			ULONG CorDeferredValidate : 1;                                    //0x68
			ULONG CorImage : 1;                                               //0x68
			ULONG DontRelocate : 1;                                           //0x68
			ULONG CorILOnly : 1;                                              //0x68
			ULONG ChpeImage : 1;                                              //0x68
			ULONG ChpeEmulatorImage : 1;                                      //0x68
			ULONG ReservedFlags5 : 1;                                         //0x68
			ULONG Redirected : 1;                                             //0x68
			ULONG ReservedFlags6 : 2;                                         //0x68
			ULONG CompatDatabaseProcessed : 1;                                //0x68
		};
	};
	USHORT ObsoleteLoadCount;                                               //0x6c
	USHORT TlsIndex;                                                        //0x6e
	struct _LIST_ENTRY HashLinks;                                           //0x70
	ULONG TimeDateStamp;                                                    //0x80
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* Lock;                                                             //0x90
	struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
	struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
	struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
	VOID* ParentDllBase;                                                    //0xb8
	VOID* SwitchBackContext;                                                //0xc0
	struct _RTL_BALANCED_NODE BaseAddressIndexNode;                         //0xc8
	struct _RTL_BALANCED_NODE MappingInfoIndexNode;                         //0xe0
	ULONGLONG OriginalBase;                                                 //0xf8
	union _LARGE_INTEGER LoadTime;                                          //0x100
	ULONG BaseNameHashValue;                                                //0x108
	enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
	ULONG ImplicitPathOptions;                                              //0x110
	ULONG ReferenceCount;                                                   //0x114
	ULONG DependentLoadFlags;                                               //0x118
	UCHAR SigningLevel;                                                     //0x11c
	ULONG CheckSum;                                                         //0x120
};
/* definitions from ntldr.h */
