#include <cstdint>
#include "spoofer.h"
#include <ntifs.h>
#include <ntstrsafe.h>
#include <windef.h>
#include <minwindef.h>
#include <ntimage.h>
#include "oxorany_include.h"

#define DEVICE_MODULE E(L"*Udahhdrivetwan*")

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;


PVOID(*DynMmCopyMemory)(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T) = NULL;
PVOID(*DynMmMapIoSpaceEx)(PHYSICAL_ADDRESS, SIZE_T, ULONG) = NULL;
VOID(*DynMmUnmapIoSpace)(PVOID, SIZE_T) = NULL;
void(*DynExFreePoolWithTag)(PVOID, ULONG) = NULL;
inline PVOID(*DynExAllocatePoolWithTag)(POOL_TYPE, SIZE_T, ULONG) = NULL;
NTSTATUS(*DynZwQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,ULONG SystemInformationLength,PULONG ReturnLength) = NULL;
NTSTATUS(*DynObCreateObject)(IN KPROCESSOR_MODE ProbeMode,IN POBJECT_TYPE Type,IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,IN KPROCESSOR_MODE AccessMode,IN OUT PVOID ParseContext OPTIONAL,IN ULONG ObjectSize,IN ULONG PagedPoolCharge OPTIONAL,IN ULONG NonPagedPoolCharge OPTIONAL,OUT PVOID* Object) = NULL;
NTSTATUS(*DynIoCreateDevice)(PDRIVER_OBJECT, ULONG, PUNICODE_STRING, DEVICE_TYPE, ULONG, BOOLEAN, PDEVICE_OBJECT*) = NULL;
NTSTATUS(*DynIoCreateSymbolicLink)(PUNICODE_STRING, PUNICODE_STRING) = NULL;
PVOID(*DynExAllocatePool)(POOL_TYPE, SIZE_T) = NULL;
NTSTATUS(*DynPsLookupProcessByProcessId)(HANDLE, PEPROCESS*) = NULL;
NTSTATUS(*DynObInsertObject)(PVOID, PACCESS_STATE, ACCESS_MASK, ULONG, PVOID*, PHANDLE) = NULL;
NTSTATUS(*DynZwClose)(HANDLE) = NULL;
PVOID(*DynMmGetSystemRoutineAddress)(PUNICODE_STRING SystemRoutineName) = NULL;
PVOID(*DynPsGetProcessSectionBaseAddress)(PEPROCESS) = NULL;
PPEB(*DynPsGetProcessPeb)(PEPROCESS Process) = NULL;

NTSTATUS(*DynPsCreateSystemThread)(
	PHANDLE ThreadHandle,
	ULONG DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle,
	PCLIENT_ID ClientId,
	PKSTART_ROUTINE StartRoutine,
	PVOID StartContext
	) = NULL;NTSTATUS(*DynKeDelayExecutionThread)(KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER) = NULL;
VOID(*DynPsTerminateSystemThread)(NTSTATUS) = NULL;

// Resource management
VOID(*DynExReleaseResourceLite)(PERESOURCE) = NULL;
BOOLEAN(*DynExAcquireResourceExclusiveLite)(PERESOURCE, BOOLEAN) = NULL;
PIMAGE_NT_HEADERS(*DynRtlImageNtHeader)(PVOID ModuleAddress) = NULL;



// String utilities
VOID(*DynRtlInitAnsiString)(PANSI_STRING, PCSZ) = NULL;
LONG(*DynRtlCompareString)(PSTRING, PSTRING, BOOLEAN) = NULL;
LONG(*DynRtlCompareUnicodeString)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN) = NULL;

BOOLEAN(*DynRtlEqualUnicodeString)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN) = NULL;

// AVL table functions
PVOID(*DynRtlLookupElementGenericTableAvl)(PRTL_AVL_TABLE, PVOID) = NULL;
BOOLEAN(*DynRtlDeleteElementGenericTableAvl)(PRTL_AVL_TABLE, PVOID) = NULL;


NTSTATUS(*DynKeQueryUnbiasedInterruptTime)() = NULL;
PVOID(*DynExAllocatePool2)(POOL_FLAGS, SIZE_T, ULONG) = NULL;
VOID(*DynObMakeTemporaryObject)(PVOID) = NULL;
NTSTATUS(*DynObfDereferenceObject)(PVOID) = NULL;
NTSTATUS(*DynZwCreateFile)(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
	) = NULL;


inline ULONG(*DynRtlRandomEx)(PULONG) = NULL;

VOID(*DynKeQuerySystemTimePrecise)(PLARGE_INTEGER) = NULL;

NTSTATUS(*DynRtlGetVersion)(PRTL_OSVERSIONINFOW) = NULL;
BOOLEAN(*DynMmIsAddressValid)(PVOID) = NULL;
PVOID(*DynMmGetVirtualForPhysical)(PHYSICAL_ADDRESS) = NULL;
PEPROCESS(*DynIoGetCurrentProcess)(VOID) = NULL;
VOID(*DynObDereferenceObject)(PVOID) = NULL;
VOID(*DynIoCompleteRequest)(PIRP, CCHAR) = NULL;
PPHYSICAL_MEMORY_RANGE(*DynMmGetPhysicalMemoryRanges)(VOID) = NULL;
NTSTATUS(*DynObOpenObjectByPointer)(PVOID, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PHANDLE) = NULL;
//ULONG64(*DynReadGsQword)(ULONG) = NULL;

// Zw Virtual Memory functions
NTSTATUS(*DynZwAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) = NULL;

NTSTATUS(*DynZwProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) = NULL;

NTSTATUS(*DynZwFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
) = NULL;


typedef struct _BASE_REQUEST {
	INT32 ProcessId;
	UINT_PTR* Address;
} BASE_REQUEST, * PBASE_REQUEST;

typedef struct _PEB_REQUEST {
	INT32 ProcessId;
	UINT_PTR* Address;
} PEB_REQUEST, * PPEB_REQUEST;

#define MAX_STRING_LEN 256

typedef struct _CLEAN_REQUEST {
	bool UseUsermode = false;
	CHAR Vulnerable[MAX_STRING_LEN];
} CLEAN_REQUEST, * PCLEAN_REQUEST;

typedef struct _CACHE_REQUEST {
	INT32 ProcessId;
	UINT_PTR* Address;
} CACHE_REQUEST, * PCACHE_REQUEST;




typedef struct _READ_REQUEST {
	INT32 ProcessId;
	UINT_PTR Address;
	UINT_PTR Buffer;
	SIZE_T Size;
} READ_REQUEST, * PREAD_REQUEST;

typedef struct _WRITE_REQUEST {
	INT32 ProcessId;
	UINT_PTR Address;
	UINT_PTR Buffer;
	SIZE_T Size;
} WRITE_REQUEST, * PWRITE_REQUEST;

typedef struct _ALLOCATE_REQUEST {
	INT32 ProcessId;
	PVOID BaseAddress;
	SIZE_T RegionSize;
	ULONG AllocationType;
	ULONG Protect;
} ALLOCATE_REQUEST, * PALLOCATE_REQUEST;

typedef struct _PROTECT_REQUEST {
	INT32 ProcessId;
	PVOID BaseAddress;
	SIZE_T RegionSize;
	ULONG NewProtect;
	ULONG OldProtect;
} PROTECT_REQUEST, * PPROTECT_REQUEST;

typedef struct _FREE_REQUEST {
	INT32 ProcessId;
	PVOID BaseAddress;
	SIZE_T RegionSize;
	ULONG FreeType;
} FREE_REQUEST, * PFREE_REQUEST;

struct cache {
    uintptr_t Address;
    UINT64 Value;
};



static cache cached_pml4e[512];
static const ULONG64 PMASK = (~0xfull << 8) & 0xfffffffffull;


typedef struct _KPROCESS {
	char padding[0x28];
	uint64_t DirectoryTableBase;
} KPROCESS, * PKPROCESS;

// IOCTL control codes
#define IOCTL_FETCH_BASE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x754, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_WRITE_MEMORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x315, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_READ_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x634, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CACHE_CR3       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x143, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CACHE_PEB       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x453, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CLEAN     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x753, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ALLOCATE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x854, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_PROTECT_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x955, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_FREE_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA56, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)


#define win_1803 17134 
#define win_1809 17763 
#define win_1903 18362 
#define win_1909 18363
#define win_2004 19041
#define win_20H2 19569
#define win_21H1 20180

#define KernelBucketHashPattern_21H1 skCrypt("\x4C\x8D\x35\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x8B\x84\x24")
#define KernelBucketHashMask_21H1 skCrypt("xxx????x????xxx")

#define KernelBucketHashPattern_22H2 skCrypt("\x48\x8B\x1D\x00\x00\x00\x00\xEB\x00\xF7\x43\x40\x00\x20\x00\x00")
#define KernelBucketHashMask_22H2 skCrypt("xxx????x?xxxxxxx")

NTSTATUS NTAPI IopInvalidDeviceRequest(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
	Irp->IoStatus.Information = 0;
	DynIoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_INVALID_DEVICE_REQUEST;
}

typedef struct _IO_CLIENT_EXTENSION
{
	struct _IO_CLIENT_EXTENSION* NextExtension;
	PVOID ClientIdentificationAddress;
} IO_CLIENT_EXTENSION, * PIO_CLIENT_EXTENSION;

typedef struct _EXTENDED_DRIVER_EXTENSION
{
	struct _DRIVER_OBJECT* DriverObject;
	PDRIVER_ADD_DEVICE AddDevice;
	ULONG Count;
	UNICODE_STRING ServiceKeyName;
	PIO_CLIENT_EXTENSION ClientDriverExtension;
	PFS_FILTER_CALLBACKS FsFilterCallbacks;
} EXTENDED_DRIVER_EXTENSION, * PEXTENDED_DRIVER_EXTENSION;


volatile uint64_t g_MmPfnDatabase = 0;
volatile uint64_t g_PXE_BASE = 0;
volatile uint64_t g_idx = 0;
static uint64_t pte_base = 0;
static uint64_t pde_base = 0;
static uint64_t ppe_base = 0;
static uint64_t pxe_base = 0;
static uint64_t self_mapidx = 0;
static uint64_t mm_pfn_database = 0;

typedef struct _MMPFN {
	uintptr_t flags;
	uintptr_t pte_address;
	uintptr_t Unused_1;
	uintptr_t Unused_2;
	uintptr_t Unused_3;
	uintptr_t Unused_4;
} _MMPFN;

typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
	LIST_ENTRY64 List;
	ULONG           OwnerTag;
	ULONG           Size;
} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64 {

	DBGKD_DEBUG_DATA_HEADER64 Header;

	//
	// Base address of kernel image
	//

	ULONG64   KernBase;

	//
	// DbgBreakPointWithStatus is a function which takes an argument
	// and hits a breakpoint.  This field contains the address of the
	// breakpoint instruction.  When the debugger sees a breakpoint
	// at this address, it may retrieve the argument from the first
	// argument register, or on x86 the eax register.
	//

	ULONG64   BreakpointWithStatus;       // address of breakpoint

	//
	// Address of the saved context record during a bugcheck
	//
	// N.B. This is an automatic in KeBugcheckEx's frame, and
	// is only valid after a bugcheck.
	//

	ULONG64   SavedContext;

	//
	// help for walking stacks with user callbacks:
	//

	//
	// The address of the thread structure is provided in the
	// WAIT_STATE_CHANGE packet.  This is the offset from the base of
	// the thread structure to the pointer to the kernel stack frame
	// for the currently active usermode callback.
	//

	USHORT  ThCallbackStack;            // offset in thread data

	//
	// these values are offsets into that frame:
	//

	USHORT  NextCallback;               // saved pointer to next callback frame
	USHORT  FramePointer;               // saved frame pointer

	//
	// pad to a quad boundary
	//
	USHORT  PaeEnabled : 1;
	USHORT  KiBugCheckRecoveryActive : 1; // Windows 10 Manganese Addition
	USHORT  PagingLevels : 4;

	//
	// Address of the kernel callout routine.
	//

	ULONG64   KiCallUserMode;             // kernel routine

	//
	// Address of the usermode entry point for callbacks.
	//

	ULONG64   KeUserCallbackDispatcher;   // address in ntdll


	//
	// Addresses of various kernel data structures and lists
	// that are of interest to the kernel debugger.
	//

	ULONG64   PsLoadedModuleList;
	ULONG64   PsActiveProcessHead;
	ULONG64   PspCidTable;

	ULONG64   ExpSystemResourcesList;
	ULONG64   ExpPagedPoolDescriptor;
	ULONG64   ExpNumberOfPagedPools;

	ULONG64   KeTimeIncrement;
	ULONG64   KeBugCheckCallbackListHead;
	ULONG64   KiBugcheckData;

	ULONG64   IopErrorLogListHead;

	ULONG64   ObpRootDirectoryObject;
	ULONG64   ObpTypeObjectType;

	ULONG64   MmSystemCacheStart;
	ULONG64   MmSystemCacheEnd;
	ULONG64   MmSystemCacheWs;

	ULONG64   MmPfnDatabase;
	ULONG64   MmSystemPtesStart;
	ULONG64   MmSystemPtesEnd;
	ULONG64   MmSubsectionBase;
	ULONG64   MmNumberOfPagingFiles;

	ULONG64   MmLowestPhysicalPage;
	ULONG64   MmHighestPhysicalPage;
	ULONG64   MmNumberOfPhysicalPages;

	ULONG64   MmMaximumNonPagedPoolInBytes;
	ULONG64   MmNonPagedSystemStart;
	ULONG64   MmNonPagedPoolStart;
	ULONG64   MmNonPagedPoolEnd;

	ULONG64   MmPagedPoolStart;
	ULONG64   MmPagedPoolEnd;
	ULONG64   MmPagedPoolInformation;
	ULONG64   MmPageSize;

	ULONG64   MmSizeOfPagedPoolInBytes;

	ULONG64   MmTotalCommitLimit;
	ULONG64   MmTotalCommittedPages;
	ULONG64   MmSharedCommit;
	ULONG64   MmDriverCommit;
	ULONG64   MmProcessCommit;
	ULONG64   MmPagedPoolCommit;
	ULONG64   MmExtendedCommit;

	ULONG64   MmZeroedPageListHead;
	ULONG64   MmFreePageListHead;
	ULONG64   MmStandbyPageListHead;
	ULONG64   MmModifiedPageListHead;
	ULONG64   MmModifiedNoWritePageListHead;
	ULONG64   MmAvailablePages;
	ULONG64   MmResidentAvailablePages;

	ULONG64   PoolTrackTable;
	ULONG64   NonPagedPoolDescriptor;

	ULONG64   MmHighestUserAddress;
	ULONG64   MmSystemRangeStart;
	ULONG64   MmUserProbeAddress;

	ULONG64   KdPrintCircularBuffer;
	ULONG64   KdPrintCircularBufferEnd;
	ULONG64   KdPrintWritePointer;
	ULONG64   KdPrintRolloverCount;

	ULONG64   MmLoadedUserImageList;

	// NT 5.1 Addition

	ULONG64   NtBuildLab;
	ULONG64   KiNormalSystemCall;

	// NT 5.0 hotfix addition

	ULONG64   KiProcessorBlock;
	ULONG64   MmUnloadedDrivers;
	ULONG64   MmLastUnloadedDriver;
	ULONG64   MmTriageActionTaken;
	ULONG64   MmSpecialPoolTag;
	ULONG64   KernelVerifier;
	ULONG64   MmVerifierData;
	ULONG64   MmAllocatedNonPagedPool;
	ULONG64   MmPeakCommitment;
	ULONG64   MmTotalCommitLimitMaximum;
	ULONG64   CmNtCSDVersion;

	// NT 5.1 Addition

	ULONG64   MmPhysicalMemoryBlock;
	ULONG64   MmSessionBase;
	ULONG64   MmSessionSize;
	ULONG64   MmSystemParentTablePage;

	// Server 2003 addition

	ULONG64   MmVirtualTranslationBase;

	USHORT    OffsetKThreadNextProcessor;
	USHORT    OffsetKThreadTeb;
	USHORT    OffsetKThreadKernelStack;
	USHORT    OffsetKThreadInitialStack;

	USHORT    OffsetKThreadApcProcess;
	USHORT    OffsetKThreadState;
	USHORT    OffsetKThreadBStore;
	USHORT    OffsetKThreadBStoreLimit;

	USHORT    SizeEProcess;
	USHORT    OffsetEprocessPeb;
	USHORT    OffsetEprocessParentCID;
	USHORT    OffsetEprocessDirectoryTableBase;

	USHORT    SizePrcb;
	USHORT    OffsetPrcbDpcRoutine;
	USHORT    OffsetPrcbCurrentThread;
	USHORT    OffsetPrcbMhz;

	USHORT    OffsetPrcbCpuType;
	USHORT    OffsetPrcbVendorString;
	USHORT    OffsetPrcbProcStateContext;
	USHORT    OffsetPrcbNumber;

	USHORT    SizeEThread;

	UCHAR     L1tfHighPhysicalBitIndex;  // Windows 10 19H1 Addition
	UCHAR     L1tfSwizzleBitIndex;       // Windows 10 19H1 Addition

	ULONG     Padding0;

	ULONG64   KdPrintCircularBufferPtr;
	ULONG64   KdPrintBufferSize;

	ULONG64   KeLoaderBlock;

	USHORT    SizePcr;
	USHORT    OffsetPcrSelfPcr;
	USHORT    OffsetPcrCurrentPrcb;
	USHORT    OffsetPcrContainedPrcb;

	USHORT    OffsetPcrInitialBStore;
	USHORT    OffsetPcrBStoreLimit;
	USHORT    OffsetPcrInitialStack;
	USHORT    OffsetPcrStackLimit;

	USHORT    OffsetPrcbPcrPage;
	USHORT    OffsetPrcbProcStateSpecialReg;
	USHORT    GdtR0Code;
	USHORT    GdtR0Data;

	USHORT    GdtR0Pcr;
	USHORT    GdtR3Code;
	USHORT    GdtR3Data;
	USHORT    GdtR3Teb;

	USHORT    GdtLdt;
	USHORT    GdtTss;
	USHORT    Gdt64R3CmCode;
	USHORT    Gdt64R3CmTeb;

	ULONG64   IopNumTriageDumpDataBlocks;
	ULONG64   IopTriageDumpDataBlocks;

	// Longhorn addition

	ULONG64   VfCrashDataBlock;
	ULONG64   MmBadPagesDetected;
	ULONG64   MmZeroedPageSingleBitErrorsDetected;

	// Windows 7 addition

	ULONG64   EtwpDebuggerData;
	USHORT    OffsetPrcbContext;

	// Windows 8 addition

	USHORT    OffsetPrcbMaxBreakpoints;
	USHORT    OffsetPrcbMaxWatchpoints;

	ULONG     OffsetKThreadStackLimit;
	ULONG     OffsetKThreadStackBase;
	ULONG     OffsetKThreadQueueListEntry;
	ULONG     OffsetEThreadIrpList;

	USHORT    OffsetPrcbIdleThread;
	USHORT    OffsetPrcbNormalDpcState;
	USHORT    OffsetPrcbDpcStack;
	USHORT    OffsetPrcbIsrStack;

	USHORT    SizeKDPC_STACK_FRAME;

	// Windows 8.1 Addition

	USHORT    OffsetKPriQueueThreadListHead;
	USHORT    OffsetKThreadWaitReason;

	// Windows 10 RS1 Addition

	USHORT    Padding1;
	ULONG64   PteBase;

	// Windows 10 RS5 Addition

	ULONG64   RetpolineStubFunctionTable;
	ULONG     RetpolineStubFunctionTableSize;
	ULONG     RetpolineStubOffset;
	ULONG     RetpolineStubSize;

	// Windows 10 Iron Addition

	USHORT OffsetEProcessMmHotPatchContext;

	// Windows 11 Cobalt Addition

	ULONG   OffsetKThreadShadowStackLimit;
	ULONG   OffsetKThreadShadowStackBase;
	ULONG64 ShadowStackEnabled;

	// Windows 11 Nickel Addition

	ULONG64 PointerAuthMask;
	USHORT  OffsetPrcbExceptionStack;

} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;

typedef struct _DUMP_HEADER
{
	ULONG Signature;
	ULONG ValidDump;
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG_PTR DirectoryTableBase;
	ULONG_PTR PfnDataBase;
	PLIST_ENTRY PsLoadedModuleList;
	PLIST_ENTRY PsActiveProcessHead;
	ULONG MachineImageType;
	ULONG NumberProcessors;
	ULONG BugCheckCode;
	ULONG_PTR BugCheckParameter1;
	ULONG_PTR BugCheckParameter2;
	ULONG_PTR BugCheckParameter3;
	ULONG_PTR BugCheckParameter4;
	CHAR VersionUser[32];
	struct _KDDEBUGGER_DATA64* KdDebuggerDataBlock;
} DUMP_HEADER, * PDUMP_HEADER;

#ifndef _WIN64
#define KDDEBUGGER_DATA_OFFSET 0x1068
#else
#define KDDEBUGGER_DATA_OFFSET 0x2080
#endif

#ifndef _WIN64
#define DUMP_BLOCK_SIZE 0x20000
#else
#define DUMP_BLOCK_SIZE 0x40000
#endif

#pragma warning(push)
#pragma warning(disable:4201)
typedef union {
	struct {
		uint64_t reserved1 : 3;
		uint64_t page_level_write_through : 1;
		uint64_t page_level_cache_disable : 1;
		uint64_t reserved2 : 7;
		uint64_t address_of_page_directory : 36;
		uint64_t reserved3 : 16;
	};
	uint64_t flags;
} cr33;

typedef union {
	struct {
		uint64_t present : 1;
		uint64_t write : 1;
		uint64_t supervisor : 1;
		uint64_t page_level_write_through : 1;
		uint64_t page_level_cache_disable : 1;
		uint64_t accessed : 1;
		uint64_t dirty : 1;
		uint64_t large_page : 1;
		uint64_t global : 1;
		uint64_t ignored_1 : 2;
		uint64_t restart : 1;
		uint64_t page_frame_number : 36;
		uint64_t reserved1 : 4;
		uint64_t ignored_2 : 7;
		uint64_t protection_key : 4;
		uint64_t execute_disable : 1;
	};
	uint64_t flags;
} pt_entry_64;
#pragma warning(pop)

typedef struct _SYSTEM_MODULE
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;



struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
};

typedef struct _MM_UNLOADED_DRIVER {
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	/*PNON_PAGED_DEBUG_INFO*/ PVOID NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
typedef struct _ACTIVATION_CONTEXT _ACTIVATION_CONTEXT, * P_ACTIVATION_CONTEXT;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

union large_integer {
	struct {
		std::uint32_t low_part;
		std::int32_t high_part;
	};
	struct {
		std::uint32_t low_part;
		std::int32_t high_part;
	} u;
	std::int64_t quad_part;
};

struct single_list_entry {
	single_list_entry* next;
};
struct rtl_balanced_node {
	union {
		rtl_balanced_node* children[2];
		struct {
			rtl_balanced_node* left;
			rtl_balanced_node* right;
		};
	};
	union {
		struct {
			std::uint8_t red : 1;
			std::uint8_t balance : 2;
		};
		std::uint64_t parent_value;
	};
};

struct list_entry {
	list_entry* flink;
	list_entry* blink;
};

struct dispatcher_header {
	union {
		volatile std::int32_t lock;
		std::int32_t lock_nv;
		struct {
			std::uint8_t type;
			std::uint8_t signalling;
			std::uint8_t size;
			std::uint8_t reserved1;
		};
		struct {
			std::uint8_t timer_type;
			union {
				std::uint8_t timer_control_flags;
				struct {
					std::uint8_t absolute : 1;
					std::uint8_t wake : 1;
					std::uint8_t encoded_tolerable_delay : 6;
				};
			};
			std::uint8_t hand;
			union {
				std::uint8_t timer_misc_flags;
				struct {
					std::uint8_t index : 6;
					std::uint8_t inserted : 1;
					volatile std::uint8_t expired : 1;
				};
			};
		};
		struct {
			std::uint8_t timer2_type;
			union {
				std::uint8_t timer2_flags;
				struct {
					std::uint8_t timer2_inserted : 1;
					std::uint8_t timer2_expiring : 1;
					std::uint8_t timer2_cancel_pending : 1;
					std::uint8_t timer2_set_pending : 1;
					std::uint8_t timer2_running : 1;
					std::uint8_t timer2_disabled : 1;
					std::uint8_t timer2_reserved_flags : 2;
				};
			};
			std::uint8_t timer2_component_id;
			std::uint8_t timer2_relative_id;
		};
		struct {
			std::uint8_t queue_type;
			union {
				std::uint8_t queue_control_flags;
				struct {
					std::uint8_t abandoned : 1;
					std::uint8_t disable_increment : 1;
					std::uint8_t queue_reserved_control_flags : 6;
				};
			};
			std::uint8_t queue_size;
			std::uint8_t queue_reserved;
		};
		struct {
			std::uint8_t thread_type;
			std::uint8_t thread_reserved;
			union {
				std::uint8_t thread_control_flags;
				struct {
					std::uint8_t cycle_profiling : 1;
					std::uint8_t counter_profiling : 1;
					std::uint8_t group_scheduling : 1;
					std::uint8_t affinity_set : 1;
					std::uint8_t tagged : 1;
					std::uint8_t energy_profiling : 1;
					std::uint8_t scheduler_assist : 1;
					std::uint8_t thread_reserved_control_flags : 1;
				};
			};
			union {
				std::uint8_t debug_active;
				struct {
					std::uint8_t active_dr7 : 1;
					std::uint8_t instrumented : 1;
					std::uint8_t minimal : 1;
					std::uint8_t reserved4 : 2;
					std::uint8_t alt_syscall : 1;
					std::uint8_t ums_scheduled : 1;
					std::uint8_t ums_primary : 1;
				};
			};
		};
		struct {
			std::uint8_t mutant_type;
			std::uint8_t mutant_size;
			std::uint8_t dpc_active;
			std::uint8_t mutant_reserved;
		};
	};
	std::int32_t signal_state;
	list_entry wait_list_head;
};

struct kevent {
	dispatcher_header header;
};



struct kaffinity_ex {
	std::uint16_t count;
	std::uint16_t size;
	std::uint32_t reserved;
	std::uint64_t bitmap[20];
};


union kexecute_options {
	struct {
		std::uint8_t execute_disable : 1;
		std::uint8_t execute_enable : 1;
		std::uint8_t disable_thunk_emulation : 1;
		std::uint8_t permanent : 1;
		std::uint8_t execute_dispatch_enable : 1;
		std::uint8_t image_dispatch_enable : 1;
		std::uint8_t disable_exception_chain_validation : 1;
		std::uint8_t spare : 1;
	};
	volatile std::uint8_t execute_options;
	std::uint8_t execute_options_nv;
};

union kstack_count {
	std::int32_t value;
	struct {
		std::uint32_t state : 3;
		std::uint32_t stack_count : 29;
	};
};

struct kprocess {
	dispatcher_header header;
	list_entry profile_list_head;
	std::uint64_t directory_table_base;
	list_entry thread_list_head;
	std::uint32_t process_lock;
	std::uint32_t process_timer_delay;
	std::uint64_t deep_freeze_start_time;
	kaffinity_ex affinity;
	std::uint64_t affinity_padding[12];
	list_entry ready_list_head;
	single_list_entry swap_list_entry;
	volatile kaffinity_ex active_processors;
	std::uint64_t active_processors_padding[12];
	union {
		struct {
			std::uint32_t auto_alignment : 1;
			std::uint32_t disable_boost : 1;
			std::uint32_t disable_quantum : 1;
			std::uint32_t deep_freeze : 1;
			std::uint32_t timer_virtualization : 1;
			std::uint32_t check_stack_extents : 1;
			std::uint32_t cache_isolation_enabled : 1;
			std::uint32_t ppm_policy : 3;
			std::uint32_t va_space_deleted : 1;
			std::uint32_t reserved_flags : 21;
		};
		volatile std::int32_t process_flags;
	};
	std::uint32_t active_groups_mask;
	char base_priority;
	char quantum_reset;
	char visited;
	kexecute_options flags;
	std::uint16_t thread_seed[20];
	std::uint16_t thread_seed_padding[12];
	std::uint16_t ideal_processor[20];
	std::uint16_t ideal_processor_padding[12];
	std::uint16_t ideal_node[20];
	std::uint16_t ideal_node_padding[12];
	std::uint16_t ideal_global_node;
	std::uint16_t spare1;
	volatile kstack_count stack_count;
	list_entry process_list_entry;
	std::uint64_t cycle_time;
	std::uint64_t context_switches;
	void* scheduling_group;
	std::uint32_t freeze_count;
	std::uint32_t kernel_time;
	std::uint32_t user_time;
	std::uint32_t ready_time;
	std::uint64_t user_directory_table_base;
	std::uint8_t address_policy;
	std::uint8_t spare2[71];
	void* instrumentation_callback;
	union {
		std::uint64_t secure_handle;
		struct {
			std::uint64_t secure_process : 1;
			std::uint64_t unused : 1;
		} flags;
	} secure_state;
	std::uint64_t kernel_wait_time;
	std::uint64_t user_wait_time;
	std::uint64_t end_padding[8];
};

struct ex_push_lock {
	union {
		struct {
			std::uint64_t locked : 1;
			std::uint64_t waiting : 1;
			std::uint64_t waking : 1;
			std::uint64_t multiple_shared : 1;
			std::uint64_t shared : 60;
		};
		std::uint64_t value;
		void* ptr;
	};
};

struct ex_rundown_ref {
	union {
		std::uint64_t count;
		void* ptr;
	};
};

struct ex_fast_ref {
	union {
		void* object;
		std::uint64_t ref_cnt : 4;
		std::uint64_t value;
	};
};

struct rtl_avl_tree {
	rtl_balanced_node* root;
};

struct se_audit_process_creation_info {
	void* image_file_name;
};

struct mmsupport_flags {
	union {
		struct {
			std::uint8_t working_set_type : 3;
			std::uint8_t reserved0 : 3;
			std::uint8_t maximum_working_set_hard : 1;
			std::uint8_t minimum_working_set_hard : 1;
			std::uint8_t session_master : 1;
			std::uint8_t trimmer_state : 2;
			std::uint8_t reserved : 1;
			std::uint8_t page_stealers : 4;
		};
		std::uint16_t u1;
	};
	std::uint8_t memory_priority;
	union {
		struct {
			std::uint8_t wsle_deleted : 1;
			std::uint8_t svm_enabled : 1;
			std::uint8_t force_age : 1;
			std::uint8_t force_trim : 1;
			std::uint8_t new_maximum : 1;
			std::uint8_t commit_release_state : 2;
		};
		std::uint8_t u2;
	};
};

struct mmsupport_instance {
	std::uint32_t next_page_color;
	std::uint32_t page_fault_count;
	std::uint64_t trimmed_page_count;
	void* vm_working_set_list;
	list_entry working_set_expansion_links;
	std::uint64_t age_distribution[8];
	void* exit_outswap_gate;
	std::uint64_t minimum_working_set_size;
	std::uint64_t working_set_leaf_size;
	std::uint64_t working_set_leaf_private_size;
	std::uint64_t working_set_size;
	std::uint64_t working_set_private_size;
	std::uint64_t maximum_working_set_size;
	std::uint64_t peak_working_set_size;
	std::uint32_t hard_fault_count;
	std::uint16_t last_trim_stamp;
	std::uint16_t partition_id;
	std::uint64_t selfmap_lock;
	mmsupport_flags flags;
};

struct mmsupport_shared {
	volatile std::int32_t working_set_lock;
	std::int32_t good_citizen_waiting;
	std::uint64_t released_commit_debt;
	std::uint64_t reset_pages_repurposed_count;
	void* ws_swap_support;
	void* commit_release_context;
	void* access_log;
	volatile std::uint64_t charged_wsle_pages;
	std::uint64_t actual_wsle_pages;
	std::uint64_t working_set_core_lock;
	void* shadow_mapping;
	std::uint8_t reserved[0x80 - 0x50];
};

struct mmsupport_full {
	mmsupport_instance instance;
	mmsupport_shared shared;
};

struct alpc_process_context {
	ex_push_lock lock;
	list_entry view_list_head;
	volatile std::uint64_t paged_pool_quota_cache;
};

struct ps_protection {
	union {
		std::uint8_t level;
		struct {
			std::uint8_t type : 3;
			std::uint8_t audit : 1;
			std::uint8_t signer : 4;
		};
	};
};

union ps_interlocked_timer_delay_values {
	struct {
		std::uint64_t delay_ms : 30;
		std::uint64_t coalescing_window_ms : 30;
		std::uint64_t reserved : 1;
		std::uint64_t new_timer_wheel : 1;
		std::uint64_t retry : 1;
		std::uint64_t locked : 1;
	};
	std::uint64_t all;
};

struct wnf_state_name {
	std::uint32_t data[2];
};

struct jobobject_wake_filter {
	std::uint32_t high_edge_filter;
	std::uint32_t low_edge_filter;
};

struct ps_process_wake_information {
	std::uint64_t notification_channel;
	std::uint32_t wake_counters[7];
	jobobject_wake_filter wake_filter;
	std::uint32_t no_wake_counter;
};

struct ps_dynamic_enforced_address_ranges {
	rtl_avl_tree tree;
	ex_push_lock lock;
};

struct file_object {
	std::int16_t type;
	std::int16_t size;
	DEVICE_OBJECT* device_object;
	void* vpb;
	void* fs_context;
	void* fs_context2;
	void* section_object_pointer;
	void* private_cache_map;
	std::int32_t final_status;
	file_object* related_file_object;
	std::uint8_t lock_operation;
	std::uint8_t delete_pending;
	std::uint8_t read_access;
	std::uint8_t write_access;
	std::uint8_t delete_access;
	std::uint8_t shared_read;
	std::uint8_t shared_write;
	std::uint8_t shared_delete;
	std::uint32_t flags;
	UNICODE_STRING file_name;
	large_integer current_byte_offset;
	std::uint32_t waiters;
	std::uint32_t busy;
	void* last_lock;
	kevent lock;
	kevent event;
	void* completion_context;
	std::uint64_t irp_list_lock;
	list_entry irp_list;
	void* file_object_extension;
};

struct eprocess {
	kprocess pcb;
	ex_push_lock process_lock;
	void* unique_process_id;
	list_entry active_process_links;
	ex_rundown_ref rundown_protect;
	union {
		std::uint32_t flags2;
		struct {
			std::uint32_t job_not_really_active : 1;
			std::uint32_t accounting_folded : 1;
			std::uint32_t new_process_reported : 1;
			std::uint32_t exit_process_reported : 1;
			std::uint32_t report_commit_changes : 1;
			std::uint32_t last_report_memory : 1;
			std::uint32_t force_wake_charge : 1;
			std::uint32_t cross_session_create : 1;
			std::uint32_t needs_handle_rundown : 1;
			std::uint32_t ref_trace_enabled : 1;
			std::uint32_t pico_created : 1;
			std::uint32_t empty_job_evaluated : 1;
			std::uint32_t default_page_priority : 3;
			std::uint32_t primary_token_frozen : 1;
			std::uint32_t process_verifier_target : 1;
			std::uint32_t restrict_set_thread_context : 1;
			std::uint32_t affinity_permanent : 1;
			std::uint32_t affinity_update_enable : 1;
			std::uint32_t propagate_node : 1;
			std::uint32_t explicit_affinity : 1;
			std::uint32_t process_execution_state : 2;
			std::uint32_t enable_read_vm_logging : 1;
			std::uint32_t enable_write_vm_logging : 1;
			std::uint32_t fatal_access_termination_requested : 1;
			std::uint32_t disable_system_allowed_cpu_set : 1;
			std::uint32_t process_state_change_request : 2;
			std::uint32_t process_state_change_in_progress : 1;
			std::uint32_t in_private : 1;
		};
	};
	union {
		std::uint32_t flags;
		struct {
			std::uint32_t create_reported : 1;
			std::uint32_t no_debug_inherit : 1;
			std::uint32_t process_exiting : 1;
			std::uint32_t process_delete : 1;
			std::uint32_t manage_executable_memory_writes : 1;
			std::uint32_t vm_deleted : 1;
			std::uint32_t outswap_enabled : 1;
			std::uint32_t outswapped : 1;
			std::uint32_t fail_fast_on_commit_fail : 1;
			std::uint32_t wow64_va_space_4gb : 1;
			std::uint32_t address_space_initialized : 2;
			std::uint32_t set_timer_resolution : 1;
			std::uint32_t break_on_termination : 1;
			std::uint32_t deprioritize_views : 1;
			std::uint32_t write_watch : 1;
			std::uint32_t process_in_session : 1;
			std::uint32_t override_address_space : 1;
			std::uint32_t has_address_space : 1;
			std::uint32_t launch_prefetched : 1;
			std::uint32_t background : 1;
			std::uint32_t vm_top_down : 1;
			std::uint32_t image_notify_done : 1;
			std::uint32_t pde_update_needed : 1;
			std::uint32_t vdm_allowed : 1;
			std::uint32_t process_rundown : 1;
			std::uint32_t process_inserted : 1;
			std::uint32_t default_io_priority : 3;
			std::uint32_t process_self_delete : 1;
			std::uint32_t set_timer_resolution_link : 1;
		};
	};
	large_integer create_time;
	std::uint64_t process_quota_usage[2];
	std::uint64_t process_quota_peak[2];
	std::uint64_t peak_virtual_size;
	std::uint64_t virtual_size;
	list_entry session_process_links;
	union {
		void* exception_port_data;
		std::uint64_t exception_port_value;
		std::uint64_t exception_port_state : 3;
	};
	ex_fast_ref token;
	std::uint64_t mm_reserved;
	ex_push_lock address_creation_lock;
	ex_push_lock page_table_commitment_lock;
	void* rotate_in_progress;
	void* fork_in_progress;
	volatile void* commit_charge_job;
	rtl_avl_tree clone_root;
	volatile std::uint64_t number_of_private_pages;
	volatile std::uint64_t number_of_locked_pages;
	void* win32_process;
	volatile void* job;
	void* section_object;
	void* section_base_address;
	std::uint32_t cookie;
	void* working_set_watch;
	void* win32_window_station;
	void* inherited_from_unique_process_id;
	volatile std::uint64_t owner_process_id;
	void* peb;
	void* session;
	void* spare1;
	void* quota_block;
	void* object_table;
	void* debug_port;
	void* wow64_process;
	void* device_map;
	void* etw_data_source;
	std::uint64_t page_directory_pte;
	file_object* image_file_pointer;
	char image_file_name[15];
	std::uint8_t priority_class;
	void* security_port;
	se_audit_process_creation_info se_audit_process_creation_info;
	list_entry job_links;
	void* highest_user_address;
	list_entry thread_list_head;
	volatile std::uint32_t active_threads;
	std::uint32_t image_path_hash;
	std::uint32_t default_hard_error_processing;
	std::int32_t last_thread_exit_status;
	ex_fast_ref prefetch_trace;
	void* locked_pages_list;
	large_integer read_operation_count;
	large_integer write_operation_count;
	large_integer other_operation_count;
	large_integer read_transfer_count;
	large_integer write_transfer_count;
	large_integer other_transfer_count;
	std::uint64_t commit_charge_limit;
	volatile std::uint64_t commit_charge;
	volatile std::uint64_t commit_charge_peak;
	mmsupport_full vm;
	list_entry mm_process_links;
	std::uint32_t modified_page_count;
	std::int32_t exit_status;
	rtl_avl_tree vad_root;
	void* vad_hint;
	std::uint64_t vad_count;
	volatile std::uint64_t vad_physical_pages;
	std::uint64_t vad_physical_pages_limit;
	alpc_process_context alpc_context;
	list_entry timer_resolution_link;
	void* timer_resolution_stack_record;
	std::uint32_t requested_timer_resolution;
	std::uint32_t smallest_timer_resolution;
	large_integer exit_time;
	void* inverted_function_table;
	ex_push_lock inverted_function_table_lock;
	std::uint32_t active_threads_high_watermark;
	std::uint32_t large_private_vad_count;
	ex_push_lock thread_list_lock;
	void* wnf_context;
	void* server_silo;
	std::uint8_t signature_level;
	std::uint8_t section_signature_level;
	ps_protection protection;
	std::uint8_t hang_count : 3;
	std::uint8_t ghost_count : 3;
	std::uint8_t prefilter_exception : 1;
	union {
		std::uint32_t flags3;
		struct {
			std::uint32_t minimal : 1;
			std::uint32_t replacing_page_root : 1;
			std::uint32_t crashed : 1;
			std::uint32_t job_vads_are_tracked : 1;
			std::uint32_t vad_tracking_disabled : 1;
			std::uint32_t auxiliary_process : 1;
			std::uint32_t subsystem_process : 1;
			std::uint32_t indirect_cpu_sets : 1;
			std::uint32_t relinquished_commit : 1;
			std::uint32_t high_graphics_priority : 1;
			std::uint32_t commit_fail_logged : 1;
			std::uint32_t reserve_fail_logged : 1;
			std::uint32_t system_process : 1;
			std::uint32_t hide_image_base_addresses : 1;
			std::uint32_t address_policy_frozen : 1;
			std::uint32_t process_first_resume : 1;
			std::uint32_t foreground_external : 1;
			std::uint32_t foreground_system : 1;
			std::uint32_t high_memory_priority : 1;
			std::uint32_t enable_process_suspend_resume_logging : 1;
			std::uint32_t enable_thread_suspend_resume_logging : 1;
			std::uint32_t security_domain_changed : 1;
			std::uint32_t security_freeze_complete : 1;
			std::uint32_t vm_processor_host : 1;
			std::uint32_t vm_processor_host_transition : 1;
			std::uint32_t alt_syscall : 1;
			std::uint32_t timer_resolution_ignore : 1;
			std::uint32_t disallow_user_terminate : 1;
		};
	};
	std::int32_t device_asid;
	void* svm_data;
	ex_push_lock svm_process_lock;
	std::uint64_t svm_lock;
	list_entry svm_process_device_list_head;
	std::uint64_t last_freeze_interrupt_time;
	void* disk_counters;
	void* pico_context;
	void* enclave_table;
	std::uint64_t enclave_number;
	ex_push_lock enclave_lock;
	std::uint32_t high_priority_faults_allowed;
	void* energy_context;
	void* vm_context;
	std::uint64_t sequence_number;
	std::uint64_t create_interrupt_time;
	std::uint64_t create_unbiased_interrupt_time;
	std::uint64_t total_unbiased_frozen_time;
	std::uint64_t last_app_state_update_time;
	std::uint64_t last_app_state_uptime : 61;
	std::uint64_t last_app_state : 3;
	volatile std::uint64_t shared_commit_charge;
	ex_push_lock shared_commit_lock;
	list_entry shared_commit_links;
	union {
		struct {
			std::uint64_t allowed_cpu_sets;
			std::uint64_t default_cpu_sets;
		};
		struct {
			std::uint64_t* allowed_cpu_sets_indirect;
			std::uint64_t* default_cpu_sets_indirect;
		};
	};
	void* disk_io_attribution;
	void* dxg_process;
	std::uint32_t win32k_filter_set;
	volatile ps_interlocked_timer_delay_values process_timer_delay;
	volatile std::uint32_t ktimer_sets;
	volatile std::uint32_t ktimer2_sets;
	volatile std::uint32_t thread_timer_sets;
	std::uint64_t virtual_timer_list_lock;
	list_entry virtual_timer_list_head;
	union {
		wnf_state_name wake_channel;
		ps_process_wake_information wake_info;
	};
	union {
		std::uint32_t mitigation_flags;
		struct {
			std::uint32_t control_flow_guard_enabled : 1;
			std::uint32_t control_flow_guard_export_suppression_enabled : 1;
			std::uint32_t control_flow_guard_strict : 1;
			std::uint32_t disallow_stripped_images : 1;
			std::uint32_t force_relocate_images : 1;
			std::uint32_t high_entropy_aslr_enabled : 1;
			std::uint32_t stack_randomization_disabled : 1;
			std::uint32_t extension_point_disable : 1;
			std::uint32_t disable_dynamic_code : 1;
			std::uint32_t disable_dynamic_code_allow_opt_out : 1;
			std::uint32_t disable_dynamic_code_allow_remote_downgrade : 1;
			std::uint32_t audit_disable_dynamic_code : 1;
			std::uint32_t disallow_win32k_system_calls : 1;
			std::uint32_t audit_disallow_win32k_system_calls : 1;
			std::uint32_t enable_filtered_win32k_apis : 1;
			std::uint32_t audit_filtered_win32k_apis : 1;
			std::uint32_t disable_non_system_fonts : 1;
			std::uint32_t audit_non_system_font_loading : 1;
			std::uint32_t prefer_system32_images : 1;
			std::uint32_t prohibit_remote_image_map : 1;
			std::uint32_t audit_prohibit_remote_image_map : 1;
			std::uint32_t prohibit_low_il_image_map : 1;
			std::uint32_t audit_prohibit_low_il_image_map : 1;
			std::uint32_t signature_mitigation_opt_in : 1;
			std::uint32_t audit_block_non_microsoft_binaries : 1;
			std::uint32_t audit_block_non_microsoft_binaries_allow_store : 1;
			std::uint32_t loader_integrity_continuity_enabled : 1;
			std::uint32_t audit_loader_integrity_continuity : 1;
			std::uint32_t enable_module_tampering_protection : 1;
			std::uint32_t enable_module_tampering_protection_no_inherit : 1;
			std::uint32_t restrict_indirect_branch_prediction : 1;
			std::uint32_t isolate_security_domain : 1;
		} mitigation_flags_values;
	};

	union {
		std::uint32_t mitigation_flags2;
		struct {
			std::uint32_t enable_export_address_filter : 1;
			std::uint32_t audit_export_address_filter : 1;
			std::uint32_t enable_export_address_filter_plus : 1;
			std::uint32_t audit_export_address_filter_plus : 1;
			std::uint32_t enable_rop_stack_pivot : 1;
			std::uint32_t audit_rop_stack_pivot : 1;
			std::uint32_t enable_rop_caller_check : 1;
			std::uint32_t audit_rop_caller_check : 1;
			std::uint32_t enable_rop_sim_exec : 1;
			std::uint32_t audit_rop_sim_exec : 1;
			std::uint32_t enable_import_address_filter : 1;
			std::uint32_t audit_import_address_filter : 1;
			std::uint32_t disable_page_combine : 1;
			std::uint32_t speculative_store_bypass_disable : 1;
			std::uint32_t cet_user_shadow_stacks : 1;
			std::uint32_t audit_cet_user_shadow_stacks : 1;
			std::uint32_t audit_cet_user_shadow_stacks_logged : 1;
			std::uint32_t user_cet_set_context_ip_validation : 1;
			std::uint32_t audit_user_cet_set_context_ip_validation : 1;
			std::uint32_t audit_user_cet_set_context_ip_validation_logged : 1;
			std::uint32_t cet_user_shadow_stacks_strict_mode : 1;
			std::uint32_t block_non_cet_binaries : 1;
			std::uint32_t block_non_cet_binaries_non_ehcont : 1;
			std::uint32_t audit_block_non_cet_binaries : 1;
			std::uint32_t audit_block_non_cet_binaries_logged : 1;
			std::uint32_t reserved1 : 1;
			std::uint32_t reserved2 : 1;
			std::uint32_t reserved3 : 1;
			std::uint32_t reserved4 : 1;
			std::uint32_t reserved5 : 1;
			std::uint32_t cet_dynamic_apis_out_of_proc_only : 1;
			std::uint32_t user_cet_set_context_ip_validation_relaxed_mode : 1;
		} mitigation_flags2_values;
	};
	void* partition_object;
	std::uint64_t security_domain;
	std::uint64_t parent_security_domain;
	void* coverage_sampler_context;
	void* mm_hot_patch_context;
	rtl_avl_tree dynamic_eh_continuation_targets_tree;
	ex_push_lock dynamic_eh_continuation_targets_lock;
	ps_dynamic_enforced_address_ranges dynamic_enforced_cet_compatible_ranges;
	std::uint32_t disabled_component_flags;
	volatile std::uint32_t* path_redirection_hashes;
};

union cr3_t {
	std::uint64_t flags;
	struct {
		std::uint64_t reserved1 : 3;
		std::uint64_t page_level_write_through : 1;
		std::uint64_t page_level_cache_disable : 1;
		std::uint64_t reserved2 : 7;
		std::uint64_t dirbase : 36;
		std::uint64_t reserved3 : 16;
	};
};

union pml4e_t {
	std::uint64_t value;
	struct {
		std::uint64_t present : 1;           // Must be 1, region invalid if 0.
		std::uint64_t rw : 1;                 // If 0, writes not allowed.
		std::uint64_t user_supervisor : 1;   // If 0, user-mode accesses not allowed.
		std::uint64_t page_write_through : 1; // Determines the memory type used to access PDPT.
		std::uint64_t page_cache : 1;        // Determines the memory type used to access PDPT.
		std::uint64_t accessed : 1;          // If 0, this entry has not been used for translation.
		std::uint64_t Ignored1 : 1;
		std::uint64_t page_size : 1;         // Must be 0 for PML4E.
		std::uint64_t Ignored2 : 4;
		std::uint64_t pfn : 36;              // The page frame number of the PDPT of this PML4E.
		std::uint64_t reserved : 4;
		std::uint64_t Ignored3 : 11;
		std::uint64_t nx : 1;                // If 1, instruction fetches not allowed.
	};
};

union pdpte_t {
	std::uint64_t value;
	struct {
		std::uint64_t present : 1;            // Must be 1, region invalid if 0.
		std::uint64_t rw : 1;                 // If 0, writes not allowed.
		std::uint64_t user_supervisor : 1;    // If 0, user-mode accesses not allowed.
		std::uint64_t page_write : 1;          // Determines the memory type used to access PD.
		std::uint64_t page_cache : 1;         // Determines the memory type used to access PD.
		std::uint64_t accessed : 1;           // If 0, this entry has not been used for translation.
		std::uint64_t Ignored1 : 1;
		std::uint64_t page_size : 1;          // If 1, this entry maps a 1GB page.
		std::uint64_t Ignored2 : 4;
		std::uint64_t pfn : 36;               // The page frame number of the PD of this PDPTE.
		std::uint64_t reserved : 4;
		std::uint64_t Ignored3 : 11;
		std::uint64_t nx : 1;                 // If 1, instruction fetches not allowed.
	};
};


union pde_t {
	std::uint64_t value;
	struct {
		std::uint64_t present : 1;            // Must be 1, region invalid if 0.
		std::uint64_t rw : 1;                 // If 0, writes not allowed.
		std::uint64_t user_supervisor : 1;    // If 0, user-mode accesses not allowed.
		std::uint64_t page_write : 1;          // Determines the memory type used to access PD.
		std::uint64_t page_cache : 1;         // Determines the memory type used to access PD.
		std::uint64_t accessed : 1;           // If 0, this entry has not been used for translation.
		std::uint64_t Ignored1 : 1;
		std::uint64_t page_size : 1;          // If 1, this entry maps a 1GB page.
		std::uint64_t Ignored2 : 4;
		std::uint64_t pfn : 36;               // The page frame number of the PD of this PDPTE.
		std::uint64_t reserved : 4;
		std::uint64_t Ignored3 : 11;
		std::uint64_t nx : 1;                 // If 1, instruction fetches not allowed.
	};


	struct {
		std::uint64_t present : 1;
		std::uint64_t readWrite : 1;
		std::uint64_t userSupervisor : 1;
		std::uint64_t pageWriteThrough : 1;
		std::uint64_t pageCacheDisable : 1;
		std::uint64_t accessed : 1;
		std::uint64_t dirty : 1;
		std::uint64_t largePage : 1;
		std::uint64_t global : 1;
		std::uint64_t ignored0 : 3;
		std::uint64_t PageAttributeTable : 1;
		std::uint64_t reserved0 : 8;
		std::uint64_t pageFrameNumber : 29;
		std::uint64_t Reserved1 : 2;
		std::uint64_t ignored1 : 7;
		std::uint64_t protectionKey : 4;
		std::uint64_t noExecute : 1;
	}large;
};

union pte_t {
	std::uint64_t value;
	struct {
		std::uint64_t present : 1;          // Must be 1, region invalid if 0.
		std::uint64_t rw : 1;               // If 0, writes not allowed.
		std::uint64_t user_supervisor : 1;  // If 0, user-mode accesses not allowed.
		std::uint64_t page_write : 1;        // Determines the memory type used to access the memory.
		std::uint64_t page_cache : 1;       // Determines the memory type used to access the memory.
		std::uint64_t accessed : 1;         // If 0, this entry has not been used for translation.
		std::uint64_t dirty : 1;             // If 0, the memory backing this page has not been written to.
		std::uint64_t page_access_type : 1;  // Determines the memory type used to access the memory.
		std::uint64_t global : 1;            // If 1 and the PGE bit of CR4 is set, translations are global.
		std::uint64_t ignored2 : 3;
		std::uint64_t pfn : 36;             // The page frame number of the backing physical page.
		std::uint64_t reserved : 4;
		std::uint64_t ignored3 : 7;
		std::uint64_t protect_key : 4;       // If the PKE bit of CR4 is set, determines the protection key.
		std::uint64_t nx : 1;               // If 1, instruction fetches not allowed.
	};
};

union virt_addr_t {
	std::uint64_t value;
	struct {
		std::uint64_t offset : 12;
		std::uint64_t pt_index : 9;
		std::uint64_t pd_index : 9;
		std::uint64_t pdpt_index : 9;
		std::uint64_t pml4_index : 9;
		std::uint64_t reserved : 16;
	};
};

typedef union {
	struct {
		/**
		 * [Bit 0] Present; must be 1 to reference a page-directory-pointer table.
		 */
		UINT64 Present : 1;
#define PML4E_64_PRESENT_BIT 0
#define PML4E_64_PRESENT_FLAG 0x01
#define PML4E_64_PRESENT_MASK 0x01
#define PML4E_64_PRESENT(_) (((_) >> 0) & 0x01)

		/**
		 * [Bit 1] Read/write; if 0, writes may not be allowed to the 512-GByte region controlled by
		 * this entry.
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 Write : 1;
#define PML4E_64_WRITE_BIT 1
#define PML4E_64_WRITE_FLAG 0x02
#define PML4E_64_WRITE_MASK 0x01
#define PML4E_64_WRITE(_) (((_) >> 1) & 0x01)

		/**
		 * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 512-GByte region
		 * controlled by this entry.
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 Supervisor : 1;
#define PML4E_64_SUPERVISOR_BIT 2
#define PML4E_64_SUPERVISOR_FLAG 0x04
#define PML4E_64_SUPERVISOR_MASK 0x01
#define PML4E_64_SUPERVISOR(_) (((_) >> 2) & 0x01)

		/**
		 * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the
		 * page-directory-pointer table referenced by this entry.
		 *
		 * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More
		 * Recent Processor Families))]
		 */
		UINT64 PageLevelWriteThrough : 1;
#define PML4E_64_PAGE_LEVEL_WRITE_THROUGH_BIT 3
#define PML4E_64_PAGE_LEVEL_WRITE_THROUGH_FLAG 0x08
#define PML4E_64_PAGE_LEVEL_WRITE_THROUGH_MASK 0x01
#define PML4E_64_PAGE_LEVEL_WRITE_THROUGH(_) (((_) >> 3) & 0x01)

		/**
		 * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the
		 * page-directory-pointer table referenced by this entry.
		 *
		 * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More
		 * Recent Processor Families))]
		 */
		UINT64 PageLevelCacheDisable : 1;
#define PML4E_64_PAGE_LEVEL_CACHE_DISABLE_BIT 4
#define PML4E_64_PAGE_LEVEL_CACHE_DISABLE_FLAG 0x10
#define PML4E_64_PAGE_LEVEL_CACHE_DISABLE_MASK 0x01
#define PML4E_64_PAGE_LEVEL_CACHE_DISABLE(_) (((_) >> 4) & 0x01)

		/**
		 * [Bit 5] Accessed; indicates whether this entry has been used for linear-address translation.
		 *
		 * @see Vol3A[4.8(Accessed and Dirty Flags)]
		 */
		UINT64 Accessed : 1;
#define PML4E_64_ACCESSED_BIT 5
#define PML4E_64_ACCESSED_FLAG 0x20
#define PML4E_64_ACCESSED_MASK 0x01
#define PML4E_64_ACCESSED(_) (((_) >> 5) & 0x01)
		UINT64 Reserved1 : 1;

		/**
		 * [Bit 7] Reserved (must be 0).
		 */
		UINT64 MustBeZero : 1;
#define PML4E_64_MUST_BE_ZERO_BIT 7
#define PML4E_64_MUST_BE_ZERO_FLAG 0x80
#define PML4E_64_MUST_BE_ZERO_MASK 0x01
#define PML4E_64_MUST_BE_ZERO(_) (((_) >> 7) & 0x01)

		/**
		 * [Bits 11:8] Ignored.
		 */
		UINT64 Ignored1 : 4;
#define PML4E_64_IGNORED_1_BIT 8
#define PML4E_64_IGNORED_1_FLAG 0xF00
#define PML4E_64_IGNORED_1_MASK 0x0F
#define PML4E_64_IGNORED_1(_) (((_) >> 8) & 0x0F)

		/**
		 * [Bits 47:12] Physical address of 4-KByte aligned page-directory-pointer table referenced by
		 * this entry.
		 */
		UINT64 PageFrameNumber : 36;
#define PML4E_64_PAGE_FRAME_NUMBER_BIT 12
#define PML4E_64_PAGE_FRAME_NUMBER_FLAG 0xFFFFFFFFF000
#define PML4E_64_PAGE_FRAME_NUMBER_MASK 0xFFFFFFFFF
#define PML4E_64_PAGE_FRAME_NUMBER(_) (((_) >> 12) & 0xFFFFFFFFF)
		UINT64 Reserved2 : 4;

		/**
		 * [Bits 62:52] Ignored.
		 */
		UINT64 Ignored2 : 11;
#define PML4E_64_IGNORED_2_BIT 52
#define PML4E_64_IGNORED_2_FLAG 0x7FF0000000000000
#define PML4E_64_IGNORED_2_MASK 0x7FF
#define PML4E_64_IGNORED_2(_) (((_) >> 52) & 0x7FF)

		/**
		 * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed
		 * from the 512-GByte region controlled by this entry); otherwise, reserved (must be 0).
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 ExecuteDisable : 1;
#define PML4E_64_EXECUTE_DISABLE_BIT 63
#define PML4E_64_EXECUTE_DISABLE_FLAG 0x8000000000000000
#define PML4E_64_EXECUTE_DISABLE_MASK 0x01
#define PML4E_64_EXECUTE_DISABLE(_) (((_) >> 63) & 0x01)
	};

	UINT64 Flags;
} PML4E_64;


/**
 * @brief Format of a 4-Level Page-Directory-Pointer-Table Entry (PDPTE) that References a Page
 * Directory
 */
typedef union {
	struct {
		/**
		 * [Bit 0] Present; must be 1 to reference a page directory.
		 */
		UINT64 Present : 1;
#define PDPTE_64_PRESENT_BIT 0
#define PDPTE_64_PRESENT_FLAG 0x01
#define PDPTE_64_PRESENT_MASK 0x01
#define PDPTE_64_PRESENT(_) (((_) >> 0) & 0x01)

		/**
		 * [Bit 1] Read/write; if 0, writes may not be allowed to the 1-GByte region controlled by this
		 * entry.
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 Write : 1;
#define PDPTE_64_WRITE_BIT 1
#define PDPTE_64_WRITE_FLAG 0x02
#define PDPTE_64_WRITE_MASK 0x01
#define PDPTE_64_WRITE(_) (((_) >> 1) & 0x01)

		/**
		 * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 1-GByte region
		 * controlled by this entry.
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 Supervisor : 1;
#define PDPTE_64_SUPERVISOR_BIT 2
#define PDPTE_64_SUPERVISOR_FLAG 0x04
#define PDPTE_64_SUPERVISOR_MASK 0x01
#define PDPTE_64_SUPERVISOR(_) (((_) >> 2) & 0x01)

		/**
		 * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the
		 * page directory referenced by this entry.
		 *
		 * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More
		 * Recent Processor Families))]
		 */
		UINT64 PageLevelWriteThrough : 1;
#define PDPTE_64_PAGE_LEVEL_WRITE_THROUGH_BIT 3
#define PDPTE_64_PAGE_LEVEL_WRITE_THROUGH_FLAG 0x08
#define PDPTE_64_PAGE_LEVEL_WRITE_THROUGH_MASK 0x01
#define PDPTE_64_PAGE_LEVEL_WRITE_THROUGH(_) (((_) >> 3) & 0x01)

		/**
		 * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the
		 * page directory referenced by this entry.
		 *
		 * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More
		 * Recent Processor Families))]
		 */
		UINT64 PageLevelCacheDisable : 1;
#define PDPTE_64_PAGE_LEVEL_CACHE_DISABLE_BIT 4
#define PDPTE_64_PAGE_LEVEL_CACHE_DISABLE_FLAG 0x10
#define PDPTE_64_PAGE_LEVEL_CACHE_DISABLE_MASK 0x01
#define PDPTE_64_PAGE_LEVEL_CACHE_DISABLE(_) (((_) >> 4) & 0x01)

		/**
		 * [Bit 5] Accessed; indicates whether this entry has been used for linear-address translation.
		 *
		 * @see Vol3A[4.8(Accessed and Dirty Flags)]
		 */
		UINT64 Accessed : 1;
#define PDPTE_64_ACCESSED_BIT 5
#define PDPTE_64_ACCESSED_FLAG 0x20
#define PDPTE_64_ACCESSED_MASK 0x01
#define PDPTE_64_ACCESSED(_) (((_) >> 5) & 0x01)
		UINT64 Reserved1 : 1;

		/**
		 * [Bit 7] Page size; must be 0 (otherwise, this entry maps a 1-GByte page).
		 */
		UINT64 LargePage : 1;
#define PDPTE_64_LARGE_PAGE_BIT 7
#define PDPTE_64_LARGE_PAGE_FLAG 0x80
#define PDPTE_64_LARGE_PAGE_MASK 0x01
#define PDPTE_64_LARGE_PAGE(_) (((_) >> 7) & 0x01)

		/**
		 * [Bits 11:8] Ignored.
		 */
		UINT64 Ignored1 : 4;
#define PDPTE_64_IGNORED_1_BIT 8
#define PDPTE_64_IGNORED_1_FLAG 0xF00
#define PDPTE_64_IGNORED_1_MASK 0x0F
#define PDPTE_64_IGNORED_1(_) (((_) >> 8) & 0x0F)

		/**
		 * [Bits 47:12] Physical address of 4-KByte aligned page directory referenced by this entry.
		 */
		UINT64 PageFrameNumber : 36;
#define PDPTE_64_PAGE_FRAME_NUMBER_BIT 12
#define PDPTE_64_PAGE_FRAME_NUMBER_FLAG 0xFFFFFFFFF000
#define PDPTE_64_PAGE_FRAME_NUMBER_MASK 0xFFFFFFFFF
#define PDPTE_64_PAGE_FRAME_NUMBER(_) (((_) >> 12) & 0xFFFFFFFFF)
		UINT64 Reserved2 : 4;

		/**
		 * [Bits 62:52] Ignored.
		 */
		UINT64 Ignored2 : 11;
#define PDPTE_64_IGNORED_2_BIT 52
#define PDPTE_64_IGNORED_2_FLAG 0x7FF0000000000000
#define PDPTE_64_IGNORED_2_MASK 0x7FF
#define PDPTE_64_IGNORED_2(_) (((_) >> 52) & 0x7FF)

		/**
		 * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed
		 * from the 1-GByte region controlled by this entry); otherwise, reserved (must be 0).
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 ExecuteDisable : 1;
#define PDPTE_64_EXECUTE_DISABLE_BIT 63
#define PDPTE_64_EXECUTE_DISABLE_FLAG 0x8000000000000000
#define PDPTE_64_EXECUTE_DISABLE_MASK 0x01
#define PDPTE_64_EXECUTE_DISABLE(_) (((_) >> 63) & 0x01)
	};

	UINT64 Flags;
} PDPTE_64;

/**
 * @brief Format of a 4-Level Page-Directory Entry that References a Page Table
 */
typedef union {
	struct {
		/**
		 * [Bit 0] Present; must be 1 to reference a page table.
		 */
		UINT64 Present : 1;
#define PDE_64_PRESENT_BIT 0
#define PDE_64_PRESENT_FLAG 0x01
#define PDE_64_PRESENT_MASK 0x01
#define PDE_64_PRESENT(_) (((_) >> 0) & 0x01)

		/**
		 * [Bit 1] Read/write; if 0, writes may not be allowed to the 2-MByte region controlled by this
		 * entry.
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 Write : 1;
#define PDE_64_WRITE_BIT 1
#define PDE_64_WRITE_FLAG 0x02
#define PDE_64_WRITE_MASK 0x01
#define PDE_64_WRITE(_) (((_) >> 1) & 0x01)

		/**
		 * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 2-MByte region
		 * controlled by this entry.
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 Supervisor : 1;
#define PDE_64_SUPERVISOR_BIT 2
#define PDE_64_SUPERVISOR_FLAG 0x04
#define PDE_64_SUPERVISOR_MASK 0x01
#define PDE_64_SUPERVISOR(_) (((_) >> 2) & 0x01)

		/**
		 * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the
		 * page table referenced by this entry.
		 *
		 * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More
		 * Recent Processor Families))]
		 */
		UINT64 PageLevelWriteThrough : 1;
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH_BIT 3
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH_FLAG 0x08
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH_MASK 0x01
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH(_) (((_) >> 3) & 0x01)

		/**
		 * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the
		 * page table referenced by this entry.
		 *
		 * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More
		 * Recent Processor Families))]
		 */
		UINT64 PageLevelCacheDisable : 1;
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE_BIT 4
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE_FLAG 0x10
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE_MASK 0x01
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE(_) (((_) >> 4) & 0x01)

		/**
		 * [Bit 5] Accessed; indicates whether this entry has been used for linear-address translation.
		 *
		 * @see Vol3A[4.8(Accessed and Dirty Flags)]
		 */
		UINT64 Accessed : 1;
#define PDE_64_ACCESSED_BIT 5
#define PDE_64_ACCESSED_FLAG 0x20
#define PDE_64_ACCESSED_MASK 0x01
#define PDE_64_ACCESSED(_) (((_) >> 5) & 0x01)
		UINT64 Reserved1 : 1;

		/**
		 * [Bit 7] Page size; must be 0 (otherwise, this entry maps a 2-MByte page).
		 */
		UINT64 LargePage : 1;
#define PDE_64_LARGE_PAGE_BIT 7
#define PDE_64_LARGE_PAGE_FLAG 0x80
#define PDE_64_LARGE_PAGE_MASK 0x01
#define PDE_64_LARGE_PAGE(_) (((_) >> 7) & 0x01)

		/**
		 * [Bits 11:8] Ignored.
		 */
		UINT64 Ignored1 : 4;
#define PDE_64_IGNORED_1_BIT 8
#define PDE_64_IGNORED_1_FLAG 0xF00
#define PDE_64_IGNORED_1_MASK 0x0F
#define PDE_64_IGNORED_1(_) (((_) >> 8) & 0x0F)

		/**
		 * [Bits 47:12] Physical address of 4-KByte aligned page table referenced by this entry.
		 */
		UINT64 PageFrameNumber : 36;
#define PDE_64_PAGE_FRAME_NUMBER_BIT 12
#define PDE_64_PAGE_FRAME_NUMBER_FLAG 0xFFFFFFFFF000
#define PDE_64_PAGE_FRAME_NUMBER_MASK 0xFFFFFFFFF
#define PDE_64_PAGE_FRAME_NUMBER(_) (((_) >> 12) & 0xFFFFFFFFF)
		UINT64 Reserved2 : 4;

		/**
		 * [Bits 62:52] Ignored.
		 */
		UINT64 Ignored2 : 11;
#define PDE_64_IGNORED_2_BIT 52
#define PDE_64_IGNORED_2_FLAG 0x7FF0000000000000
#define PDE_64_IGNORED_2_MASK 0x7FF
#define PDE_64_IGNORED_2(_) (((_) >> 52) & 0x7FF)

		/**
		 * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed
		 * from the 2-MByte region controlled by this entry); otherwise, reserved (must be 0).
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 ExecuteDisable : 1;
#define PDE_64_EXECUTE_DISABLE_BIT 63
#define PDE_64_EXECUTE_DISABLE_FLAG 0x8000000000000000
#define PDE_64_EXECUTE_DISABLE_MASK 0x01
#define PDE_64_EXECUTE_DISABLE(_) (((_) >> 63) & 0x01)
	};

	UINT64 Flags;
} PDE_64;

/**
 * @brief Format of a 4-Level Page-Table Entry that Maps a 4-KByte Page
 */
typedef union {
	struct {
		/**
		 * [Bit 0] Present; must be 1 to map a 4-KByte page.
		 */
		UINT64 Present : 1;
#define PTE_64_PRESENT_BIT 0
#define PTE_64_PRESENT_FLAG 0x01
#define PTE_64_PRESENT_MASK 0x01
#define PTE_64_PRESENT(_) (((_) >> 0) & 0x01)

		/**
		 * [Bit 1] Read/write; if 0, writes may not be allowed to the 4-KByte page referenced by this
		 * entry.
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 Write : 1;
#define PTE_64_WRITE_BIT 1
#define PTE_64_WRITE_FLAG 0x02
#define PTE_64_WRITE_MASK 0x01
#define PTE_64_WRITE(_) (((_) >> 1) & 0x01)

		/**
		 * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 4-KByte page
		 * referenced by this entry.
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 Supervisor : 1;
#define PTE_64_SUPERVISOR_BIT 2
#define PTE_64_SUPERVISOR_FLAG 0x04
#define PTE_64_SUPERVISOR_MASK 0x01
#define PTE_64_SUPERVISOR(_) (((_) >> 2) & 0x01)

		/**
		 * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the
		 * 4-KByte page referenced by this entry.
		 *
		 * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More
		 * Recent Processor Families))]
		 */
		UINT64 PageLevelWriteThrough : 1;
#define PTE_64_PAGE_LEVEL_WRITE_THROUGH_BIT 3
#define PTE_64_PAGE_LEVEL_WRITE_THROUGH_FLAG 0x08
#define PTE_64_PAGE_LEVEL_WRITE_THROUGH_MASK 0x01
#define PTE_64_PAGE_LEVEL_WRITE_THROUGH(_) (((_) >> 3) & 0x01)

		/**
		 * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the
		 * 4-KByte page referenced by this entry.
		 *
		 * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More
		 * Recent Processor Families))]
		 */
		UINT64 PageLevelCacheDisable : 1;
#define PTE_64_PAGE_LEVEL_CACHE_DISABLE_BIT 4
#define PTE_64_PAGE_LEVEL_CACHE_DISABLE_FLAG 0x10
#define PTE_64_PAGE_LEVEL_CACHE_DISABLE_MASK 0x01
#define PTE_64_PAGE_LEVEL_CACHE_DISABLE(_) (((_) >> 4) & 0x01)

		/**
		 * [Bit 5] Accessed; indicates whether software has accessed the 4-KByte page referenced by this
		 * entry.
		 *
		 * @see Vol3A[4.8(Accessed and Dirty Flags)]
		 */
		UINT64 Accessed : 1;
#define PTE_64_ACCESSED_BIT 5
#define PTE_64_ACCESSED_FLAG 0x20
#define PTE_64_ACCESSED_MASK 0x01
#define PTE_64_ACCESSED(_) (((_) >> 5) & 0x01)

		/**
		 * [Bit 6] Dirty; indicates whether software has written to the 4-KByte page referenced by this
		 * entry.
		 *
		 * @see Vol3A[4.8(Accessed and Dirty Flags)]
		 */
		UINT64 Dirty : 1;
#define PTE_64_DIRTY_BIT 6
#define PTE_64_DIRTY_FLAG 0x40
#define PTE_64_DIRTY_MASK 0x01
#define PTE_64_DIRTY(_) (((_) >> 6) & 0x01)

		/**
		 * [Bit 7] Indirectly determines the memory type used to access the 4-KByte page referenced by
		 * this entry.
		 *
		 * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More
		 * Recent Processor Families))]
		 */
		UINT64 Pat : 1;
#define PTE_64_PAT_BIT 7
#define PTE_64_PAT_FLAG 0x80
#define PTE_64_PAT_MASK 0x01
#define PTE_64_PAT(_) (((_) >> 7) & 0x01)

		/**
		 * [Bit 8] Global; if CR4.PGE = 1, determines whether the translation is global; ignored
		 * otherwise.
		 *
		 * @see Vol3A[4.10(Caching Translation Information)]
		 */
		UINT64 Global : 1;
#define PTE_64_GLOBAL_BIT 8
#define PTE_64_GLOBAL_FLAG 0x100
#define PTE_64_GLOBAL_MASK 0x01
#define PTE_64_GLOBAL(_) (((_) >> 8) & 0x01)

		/**
		 * [Bits 11:9] Ignored.
		 */
		UINT64 CopyOnWrite : 1;
		UINT64 Unused : 1;
		UINT64 Write1 : 1;
#define PTE_64_IGNORED_1_BIT 9
#define PTE_64_IGNORED_1_FLAG 0xE00
#define PTE_64_IGNORED_1_MASK 0x07
#define PTE_64_IGNORED_1(_) (((_) >> 9) & 0x07)

		/**
		 * [Bits 47:12] Physical address of the 4-KByte page referenced by this entry.
		 */
		UINT64 PageFrameNumber : 36;
#define PTE_64_PAGE_FRAME_NUMBER_BIT 12
#define PTE_64_PAGE_FRAME_NUMBER_FLAG 0xFFFFFFFFF000
#define PTE_64_PAGE_FRAME_NUMBER_MASK 0xFFFFFFFFF
#define PTE_64_PAGE_FRAME_NUMBER(_) (((_) >> 12) & 0xFFFFFFFFF)
		UINT64 Reserved1 : 4;

		/**
		 * [Bits 58:52] Ignored.
		 */
		UINT64 Ignored2 : 7;
#define PTE_64_IGNORED_2_BIT 52
#define PTE_64_IGNORED_2_FLAG 0x7F0000000000000
#define PTE_64_IGNORED_2_MASK 0x7F
#define PTE_64_IGNORED_2(_) (((_) >> 52) & 0x7F)

		/**
		 * [Bits 62:59] Protection key; if CR4.PKE = 1, determines the protection key of the page;
		 * ignored otherwise.
		 *
		 * @see Vol3A[4.6.2(Protection Keys)]
		 */
		UINT64 ProtectionKey : 4;
#define PTE_64_PROTECTION_KEY_BIT 59
#define PTE_64_PROTECTION_KEY_FLAG 0x7800000000000000
#define PTE_64_PROTECTION_KEY_MASK 0x0F
#define PTE_64_PROTECTION_KEY(_) (((_) >> 59) & 0x0F)

		/**
		 * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed
		 * from the 1-GByte page controlled by this entry); otherwise, reserved (must be 0).
		 *
		 * @see Vol3A[4.6(Access Rights)]
		 */
		UINT64 ExecuteDisable : 1;
#define PTE_64_EXECUTE_DISABLE_BIT 63
#define PTE_64_EXECUTE_DISABLE_FLAG 0x8000000000000000
#define PTE_64_EXECUTE_DISABLE_MASK 0x01
#define PTE_64_EXECUTE_DISABLE(_) (((_) >> 63) & 0x01)
	};

	UINT64 Flags;
} PTE_64;

/**
 * @brief Format of a common Page-Table Entry
 */
typedef union {
	struct {
		UINT64 Present : 1;
#define PT_ENTRY_64_PRESENT_BIT 0
#define PT_ENTRY_64_PRESENT_FLAG 0x01
#define PT_ENTRY_64_PRESENT_MASK 0x01
#define PT_ENTRY_64_PRESENT(_) (((_) >> 0) & 0x01)
		UINT64 Write : 1;
#define PT_ENTRY_64_WRITE_BIT 1
#define PT_ENTRY_64_WRITE_FLAG 0x02
#define PT_ENTRY_64_WRITE_MASK 0x01
#define PT_ENTRY_64_WRITE(_) (((_) >> 1) & 0x01)
		UINT64 Supervisor : 1;
#define PT_ENTRY_64_SUPERVISOR_BIT 2
#define PT_ENTRY_64_SUPERVISOR_FLAG 0x04
#define PT_ENTRY_64_SUPERVISOR_MASK 0x01
#define PT_ENTRY_64_SUPERVISOR(_) (((_) >> 2) & 0x01)
		UINT64 PageLevelWriteThrough : 1;
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH_BIT 3
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH_FLAG 0x08
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH_MASK 0x01
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH(_) (((_) >> 3) & 0x01)
		UINT64 PageLevelCacheDisable : 1;
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE_BIT 4
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE_FLAG 0x10
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE_MASK 0x01
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE(_) (((_) >> 4) & 0x01)
		UINT64 Accessed : 1;
#define PT_ENTRY_64_ACCESSED_BIT 5
#define PT_ENTRY_64_ACCESSED_FLAG 0x20
#define PT_ENTRY_64_ACCESSED_MASK 0x01
#define PT_ENTRY_64_ACCESSED(_) (((_) >> 5) & 0x01)
		UINT64 Dirty : 1;
#define PT_ENTRY_64_DIRTY_BIT 6
#define PT_ENTRY_64_DIRTY_FLAG 0x40
#define PT_ENTRY_64_DIRTY_MASK 0x01
#define PT_ENTRY_64_DIRTY(_) (((_) >> 6) & 0x01)
		UINT64 LargePage : 1;
#define PT_ENTRY_64_LARGE_PAGE_BIT 7
#define PT_ENTRY_64_LARGE_PAGE_FLAG 0x80
#define PT_ENTRY_64_LARGE_PAGE_MASK 0x01
#define PT_ENTRY_64_LARGE_PAGE(_) (((_) >> 7) & 0x01)
		UINT64 Global : 1;
#define PT_ENTRY_64_GLOBAL_BIT 8
#define PT_ENTRY_64_GLOBAL_FLAG 0x100
#define PT_ENTRY_64_GLOBAL_MASK 0x01
#define PT_ENTRY_64_GLOBAL(_) (((_) >> 8) & 0x01)

		/**
		 * [Bits 11:9] Ignored.
		 */
		UINT64 Ignored1 : 3;
#define PT_ENTRY_64_IGNORED_1_BIT 9
#define PT_ENTRY_64_IGNORED_1_FLAG 0xE00
#define PT_ENTRY_64_IGNORED_1_MASK 0x07
#define PT_ENTRY_64_IGNORED_1(_) (((_) >> 9) & 0x07)

		/**
		 * [Bits 47:12] Physical address of the 4-KByte page referenced by this entry.
		 */
		UINT64 PageFrameNumber : 36;
#define PT_ENTRY_64_PAGE_FRAME_NUMBER_BIT 12
#define PT_ENTRY_64_PAGE_FRAME_NUMBER_FLAG 0xFFFFFFFFF000
#define PT_ENTRY_64_PAGE_FRAME_NUMBER_MASK 0xFFFFFFFFF
#define PT_ENTRY_64_PAGE_FRAME_NUMBER(_) (((_) >> 12) & 0xFFFFFFFFF)
		UINT64 Reserved1 : 4;

		/**
		 * [Bits 58:52] Ignored.
		 */
		UINT64 Ignored2 : 7;
#define PT_ENTRY_64_IGNORED_2_BIT 52
#define PT_ENTRY_64_IGNORED_2_FLAG 0x7F0000000000000
#define PT_ENTRY_64_IGNORED_2_MASK 0x7F
#define PT_ENTRY_64_IGNORED_2(_) (((_) >> 52) & 0x7F)
		UINT64 ProtectionKey : 4;
#define PT_ENTRY_64_PROTECTION_KEY_BIT 59
#define PT_ENTRY_64_PROTECTION_KEY_FLAG 0x7800000000000000
#define PT_ENTRY_64_PROTECTION_KEY_MASK 0x0F
#define PT_ENTRY_64_PROTECTION_KEY(_) (((_) >> 59) & 0x0F)
		UINT64 ExecuteDisable : 1;
#define PT_ENTRY_64_EXECUTE_DISABLE_BIT 63
#define PT_ENTRY_64_EXECUTE_DISABLE_FLAG 0x8000000000000000
#define PT_ENTRY_64_EXECUTE_DISABLE_MASK 0x01
#define PT_ENTRY_64_EXECUTE_DISABLE(_) (((_) >> 63) & 0x01)
	};

	UINT64 Flags;
} PT_ENTRY_64;

typedef union _ADDRESS_TRANSLATION_HELPER {
	//
	// Indexes to locate paging-structure entries corresponds to this virtual
	// address.
	//
	struct {
		UINT64 Unused : 12;  //< [11:0]
		UINT64 Pt : 9;       //< [20:12]
		UINT64 Pd : 9;       //< [29:21]
		UINT64 Pdpt : 9;     //< [38:30]
		UINT64 Pml4 : 9;     //< [47:39]
	} AsIndex;

	//
	// The page offset for each type of pages. For example, for 4KB pages, bits
	// [11:0] are treated as the page offset and Mapping4Kb can be used for it.
	//
	union {
		UINT64 Mapping4Kb : 12;  //< [11:0]
		UINT64 Mapping2Mb : 21;  //< [20:0]
		UINT64 Mapping1Gb : 30;  //< [29:0]
	} AsPageOffset;

	UINT64 AsUInt64;
} ADDRESS_TRANSLATION_HELPER;

typedef struct _PAGE_INFORMATION {
	PML4E_64* PML4E;
	PDPTE_64* PDPTE;
	PDE_64* PDE;
	PTE_64* PTE;
} PAGE_INFORMATION, * PPAGE_INFORMATION;

typedef union {
	struct {
		UINT64 Reserved1 : 3;

		/**
		 * @brief Page-level Write-Through
		 *
		 * [Bit 3] Controls the memory type used to access the first paging structure of the current
		 * paging-structure hierarchy. This bit is not used if paging is disabled, with PAE paging, or
		 * with 4-level paging if CR4.PCIDE=1.
		 *
		 * @see Vol3A[4.9(PAGING AND MEMORY TYPING)]
		 */
		UINT64 PageLevelWriteThrough : 1;
#define CR3_PAGE_LEVEL_WRITE_THROUGH_BIT 3
#define CR3_PAGE_LEVEL_WRITE_THROUGH_FLAG 0x08
#define CR3_PAGE_LEVEL_WRITE_THROUGH_MASK 0x01
#define CR3_PAGE_LEVEL_WRITE_THROUGH(_) (((_) >> 3) & 0x01)

		/**
		 * @brief Page-level Cache Disable
		 *
		 * [Bit 4] Controls the memory type used to access the first paging structure of the current
		 * paging-structure hierarchy. This bit is not used if paging is disabled, with PAE paging, or
		 * with 4-level paging2 if CR4.PCIDE=1.
		 *
		 * @see Vol3A[4.9(PAGING AND MEMORY TYPING)]
		 */
		UINT64 PageLevelCacheDisable : 1;
#define CR3_PAGE_LEVEL_CACHE_DISABLE_BIT 4
#define CR3_PAGE_LEVEL_CACHE_DISABLE_FLAG 0x10
#define CR3_PAGE_LEVEL_CACHE_DISABLE_MASK 0x01
#define CR3_PAGE_LEVEL_CACHE_DISABLE(_) (((_) >> 4) & 0x01)
		UINT64 Reserved2 : 7;

		/**
		 * @brief Address of page directory
		 *
		 * [Bits 47:12] Physical address of the 4-KByte aligned page directory (32-bit paging) or PML4
		 * table (64-bit paging) used for linear-address translation.
		 *
		 * @see Vol3A[4.3(32-BIT PAGING)]
		 * @see Vol3A[4.5(4-LEVEL PAGING)]
		 */
		UINT64 AddressOfPageDirectory : 36;
#define CR3_ADDRESS_OF_PAGE_DIRECTORY_BIT 12
#define CR3_ADDRESS_OF_PAGE_DIRECTORY_FLAG 0xFFFFFFFFF000
#define CR3_ADDRESS_OF_PAGE_DIRECTORY_MASK 0xFFFFFFFFF
#define CR3_ADDRESS_OF_PAGE_DIRECTORY(_) (((_) >> 12) & 0xFFFFFFFFF)
		UINT64 Reserved3 : 16;
	};

	UINT64 Flags;
} CR333;

#define PAGE_SIZE 0x1000
#define PAGE_SHIFT 12

#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

struct _MMPFNENTRY3 {
	UCHAR Priority : 3;
	UCHAR OnProtectedStandby : 1;
	UCHAR InPageError : 1;
	UCHAR SystemChargedPage : 1;
	UCHAR RemovalRequested : 1;
	UCHAR ParityError : 1;
};


// 0x8 bytes (sizeof)
struct _MIPFNBLINK {
	union {
		struct {
			ULONGLONG Blink : 40;                   // 0x0
			ULONGLONG NodeBlinkLow : 19;            // 0x0
			ULONGLONG TbFlushStamp : 3;             // 0x0
			ULONGLONG PageBlinkDeleteBit : 1;       // 0x0
			ULONGLONG PageBlinkLockBit : 1;         // 0x0
			ULONGLONG ShareCount : 62;              // 0x0
			ULONGLONG PageShareCountDeleteBit : 1;  // 0x0
			ULONGLONG PageShareCountLockBit : 1;    // 0x0
		};
		LONGLONG EntireField;  // 0x0
		struct {
			ULONGLONG LockNotUsed : 62;  // 0x0
			ULONGLONG DeleteBit : 1;     // 0x0
			ULONGLONG LockBit : 1;       // 0x0
		};
	};
};
