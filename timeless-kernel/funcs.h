#include "utils.h"

extern "C" std::uintptr_t get_nt_base();

namespace nt {
	class c_resolver {
	public:
		template<typename type>
		type get(std::uint64_t offset) const {
			return *reinterpret_cast<type*>(m_nt_base + offset);
		}

		bool setup() {
			m_nt_base = (get_nt_base());
			return m_nt_base != 0;
		}

		std::uintptr_t scan_text_section(const char* pattern, const char* mask) const {
			std::uintptr_t base = 0, size = 0;
			if (!next_exec_section(&base, &size))
				return 0;
			return find_pattern(base, size, pattern, mask);
		}

		std::uintptr_t scan_ida_pattern(const char* ida_pattern) const {
			std::uintptr_t base = 0, size = 0;
			if (!next_exec_section(&base, &size))
				return 0;
			return find_ida_pattern(base, size, ida_pattern);
		}

		std::uintptr_t find_pattern(std::uintptr_t base, size_t size, const char* pattern, const char* mask) const {
			size_t len = utils.strlen(mask);
			for (size_t i = 0; i <= size - len; ++i) {
				bool matched = true;
				for (size_t j = 0; j < len; ++j) {
					if (mask[j] == 'x' && pattern[j] != *(char*)(base + i + j)) {
						matched = false;
						break;
					}
				}
				if (matched) return base + i;
			}
			return 0;
		}

		std::uintptr_t find_ida_pattern(std::uintptr_t base, size_t size, const char* ida_pattern) const {
			uint8_t pattern[256]{};
			char mask[256]{};
			size_t pat_len = 0;

			const char* p = ida_pattern;
			while (*p && pat_len < sizeof(pattern)) {
				if (*p == ' ') {
					++p;
					continue;
				}
				if (*p == '?') {
					pattern[pat_len] = 0;
					mask[pat_len++] = '?';
					++p;
					if (*p == '?') ++p;
				}
				else {
					char byte_str[3] = { p[0], p[1], 0 };
					pattern[pat_len] = static_cast<uint8_t>(utils.strtoul(byte_str, nullptr, 16));
					mask[pat_len++] = 'x';
					p += 2;
				}
			}

			return find_signature(base, size, pattern, mask);
		}

		std::uintptr_t find_signature(std::uintptr_t base, size_t size, const uint8_t* signature, const char* mask) const {
			size_t len = utils.strlen(mask);
			for (size_t i = 0; i <= size - len; ++i) {
				bool matched = true;
				for (size_t j = 0; j < len; ++j) {
					if (mask[j] == 'x' && signature[j] != *(uint8_t*)(base + i + j)) {
						matched = false;
						break;
					}
				}
				if (matched) return base + i;
			}
			return 0;
		}

		bool next_exec_section(std::uintptr_t* exec_base, std::uintptr_t* exec_size) const {
			auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(m_nt_base);
			if (dos->e_magic != IMAGE_DOS_SIGNATURE)
				return false;

			auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_nt_base + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE)
				return false;

			auto sec = IMAGE_FIRST_SECTION(nt);
			for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
				if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
					*exec_base = m_nt_base + sec->VirtualAddress;
					*exec_size = sec->SizeOfRawData;
					return true;
				}
			}

			return false;
		}

		std::uint64_t get_export_address(const char* export_name) {
			if (!m_nt_base || !export_name)
				return 0;

			auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(m_nt_base);
			if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
				return 0;

			auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_nt_base + dos_header->e_lfanew);
			if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
				return 0;

			auto& data_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!data_directory.VirtualAddress || !data_directory.Size)
				return 0;

			auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(m_nt_base + data_directory.VirtualAddress);
			if (!export_directory || !export_directory->AddressOfFunctions || !export_directory->AddressOfNames || !export_directory->AddressOfNameOrdinals)
				return 0;

			auto names = reinterpret_cast<std::uint32_t*>(m_nt_base + export_directory->AddressOfNames);
			auto functions = reinterpret_cast<std::uint32_t*>(m_nt_base + export_directory->AddressOfFunctions);
			auto ordinals = reinterpret_cast<std::uint16_t*>(m_nt_base + export_directory->AddressOfNameOrdinals);

			for (std::uint32_t i = 0; i < export_directory->NumberOfNames; ++i) {
				const char* name = reinterpret_cast<const char*>(m_nt_base + names[i]);
				if (!utils.strcmp(name, export_name)) {
					auto function_rva = functions[ordinals[i]];
					return m_nt_base + function_rva;
				}
			}

			return 0;
		}

		std::uintptr_t get_system_routine(const char* name) const {
			auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(m_nt_base);
			auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(m_nt_base + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE)
				return 0;

			auto dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!dir.VirtualAddress)
				return 0;

			auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(m_nt_base + dir.VirtualAddress);
			auto names = reinterpret_cast<uint32_t*>(m_nt_base + export_dir->AddressOfNames);
			auto funcs = reinterpret_cast<uint32_t*>(m_nt_base + export_dir->AddressOfFunctions);
			auto ordinals = reinterpret_cast<uint16_t*>(m_nt_base + export_dir->AddressOfNameOrdinals);

			for (size_t i = 0; i < export_dir->NumberOfNames; ++i) {
				const char* cur_name = reinterpret_cast<const char*>(m_nt_base + names[i]);
				if (utils.strcmp(cur_name, name) == 0) {
					return m_nt_base + funcs[ordinals[i]];
				}
			}

			return 0;
		}

	private:
		std::uintptr_t m_nt_base = 0;
	};
}


namespace nt {
	c_resolver g_resolver;
	void* g_thread_handle = nullptr;
	inline void* ps_loaded_module_list = 0;
	inline void* ps_initial_system_process = 0;
	UNICODE_STRING g_registryPath = { 0 };

	enum hide_type {
		NONE,
		PFN_EXISTS_BIT,
		SET_PARITY_ERROR,
		SET_LOCK_BIT,
		HIDE_TRANSLATION,
		HIDE_TEST
	};
}

struct table_cache {
	uint64_t base;      // physical address of this table
	uint64_t entries[512]; // all entries
	bool valid;
};
#define ENTRY_MASK 0x000FFFFFFFFFF000ULL
#define PAGE_PRESENT 0x1ULL
#define PAGE_LARGE 0x80ULL
struct Funcs
{
	NTSTATUS load() {
		UNICODE_STRING funcName;

		nt::ps_loaded_module_list = (void*)nt::g_resolver.get_export_address(oxorany("PsLoadedModuleList"));
		if (!nt::ps_loaded_module_list)
			return false;
		nt::ps_initial_system_process = (void*)nt::g_resolver.get_export_address(oxorany("PsInitialSystemProcess"));
		if (!nt::ps_initial_system_process)
			return false;

		DynPsCreateSystemThread = (NTSTATUS(*)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PKSTART_ROUTINE, PVOID))nt::g_resolver.get_system_routine(oxorany("PsCreateSystemThread"));
		if (!DynPsCreateSystemThread) return STATUS_UNSUCCESSFUL;

		DynKeDelayExecutionThread = (NTSTATUS(*)(KPROCESSOR_MODE, BOOLEAN, PLARGE_INTEGER))nt::g_resolver.get_system_routine(oxorany("KeDelayExecutionThread"));
		if (!DynKeDelayExecutionThread) return STATUS_UNSUCCESSFUL;

		DynPsTerminateSystemThread = (VOID(*)(NTSTATUS))nt::g_resolver.get_system_routine(oxorany("PsTerminateSystemThread"));
		if (!DynPsTerminateSystemThread) return STATUS_UNSUCCESSFUL;

		DynExReleaseResourceLite = (VOID(*)(PERESOURCE))nt::g_resolver.get_system_routine(oxorany("ExReleaseResourceLite"));
		if (!DynExReleaseResourceLite) return STATUS_UNSUCCESSFUL;

		DynRtlImageNtHeader = (decltype(DynRtlImageNtHeader))nt::g_resolver.get_system_routine(oxorany("RtlImageNtHeader"));
		if (!DynRtlImageNtHeader) {
			return STATUS_ENTRYPOINT_NOT_FOUND;
		}

		DynExAcquireResourceExclusiveLite = (BOOLEAN(*)(PERESOURCE, BOOLEAN))nt::g_resolver.get_system_routine(oxorany("ExAcquireResourceExclusiveLite"));
		if (!DynExAcquireResourceExclusiveLite) return STATUS_UNSUCCESSFUL;

		DynRtlInitAnsiString = (VOID(*)(PANSI_STRING, PCSZ))nt::g_resolver.get_system_routine(oxorany("RtlInitAnsiString"));
		if (!DynRtlInitAnsiString) return STATUS_UNSUCCESSFUL;

		DynRtlCompareString = (LONG(*)(PSTRING, PSTRING, BOOLEAN))nt::g_resolver.get_system_routine(oxorany("RtlCompareString"));
		if (!DynRtlCompareString) return STATUS_UNSUCCESSFUL;


		DynRtlCompareUnicodeString = (LONG(*)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN))nt::g_resolver.get_system_routine(oxorany("RtlCompareUnicodeString"));
		if (!DynRtlCompareUnicodeString) return STATUS_UNSUCCESSFUL;

		DynRtlLookupElementGenericTableAvl = (PVOID(*)(PRTL_AVL_TABLE, PVOID))nt::g_resolver.get_system_routine(oxorany("RtlLookupElementGenericTableAvl"));
		if (!DynRtlLookupElementGenericTableAvl) return STATUS_UNSUCCESSFUL;

		DynRtlDeleteElementGenericTableAvl = (BOOLEAN(*)(PRTL_AVL_TABLE, PVOID))nt::g_resolver.get_system_routine(oxorany("RtlDeleteElementGenericTableAvl"));
		if (!DynRtlDeleteElementGenericTableAvl) return STATUS_UNSUCCESSFUL;

		DynRtlEqualUnicodeString = (BOOLEAN(*)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN))nt::g_resolver.get_system_routine(oxorany("RtlEqualUnicodeString"));
		if (!DynRtlEqualUnicodeString) return STATUS_UNSUCCESSFUL;

		DynMmCopyMemory = (PVOID(*)(PVOID, MM_COPY_ADDRESS, SIZE_T, ULONG, PSIZE_T))nt::g_resolver.get_system_routine(oxorany("MmCopyMemory"));
		if (!DynMmCopyMemory) return STATUS_UNSUCCESSFUL;

		DynMmMapIoSpaceEx = (PVOID(*)(PHYSICAL_ADDRESS, SIZE_T, ULONG))nt::g_resolver.get_system_routine(oxorany("MmMapIoSpaceEx"));
		if (!DynMmMapIoSpaceEx) return STATUS_UNSUCCESSFUL;

		DynMmUnmapIoSpace = (VOID(*)(PVOID, SIZE_T))nt::g_resolver.get_system_routine(oxorany("MmUnmapIoSpace"));
		if (!DynMmUnmapIoSpace) return STATUS_UNSUCCESSFUL;

		DynIoCreateDevice = (NTSTATUS(*)(PDRIVER_OBJECT, ULONG, PUNICODE_STRING, DEVICE_TYPE, ULONG, BOOLEAN, PDEVICE_OBJECT*))nt::g_resolver.get_system_routine(oxorany("IoCreateDevice"));
		if (!DynIoCreateDevice) return STATUS_UNSUCCESSFUL;

		DynIoCreateSymbolicLink = (NTSTATUS(*)(PUNICODE_STRING, PUNICODE_STRING))nt::g_resolver.get_system_routine(oxorany("IoCreateSymbolicLink"));
		if (!DynIoCreateSymbolicLink) return STATUS_UNSUCCESSFUL;

		DynZwQuerySystemInformation = (decltype(DynZwQuerySystemInformation))nt::g_resolver.get_system_routine(oxorany("ZwQuerySystemInformation"));
		if (!DynZwQuerySystemInformation) {
			return STATUS_ENTRYPOINT_NOT_FOUND;
		}

		DynObCreateObject = (decltype(DynObCreateObject))nt::g_resolver.get_system_routine(oxorany("ObCreateObject"));

		if (!DynObCreateObject) {
			return STATUS_ENTRYPOINT_NOT_FOUND;
		}


		DynExAllocatePool = (PVOID(*)(POOL_TYPE, SIZE_T))nt::g_resolver.get_system_routine(oxorany("ExAllocatePool"));
		if (!DynExAllocatePool) return STATUS_UNSUCCESSFUL;

		DynPsLookupProcessByProcessId = (NTSTATUS(*)(HANDLE, PEPROCESS*))nt::g_resolver.get_system_routine(oxorany("PsLookupProcessByProcessId"));
		if (!DynPsLookupProcessByProcessId) return STATUS_UNSUCCESSFUL;

		DynPsGetProcessPeb = (PPEB(*)(PEPROCESS))nt::g_resolver.get_system_routine(oxorany("PsGetProcessPeb"));
		if (!DynPsGetProcessPeb) return STATUS_UNSUCCESSFUL;

		DynObInsertObject = (NTSTATUS(*)(PVOID, PACCESS_STATE, ACCESS_MASK, ULONG, PVOID*, PHANDLE))nt::g_resolver.get_system_routine(oxorany("ObInsertObject"));
		if (!DynObInsertObject) {
			return STATUS_UNSUCCESSFUL;  
		}

		DynZwClose = (NTSTATUS(*)(HANDLE))nt::g_resolver.get_system_routine(oxorany("ZwClose"));
		if (!DynZwClose) {
			return STATUS_UNSUCCESSFUL; 
		}

		DynZwCreateFile = (NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG))
			nt::g_resolver.get_system_routine(oxorany("ZwCreateFile"));

		if (!DynZwCreateFile) {
			return STATUS_UNSUCCESSFUL;
		}

		DynExAllocatePool2 = (PVOID(*)(POOL_FLAGS, SIZE_T, ULONG))nt::g_resolver.get_system_routine(oxorany("ExAllocatePool2"));
		if (!DynExAllocatePool2) return STATUS_UNSUCCESSFUL;

		DynObMakeTemporaryObject = (VOID(*)(PVOID))nt::g_resolver.get_system_routine(oxorany("ObMakeTemporaryObject"));
		if (!DynObMakeTemporaryObject) return STATUS_UNSUCCESSFUL;

		DynKeQuerySystemTimePrecise = (VOID(*)(PLARGE_INTEGER))nt::g_resolver.get_system_routine(oxorany("KeQuerySystemTimePrecise"));
		if (!DynObMakeTemporaryObject) return STATUS_UNSUCCESSFUL;

		DynObfDereferenceObject = (NTSTATUS(*)(PVOID))nt::g_resolver.get_system_routine(oxorany("ObfDereferenceObject"));
		if (!DynObfDereferenceObject) return STATUS_UNSUCCESSFUL;
		
		DynKeQueryUnbiasedInterruptTime = (NTSTATUS(*)())nt::g_resolver.get_system_routine(oxorany("KeQueryUnbiasedInterruptTime"));
		if (!DynKeQueryUnbiasedInterruptTime) return STATUS_UNSUCCESSFUL;

		DynRtlRandomEx = (ULONG(*)(PULONG))nt::g_resolver.get_system_routine(oxorany("RtlRandomEx"));
		if (!DynRtlRandomEx) return STATUS_UNSUCCESSFUL;

		DynPsGetProcessSectionBaseAddress = (PVOID(*)(PEPROCESS))nt::g_resolver.get_system_routine(oxorany("PsGetProcessSectionBaseAddress"));
		if (!DynPsGetProcessSectionBaseAddress) return STATUS_UNSUCCESSFUL;

		DynExReleaseResourceLite = (decltype(DynExReleaseResourceLite)) nt::g_resolver.get_system_routine(oxorany("ExReleaseResourceLite"));

		if (!DynExReleaseResourceLite) return STATUS_UNSUCCESSFUL;


		DynExAcquireResourceExclusiveLite = (decltype(DynExAcquireResourceExclusiveLite))
			nt::g_resolver.get_system_routine(oxorany("ExAcquireResourceExclusiveLite"));

		if (!DynExAcquireResourceExclusiveLite) return STATUS_UNSUCCESSFUL;

		DynRtlGetVersion = (NTSTATUS(*)(PRTL_OSVERSIONINFOW))nt::g_resolver.get_system_routine(oxorany("RtlGetVersion"));
		if (!DynRtlGetVersion) return STATUS_UNSUCCESSFUL;

		DynMmIsAddressValid = (BOOLEAN(*)(PVOID))nt::g_resolver.get_system_routine(oxorany("MmIsAddressValid"));
		if (!DynMmIsAddressValid) return STATUS_UNSUCCESSFUL;

		DynMmGetVirtualForPhysical = (PVOID(*)(PHYSICAL_ADDRESS))nt::g_resolver.get_system_routine(oxorany("MmGetVirtualForPhysical"));
		if (!DynMmGetVirtualForPhysical) return STATUS_UNSUCCESSFUL;

		DynIoGetCurrentProcess = (PEPROCESS(*)(VOID))nt::g_resolver.get_system_routine(oxorany("IoGetCurrentProcess"));
		if (!DynIoGetCurrentProcess) return STATUS_UNSUCCESSFUL;
	
		DynExFreePoolWithTag = (void(*)(PVOID, ULONG))nt::g_resolver.get_system_routine(oxorany("ExFreePoolWithTag"));
		if (!DynExFreePoolWithTag) return STATUS_UNSUCCESSFUL;

		DynExAllocatePoolWithTag = (PVOID(*)(POOL_TYPE, SIZE_T, ULONG))nt::g_resolver.get_system_routine(oxorany("ExAllocatePoolWithTag"));
		if (!DynExAllocatePoolWithTag) return STATUS_UNSUCCESSFUL;

		DynObDereferenceObject = (VOID(*)(PVOID))nt::g_resolver.get_system_routine(oxorany("ObDereferenceObject"));
		if (!DynObDereferenceObject) return STATUS_UNSUCCESSFUL;

		DynIoCompleteRequest = (VOID(*)(PIRP, CCHAR))nt::g_resolver.get_system_routine(oxorany("IoCompleteRequest"));
		if (!DynIoCompleteRequest) return STATUS_UNSUCCESSFUL;

			DynMmGetPhysicalMemoryRanges = (PPHYSICAL_MEMORY_RANGE(*)(VOID))nt::g_resolver.get_system_routine(oxorany("MmGetPhysicalMemoryRanges"));
	if (!DynMmGetPhysicalMemoryRanges) return STATUS_UNSUCCESSFUL;

	DynZwAllocateVirtualMemory = (decltype(DynZwAllocateVirtualMemory))nt::g_resolver.get_system_routine(oxorany("ZwAllocateVirtualMemory"));
	if (!DynZwAllocateVirtualMemory) return STATUS_UNSUCCESSFUL;

	DynZwProtectVirtualMemory = (decltype(DynZwProtectVirtualMemory))nt::g_resolver.get_system_routine(oxorany("ZwProtectVirtualMemory"));
	if (!DynZwProtectVirtualMemory) return STATUS_UNSUCCESSFUL;

	DynZwFreeVirtualMemory = (decltype(DynZwFreeVirtualMemory))nt::g_resolver.get_system_routine(oxorany("ZwFreeVirtualMemory"));
	if (!DynZwFreeVirtualMemory) return STATUS_UNSUCCESSFUL;

	DynObOpenObjectByPointer = (decltype(DynObOpenObjectByPointer))nt::g_resolver.get_system_routine(oxorany("ObOpenObjectByPointer"));
	if (!DynObOpenObjectByPointer) return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}

	INT32 winver() {
		RTL_OSVERSIONINFOW ver = { 0 };
		(DynRtlGetVersion)(&ver);
		switch (ver.dwBuildNumber)
		{
		case win_1803:
			return 0x0278;
			break;
		case win_1809:
			return 0x0278;
			break;
		case win_1903:
			return 0x0280;
			break;
		case win_1909:
			return 0x0280;
			break;
		case win_2004:
			return 0x0388;
			break;
		case win_20H2:
			return 0x0388;
			break;
		case win_21H1:
			return 0x0388;
			break;
		default:
			return 0x0388;
		}
	}

	UINT64 cr3(const PEPROCESS pProcess) {
		PUCHAR process = (PUCHAR)pProcess;
		ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
		if (process_dirbase == 0) {
			INT32 UserDirOffset = winver();
			ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
			return process_userdirbase;
		}
		return process_dirbase;
	}


	NTSTATUS read2(PVOID target_address, PVOID buffer, SIZE_T size) {
		if (!target_address || !buffer || size == 0) {
			return STATUS_INVALID_PARAMETER;
		}

		PHYSICAL_ADDRESS AddrToWrite = { 0 };
		AddrToWrite.QuadPart = (LONGLONG)(ULONG_PTR)target_address; // Proper casting

		PVOID pmapped_mem = DynMmMapIoSpaceEx(AddrToWrite, size, PAGE_READWRITE);
		if (!pmapped_mem) {
			return STATUS_UNSUCCESSFUL;
		}

		// Calculate how much we can safely copy (within page boundaries)
		ULONG_PTR physical_addr = (ULONG_PTR)target_address;
		SIZE_T page_offset = physical_addr & 0xFFF;
		SIZE_T bytes_available_in_page = PAGE_SIZE - page_offset;
		SIZE_T bytes_to_copy = utils.c_min(size, bytes_available_in_page);

		// Ensure we don't copy more than requested
		bytes_to_copy = utils.c_min(bytes_to_copy, size);

	
		utils.c_memcpy(buffer, pmapped_mem, bytes_to_copy);
				

		DynMmUnmapIoSpace(pmapped_mem, size);
		return STATUS_SUCCESS;
	}

	NTSTATUS read(PVOID target_address, PVOID buffer, SIZE_T size) {
		
		if ((ULONG64)target_address < 0x1000 || (ULONG64)target_address > 0x7FFFFFFFFFFF)
			return STATUS_INVALID_PARAMETER;

		MM_COPY_ADDRESS to_read = { 0 };
		to_read.PhysicalAddress.QuadPart = (LONGLONG)target_address;


		SIZE_T copiedBytes = 0;
		PVOID copyResult = 0;
	
		 copyResult = DynMmCopyMemory(buffer, to_read, size, MM_COPY_MEMORY_PHYSICAL, &copiedBytes);
	

		if (!copyResult || copiedBytes == 0)
			return STATUS_UNSUCCESSFUL;

		return (copiedBytes < size) ? STATUS_PARTIAL_COPY : STATUS_SUCCESS;

	}
	

	NTSTATUS write(PVOID target_address, PVOID buffer, SIZE_T size) {
		//if (!target_address || !buffer || size == 0 || !bytes_written)
		//	return STATUS_INVALID_PARAMETER;

		//PHYSICAL_ADDRESS addrToWrite = { 0 };
		//addrToWrite.QuadPart = reinterpret_cast<LONGLONG>(target_address);

		//PVOID mappedMem = DynMmMapIoSpaceEx(addrToWrite, size, PAGE_READWRITE);
		//if (!mappedMem)
		//	return STATUS_UNSUCCESSFUL;

		//// Ensure that memcpy succeeds before proceeding
		//utils.c_memcpy(mappedMem, buffer, size);

		//*bytes_written = size;

		//DynMmUnmapIoSpace(mappedMem, size);

		//return STATUS_SUCCESS;\
		f (!target_address || !buffer || size == 0 || !bytes_written)
	//	return STATUS_INVALID_PARAMETER;

		if ((ULONG64)target_address < 0x1000 || (ULONG64)target_address > 0x7FFFFFFFFFFF)
			return STATUS_INVALID_PARAMETER;

		PHYSICAL_ADDRESS addrToWrite = { 0 };
		addrToWrite.QuadPart = (LONGLONG)target_address;

		PVOID mappedMem = DynMmMapIoSpaceEx(addrToWrite, size, PAGE_READWRITE);
		if (!mappedMem)
			return STATUS_UNSUCCESSFUL;

		
		utils.c_memcpy(mappedMem, buffer, size);
		
	

		DynMmUnmapIoSpace(mappedMem, size);
		return STATUS_SUCCESS;
	}

	UINT64 cached(UINT64 address, cache* cached_entry) {
		if (!address) return 0;
		if (!cached_entry) return 0;


		if (cached_entry->Address == address) {
			return cached_entry->Value;
		}

		read(PVOID(address), &cached_entry->Value, sizeof(cached_entry->Value));
		cached_entry->Address = address;
		return cached_entry->Value;
	}

	//uint64_t linear(uint64_t directoryTableBase, uint64_t virtualAddress) {

	//	if (!directoryTableBase) return 0 ;
	//	if (!virtualAddress) return 0;

	//	directoryTableBase &= ~0xf;

	//	uint64_t pageOffset = virtualAddress & ((1ULL << 12) - 1);
	//	uint64_t pte = (virtualAddress >> 12) & 0x1ff;
	//	uint64_t pt = (virtualAddress >> 21) & 0x1ff;
	//	uint64_t pd = (virtualAddress >> 30) & 0x1ff;
	//	uint64_t pdp = (virtualAddress >> 39) & 0x1ff;

	//	uint64_t pdpe = cached(directoryTableBase + 8 * pdp, &cached_pml4e[pdp]);
	//	if ((pdpe & 1) == 0)
	//		return 0;

	//	uint64_t pde = 0;
	//	read(PVOID((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde));
	//	if ((pde & 1) == 0)
	//		return 0;

	//	if (pde & 0x80) {
	//		return (pde & PMASK) + (virtualAddress & ((1ULL << 30) - 1));
	//	}

	//	uint64_t pteAddr = 0;
	//	read(PVOID((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr));
	//	if ((pteAddr & 1) == 0)
	//		return 0;

	//	if (pteAddr & 0x80) {
	//		return (pteAddr & PMASK) + (virtualAddress & ((1ULL << 21) - 1));
	//	}

	//	uint64_t finalAddr = 0;
	//	read(PVOID((pteAddr & PMASK) + 8 * pte), &finalAddr, sizeof(finalAddr));
	//	finalAddr &= PMASK;

	//	if (finalAddr == 0)
	//		return 0;

	//	return finalAddr + pageOffset;
	//}

	bool fetch_table(uint64_t phys, table_cache& cache) {
		if (cache.valid && cache.base == phys)
			return true;

		if (!phys || phys < 0x1000)
			return false;

		// Ensure physical address is properly aligned
		if (phys & 0xFFF)
			return false;

		if (!read((PVOID)phys, cache.entries, sizeof(cache.entries)))
			return false;

		cache.base = phys;
		cache.valid = true;
		return true;
	}

	uint64_t linear(uint64_t dtb, uint64_t va) {
		if (!dtb || !va)
			return 0;

		dtb &= ~0xFULL;
		uint64_t offset = va & 0xFFF; // 12-bit offset

		// Extract table indices
		uint64_t pml4_idx = (va >> 39) & 0x1FF;
		uint64_t pdp_idx = (va >> 30) & 0x1FF;
		uint64_t pd_idx = (va >> 21) & 0x1FF;
		uint64_t pt_idx = (va >> 12) & 0x1FF;

		static table_cache pml4, pdpt, pd, pt;
		uint64_t entry;

		// PML4
		if (!fetch_table(dtb, pml4))
			return 0;

		entry = pml4.entries[pml4_idx];
		if (!(entry & PAGE_PRESENT))
			return 0;

		// PDPT
		if (!fetch_table((entry & ENTRY_MASK), pdpt))
			return 0;

		entry = pdpt.entries[pdp_idx];
		if (!(entry & PAGE_PRESENT))
			return 0;

		// Check for 1GB page
		if (entry & PAGE_LARGE)
			return (entry & ENTRY_MASK) + (va & 0x3FFFFFFF); // 1GB mask

		// PD
		if (!fetch_table((entry & ENTRY_MASK), pd))
			return 0;

		entry = pd.entries[pd_idx];
		if (!(entry & PAGE_PRESENT))
			return 0;

		// Check for 2MB page
		if (entry & PAGE_LARGE)
			return (entry & ENTRY_MASK) + (va & 0x1FFFFF); // 2MB mask

		// PT
		if (!fetch_table((entry & ENTRY_MASK), pt))
			return 0;

		entry = pt.entries[pt_idx];
		if (!(entry & PAGE_PRESENT))
			return 0;

		return (entry & ENTRY_MASK) + offset;
	}

	intptr_t pattern(void* module_handle, const char* section, const char* signature_value) {
		static auto in_range = [](auto x, auto a, auto b) { return (x >= a && x <= b); };
		static auto get_bits = [](auto x) { return (in_range((x & (~0x20)), 'A', 'F') ?
			((x & (~0x20)) - 'A' + 0xa) : (in_range(x, '0', '9') ? x - '0' : 0)); };
		static auto get_byte = [](auto x) { return (get_bits(x[0]) << 4 | get_bits(x[1])); };

		const auto dos_headers = reinterpret_cast<PIMAGE_DOS_HEADER>(module_handle);
		const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<uintptr_t>(module_handle) + dos_headers->e_lfanew);
		const auto section_headers = reinterpret_cast<PIMAGE_SECTION_HEADER>(nt_headers + 1);

		auto range_start = 0ui64;
		auto range_end = 0ui64;
		for (auto cur_section = section_headers;
			cur_section < section_headers + nt_headers->FileHeader.NumberOfSections;
			cur_section++) {
			if (utils.c_strcmp(reinterpret_cast<const char*>(cur_section->Name), section) == 0) {
				range_start = reinterpret_cast<uintptr_t>(module_handle) + cur_section->VirtualAddress;
				range_end = range_start + cur_section->Misc.VirtualSize;
			}
		}

		if (range_start == 0)
			return 0u;

		auto first_match = 0ui64;
		auto pat = signature_value;
		for (uintptr_t cur = range_start; cur < range_end; cur++) {
			if (*pat == '\0') {
				return first_match;
			}
			if (*(uint8_t*)pat == '\?' || *reinterpret_cast<uint8_t*>(cur) == get_byte(pat)) {
				if (!first_match)
					first_match = cur;

				if (!pat[2])
					return first_match;

				if (*(uint16_t*)pat == 16191 || *(uint8_t*)pat != '\?') {
					pat += 3;
				}
				else {
					pat += 2;
				}
			}
			else {
				pat = signature_value;
				first_match = 0;
			}
		}
		return 0u;
	}

	uintptr_t base() {
		const auto idtbase = *reinterpret_cast<uint64_t*>(__readgsqword(0x18) + 0x38);
		const auto descriptor_0 = *reinterpret_cast<uint64_t*>(idtbase);
		const auto descriptor_1 = *reinterpret_cast<uint64_t*>(idtbase + 8);
		const auto isr_base = ((descriptor_0 >> 32) & 0xFFFF0000) + (descriptor_0 & 0xFFFF) + (descriptor_1 << 32);
		auto align_base = isr_base & 0xFFFFFFFFFFFFF000;

		for (; ; align_base -= 0x1000) {
			for (auto* search_base = reinterpret_cast<uint8_t*>(align_base);
				search_base < reinterpret_cast<uint8_t*>(align_base) + 0xFF9;
				search_base++) {
				if (search_base[0] == 0x48 &&
					search_base[1] == 0x8D &&
					search_base[2] == 0x1D &&
					search_base[6] == 0xFF) {
					const auto relative_offset = *reinterpret_cast<int*>(&search_base[3]);
					const auto address = reinterpret_cast<uint64_t>(search_base + relative_offset + 7);
					if ((address & 0xFFF) == 0) {
						if (*reinterpret_cast<uint16_t*>(address) == 0x5A4D) {
							return address;
						}
					}
				}
			}
		}
	}

	uintptr_t database() {
		auto search = pattern(reinterpret_cast<void*>(base()), E(".text"), E("B9 ? ? ? ? 48 8B 05 ? ? ? ? 48 89 43 18")) + 5;
		auto resolved_base = search + *reinterpret_cast<int32_t*>(search + 3) + 7;
		mm_pfn_database = *reinterpret_cast<uintptr_t*>(resolved_base);
		return mm_pfn_database;
	}

	uint64_t dirbase() {
		PKPROCESS current_process = DynIoGetCurrentProcess();
		return (uint64_t)current_process->DirectoryTableBase & 0xFFFFFFFFFFFFF000;
	}

	void* phystovirt(uint64_t phys) {
		PHYSICAL_ADDRESS phys_addr = { .QuadPart = (int64_t)(phys) };
		return reinterpret_cast<void*>(DynMmGetVirtualForPhysical(phys_addr));
	}

	void pte() {
		cr33 system_cr3 = { .flags = dirbase() };
		uint64_t dirbase_phys = system_cr3.address_of_page_directory << 12;
		pt_entry_64* pt_entry = reinterpret_cast<pt_entry_64*>(phystovirt(dirbase_phys));
		for (uint64_t idx = 0; idx < 0x200; idx++) {
			if (pt_entry[idx].page_frame_number == system_cr3.address_of_page_directory) {
				pte_base = (idx + 0x1FFFE00ui64) << 39ui64;
				pde_base = (idx << 30ui64) + pte_base;
				ppe_base = (idx << 30ui64) + pte_base + (idx << 21ui64);
				pxe_base = (idx << 12ui64) + ppe_base;
				self_mapidx = idx;
				break;
			}
		}
	}



}; 
Funcs funcs;
