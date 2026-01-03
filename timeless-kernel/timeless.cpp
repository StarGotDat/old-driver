#include "cleaner.h"
#include <intrin.h>

struct Values
{
	intptr_t dirBase = 0;
};
Values values;

bool did_clean = false;

wchar_t* wcsncpy_kernel(wchar_t* dest, const wchar_t* src, size_t count)
{
	if (dest == nullptr || src == nullptr || count == 0)
		return dest;

	wchar_t* start = dest;

	while (count && (*dest++ = *src++) != L'\0')
		count--;

	if (count > 0)
	{
		while (--count)
			*dest++ = L'\0';
	}

	return start;
}

UNICODE_STRING ExtractDriverName(PUNICODE_STRING RegistryPath) {
	UNICODE_STRING driverName = { 0 };
	PWCHAR lastBackslash = utils.c_wcsrchr(RegistryPath->Buffer, L'\\');
	PWCHAR nameStart = lastBackslash ? lastBackslash + 1 : RegistryPath->Buffer;

	size_t len = utils.c_wcslen(nameStart);
	BOOLEAN hasOne = (len > 0 && nameStart[len - 1] == L'1');
	size_t allocLength = hasOne ? len - 1 : len;

	PWCHAR nameCopy = (PWCHAR)DynExAllocatePool2(
		POOL_FLAG_PAGED,
		(allocLength + 1) * sizeof(WCHAR),
		'DrvN'
	);

	if (!nameCopy) {
		return driverName;
	}

	wcsncpy_kernel(nameCopy, nameStart, allocLength);
	nameCopy[allocLength] = L'\0';

	utils.unicode_string(&driverName, nameCopy);
	return driverName;
}

struct Fecthing
{
	NTSTATUS base(PBASE_REQUEST x) {
		if (!x || !x->ProcessId)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS process = NULL;

		NTSTATUS status = DynPsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);
		if (!NT_SUCCESS(status) || !process) {
			return STATUS_UNSUCCESSFUL;
		}

		ULONGLONG image_base = (ULONGLONG)(DynPsGetProcessSectionBaseAddress)(process);
		if (image_base == 0) {
			DynObDereferenceObject(process);
			return STATUS_UNSUCCESSFUL;
		}

		if (x->Address) {
			utils.copy(x->Address, &image_base, sizeof(image_base));
		}

		DynObDereferenceObject(process);

		return STATUS_SUCCESS;
	}

	NTSTATUS Peb(PPEB_REQUEST x) {
		if (!x || !x->ProcessId)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS process = NULL;

		NTSTATUS status = DynPsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);
		if (!NT_SUCCESS(status) || !process) {
			return STATUS_UNSUCCESSFUL;
		}

		PVOID peb = DynPsGetProcessPeb(process);
		if (!peb) {
			DynObDereferenceObject(process);
			return STATUS_UNSUCCESSFUL;
		}

		if (x->Address) {
			utils.copy(x->Address, &peb, sizeof(peb));
		}

		DynObDereferenceObject(process);

		return STATUS_SUCCESS;
	}



	NTSTATUS Clean(PCLEAN_REQUEST x)
	{
		if (!did_clean)
		{
			UNICODE_STRING uni = { 0 };

			if (x->UseUsermode) {
				if (!x || !x->Vulnerable)
					return STATUS_INVALID_PARAMETER;

				CHAR* ansiBuf = x->Vulnerable;
				SIZE_T ansiLen = utils.strlen(ansiBuf);

				WCHAR* wideBuf = (WCHAR*)DynExAllocatePoolWithTag(
					NonPagedPool,
					(ansiLen + 1) * sizeof(WCHAR),
					'wide'
				);

				if (!wideBuf)
					return STATUS_INSUFFICIENT_RESOURCES;

				for (SIZE_T i = 0; i < ansiLen; i++) {
					wideBuf[i] = (WCHAR)(UCHAR)ansiBuf[i]; // ASCII → Unicode
				}
				wideBuf[ansiLen] = L'\0';

				uni.Buffer = wideBuf;
				uni.Length = (USHORT)(ansiLen * sizeof(WCHAR));
				uni.MaximumLength = (USHORT)((ansiLen + 1) * sizeof(WCHAR));
			}
			else {


				uni = ExtractDriverName(&nt::g_registryPath);

				if (!uni.Buffer)
					return STATUS_UNSUCCESSFUL;
			}

			//	cleaner::PrintWdFilterDriverList();

			cleaner::clearHashBucket(uni, false); // make sure ts working
			cleaner::CleanMmu(uni);
			//cleaner::CleanMmu(uni);

			// Free memory if we allocated it ourselves
			if (x->UseUsermode && uni.Buffer)
				DynExFreePoolWithTag(uni.Buffer, 'wide');
			else if (!x->UseUsermode && uni.Buffer)
				DynExFreePoolWithTag(uni.Buffer, 'DrvN'); // matches ExtractDriverName allocation

			DynExFreePoolWithTag(nt::g_registryPath.Buffer, 'RegP'); // matches ExtractDriverName allocation
			did_clean = true;
		}
		return STATUS_SUCCESS;
	}

};
Fecthing fetching;


void m_attach_process(PRKPROCESS process, PRKAPC_STATE state) {
	static std::uintptr_t fn_addr = 0;
	if (!fn_addr)
		fn_addr = nt::g_resolver.get_system_routine(oxorany("KeStackAttachProcess"));
	if (!fn_addr || !state)
		return;

	using fn_t = void(*)(PRKPROCESS, PRKAPC_STATE);
	reinterpret_cast<fn_t>(fn_addr)(process, state);
}

void m_detach_process(PRKAPC_STATE state) {
	static std::uintptr_t fn_addr = 0;
	if (!fn_addr || !state)
		fn_addr = nt::g_resolver.get_system_routine(oxorany("KeUnstackDetachProcess"));
	if (!fn_addr)
		return;

	using fn_t = void(*)(PRKAPC_STATE);
	reinterpret_cast<fn_t>(fn_addr)(state);
}

struct Memory
{
	NTSTATUS read(PREAD_REQUEST x) {
		if (!x || !x->ProcessId || !x->Address || !x->Buffer || x->Size == 0)
			return STATUS_INVALID_PARAMETER;

		NTSTATUS status = STATUS_SUCCESS;
		SIZE_T remaining = x->Size;
		UINT_PTR current_virtual = x->Address;
		UINT_PTR current_buffer = x->Buffer;
		ULONG64 dirBase = values.dirBase;
		PEPROCESS process = NULL;

		if (!dirBase) {
			status = DynPsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);
			if (!NT_SUCCESS(status) || !process)
				return STATUS_INVALID_PARAMETER;

			dirBase = funcs.cr3(process);
			if (!dirBase) {
				DynObDereferenceObject(process);
				return STATUS_UNSUCCESSFUL;
			}
		}

		while (remaining > 0) {
			INT64 physical_address = funcs.linear(dirBase, current_virtual);
			if (!physical_address || physical_address < 0x1000) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			SIZE_T page_offset = physical_address & 0xFFF;
			SIZE_T bytes_this_page = PAGE_SIZE - page_offset;
			SIZE_T to_read = utils.c_min(bytes_this_page, remaining);

			if (physical_address + to_read > physical_address) {
				status = funcs.read2((PVOID)physical_address, (PVOID)current_buffer, to_read);
				if (!NT_SUCCESS(status))
					break;
			}
			else {
				status = STATUS_INVALID_ADDRESS;
				break;
			}

			current_virtual += to_read;
			current_buffer += to_read;
			remaining -= to_read;
		}

		if (process) {
			DynObDereferenceObject(process);
		}

		return (remaining > 0) ? status : STATUS_SUCCESS;
	}

	NTSTATUS write(PWRITE_REQUEST x) {
		if (!x || !x->ProcessId || !x->Address || !x->Buffer || x->Size == 0)
			return STATUS_INVALID_PARAMETER;

		NTSTATUS status = STATUS_SUCCESS;
		SIZE_T remaining = x->Size;
		UINT_PTR current_virtual = x->Address;
		UINT_PTR current_buffer = x->Buffer;
		ULONG64 dirBase = values.dirBase;
		PEPROCESS process = NULL;

		if (!dirBase) {
			status = DynPsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);
			if (!NT_SUCCESS(status) || !process)
				return STATUS_INVALID_PARAMETER;

			dirBase = funcs.cr3(process);
			if (!dirBase) {
				DynObDereferenceObject(process);
				return STATUS_UNSUCCESSFUL;
			}
		}

		while (remaining > 0) {
			INT64 physical_address = funcs.linear(dirBase, current_virtual);
			if (!physical_address || physical_address < 0x1000) {
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			SIZE_T page_offset = physical_address & 0xFFF;
			SIZE_T bytes_this_page = PAGE_SIZE - page_offset;
			SIZE_T to_write = utils.c_min(bytes_this_page, remaining);

			if (physical_address + to_write > physical_address) {
				status = funcs.write((PVOID)physical_address, (PVOID)current_buffer, to_write);
				if (!NT_SUCCESS(status))
					break;
			}
			else {
				status = STATUS_INVALID_ADDRESS;
				break;
			}

			current_virtual += to_write;
			current_buffer += to_write;
			remaining -= to_write;
		}

		if (process) {
			DynObDereferenceObject(process);
		}

		return (remaining > 0) ? status : STATUS_SUCCESS;
	}

	NTSTATUS cr3(PCACHE_REQUEST x) {
		if (!pte_base) {
			funcs.pte();
		}
		if (!mm_pfn_database) {
			funcs.database();
		}

		auto mem_range_count = 0;
		auto mem_range = DynMmGetPhysicalMemoryRanges();

		auto cr3_ptebase = self_mapidx * 8 + pxe_base;

		for (mem_range_count = 0; mem_range_count < 200; ++mem_range_count) {
			if (mem_range[mem_range_count].BaseAddress.QuadPart == 0 &&
				mem_range[mem_range_count].NumberOfBytes.QuadPart == 0)
				break;

			auto start_pfn = mem_range[mem_range_count].BaseAddress.QuadPart >> 12;
			auto end_pfn = start_pfn + (mem_range[mem_range_count].NumberOfBytes.QuadPart >> 12);

			for (auto i = start_pfn; i < end_pfn; ++i) {
				auto cur_mmpfn = reinterpret_cast<_MMPFN*>(mm_pfn_database + 0x30 * i);

				if (!cur_mmpfn) {
					continue;
				}

				if (cur_mmpfn->flags && cur_mmpfn->flags != 1 && cur_mmpfn->pte_address == cr3_ptebase) {
					auto decrypted_eprocess = ((cur_mmpfn->flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;

					if (!DynMmIsAddressValid(reinterpret_cast<void*>(decrypted_eprocess))) {
						continue;
					}

					values.dirBase = i << 12;

					PEPROCESS process;
					NTSTATUS status = DynPsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);

					if (!NT_SUCCESS(status) || !process) {
						continue;
					}

					if (reinterpret_cast<PEPROCESS>(decrypted_eprocess) == process) {
						if (values.dirBase) {
							utils.copy((void*)x->Address, &values.dirBase, sizeof(values.dirBase));
							return STATUS_SUCCESS;
						}
						break;
					}
				}
			}
		}

		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS allocate(PALLOCATE_REQUEST x) {
		if (!x || !x->ProcessId || !x->RegionSize)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS process = NULL;
		NTSTATUS status = DynPsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);
		if (!NT_SUCCESS(status) || !process)
			return STATUS_UNSUCCESSFUL;

		KAPC_STATE apc;
		PVOID base = x->BaseAddress; // can be NULL
		SIZE_T size = x->RegionSize;

		m_attach_process(process, &apc);
		status = DynZwAllocateVirtualMemory(
			NtCurrentProcess(),
			&base,
			0,
			&size,
			x->AllocationType,
			x->Protect
		);
		m_detach_process(&apc);

		if (NT_SUCCESS(status))
			x->BaseAddress = base;

		DbgPrintEx(0, 0, "[ALLOC] ZwAllocateVirtualMemory returned: 0x%X, base: %p, size: %llu\n",
			status, base, size);

		DynObDereferenceObject(process);
		return status;
	}

	NTSTATUS protect(PPROTECT_REQUEST x) {
		if (!x || !x->ProcessId || !x->BaseAddress || !x->RegionSize)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS process = NULL;
		NTSTATUS status = DynPsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);
		if (!NT_SUCCESS(status) || !process)
			return STATUS_UNSUCCESSFUL;

		KAPC_STATE apc;
		PVOID base = x->BaseAddress;
		SIZE_T size = x->RegionSize;
		ULONG oldProtect = 0;

		m_attach_process(process, &apc);
		status = DynZwProtectVirtualMemory(
			NtCurrentProcess(),   // we're attached, operate on current process
			&base,                // will receive possibly-rounded/adjusted base
			&size,                // may be updated by kernel
			x->NewProtect,
			&oldProtect
		);
		m_detach_process(&apc);

		if (NT_SUCCESS(status)) {
			x->BaseAddress = base;
			x->RegionSize = size;
			x->OldProtect = oldProtect;
		}

		DynObDereferenceObject(process);
		return status;
	}

	NTSTATUS free(PFREE_REQUEST x) {
		if (!x || !x->ProcessId || !x->BaseAddress)
			return STATUS_INVALID_PARAMETER;

		PEPROCESS process = NULL;
		NTSTATUS status = DynPsLookupProcessByProcessId((HANDLE)x->ProcessId, &process);
		if (!NT_SUCCESS(status) || !process)
			return STATUS_UNSUCCESSFUL;

		KAPC_STATE apc;
		PVOID base = x->BaseAddress;
		SIZE_T size = x->RegionSize; // for MEM_RELEASE this is usually 0; for MEM_DECOMMIT supply size

		m_attach_process(process, &apc);
		status = DynZwFreeVirtualMemory(
			NtCurrentProcess(),
			&base,
			&size,
			x->FreeType
		);
		m_detach_process(&apc);

		if (NT_SUCCESS(status)) {
			x->BaseAddress = base;
			x->RegionSize = size;
		}

		DynObDereferenceObject(process);
		return status;
	}

};
Memory memory;

NTSTATUS controller(PDEVICE_OBJECT device_obj, PIRP irp) {
	NTSTATUS status = { };
	ULONG bytes = { };
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;

	switch (code)
	{
	case IOCTL_FETCH_BASE:
		if (size == sizeof(_BASE_REQUEST)) {
			PBASE_REQUEST req = (PBASE_REQUEST)(irp->AssociatedIrp.SystemBuffer);

			status = fetching.base(req);
			bytes = sizeof(_BASE_REQUEST);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
		break;
	case IOCTL_READ_MEMORY:
		if (size == sizeof(_READ_REQUEST)) {
			PREAD_REQUEST req = (PREAD_REQUEST)(irp->AssociatedIrp.SystemBuffer);

			status = memory.read(req);
			bytes = sizeof(_READ_REQUEST);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
		break;
	case IOCTL_WRITE_MEMORY:
		if (size == sizeof(_WRITE_REQUEST)) {
			PWRITE_REQUEST req = (PWRITE_REQUEST)(irp->AssociatedIrp.SystemBuffer);

			status = memory.write(req);
			bytes = sizeof(_WRITE_REQUEST);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
		break;
	case IOCTL_CACHE_CR3:
		if (size == sizeof(_CACHE_REQUEST)) {
			PCACHE_REQUEST req = (PCACHE_REQUEST)(irp->AssociatedIrp.SystemBuffer);

			status = memory.cr3(req);
			bytes = sizeof(_CACHE_REQUEST);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
		break;
	case IOCTL_CACHE_PEB:
		if (size == sizeof(_PEB_REQUEST)) {
			PPEB_REQUEST req = (PPEB_REQUEST)(irp->AssociatedIrp.SystemBuffer);

			status = fetching.Peb(req);
			bytes = sizeof(_PEB_REQUEST);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
		break;
	case IOCTL_CLEAN:
		if (size == sizeof(_CLEAN_REQUEST)) {
			PCLEAN_REQUEST req = (PCLEAN_REQUEST)(irp->AssociatedIrp.SystemBuffer);

			status = fetching.Clean(req);
			bytes = sizeof(_CLEAN_REQUEST);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
		break;
	case IOCTL_ALLOCATE_MEMORY:
		if (size == sizeof(_ALLOCATE_REQUEST)) {
			PALLOCATE_REQUEST req = (PALLOCATE_REQUEST)(irp->AssociatedIrp.SystemBuffer);

			status = memory.allocate(req);
			bytes = sizeof(_ALLOCATE_REQUEST);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
		break;
	case IOCTL_PROTECT_MEMORY:
		if (size == sizeof(_PROTECT_REQUEST)) {
			PPROTECT_REQUEST req = (PPROTECT_REQUEST)(irp->AssociatedIrp.SystemBuffer);

			status = memory.protect(req);
			bytes = sizeof(_PROTECT_REQUEST);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
		break;
	case IOCTL_FREE_MEMORY:
		if (size == sizeof(_FREE_REQUEST)) {
			PFREE_REQUEST req = (PFREE_REQUEST)(irp->AssociatedIrp.SystemBuffer);

			status = memory.free(req);
			bytes = sizeof(_FREE_REQUEST);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
		break;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes;
	DynIoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS unsupported(PDEVICE_OBJECT device_obj, PIRP irp) {
	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	DynIoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS handler(PDEVICE_OBJECT device_obj, PIRP irp) {
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);

	switch (stack->MajorFunction) {
	case IRP_MJ_CREATE:
		break;
	case IRP_MJ_CLOSE:
		break;
	default:
		break;
	}

	DynIoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}




NTSTATUS init(PDRIVER_OBJECT drv_obj, PUNICODE_STRING path) {
	NTSTATUS status = { };
	PDEVICE_OBJECT device_obj = { };


	auto device = utils.concatenate(E(L"\\Device\\"), DEVICE_MODULE);
	auto dos_device = utils.concatenate(E(L"\\DosDevices\\"), DEVICE_MODULE);

	status = DynIoCreateDevice(drv_obj, 0, &device, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj);

	if (!NT_SUCCESS(status))
		return status;

	status = DynIoCreateSymbolicLink(&dos_device, &device);

	if (!NT_SUCCESS(status))
		return status;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv_obj->MajorFunction[i] = &unsupported;

	device_obj->Flags |= DO_BUFFERED_IO;

	drv_obj->MajorFunction[IRP_MJ_CREATE] = &handler;
	drv_obj->MajorFunction[IRP_MJ_CLOSE] = &handler;
	drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &controller;

	device_obj->Flags &= ~DO_DEVICE_INITIALIZING;

	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	if (!nt::g_resolver.setup()) return STATUS_UNSUCCESSFUL;


	auto status1 = funcs.load();
	if (!NT_SUCCESS(status1)) {
		return status1;
	}

	nt::g_registryPath.Buffer = (PWCHAR)DynExAllocatePoolWithTag(
		PagedPool,
		RegistryPath->Length + sizeof(WCHAR),
		'RegP'
	);
	if (!nt::g_registryPath.Buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	nt::g_registryPath.Length = RegistryPath->Length;
	nt::g_registryPath.MaximumLength = RegistryPath->Length + sizeof(WCHAR);

	utils.copy(nt::g_registryPath.Buffer, RegistryPath->Buffer, RegistryPath->Length);
	nt::g_registryPath.Buffer[RegistryPath->Length / sizeof(WCHAR)] = L'\0';

	status1 = IoCreateDriver(init);


	return status1;
}



//NTSTATUS DriverEntry() {
//	if (!nt::g_resolver.setup()) return STATUS_UNSUCCESSFUL;
//
//
//	auto status1 = funcs.load();
//	if (!NT_SUCCESS(status1)) {
//		return status1;
//	}
//
//	status1 = IoCreateDriver(init);
//
//
//	return status1;
//}
