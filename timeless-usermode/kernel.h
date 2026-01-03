#pragma once

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <string>
#include <iostream>
#include <chrono>

typedef LONG NTSTATUS;

#define IOCTL_FETCH_BASE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x754, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_WRITE_MEMORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x315, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_READ_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x634, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CACHE_CR3       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x143, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CACHE_PEB       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x453, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CLEAN     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x753, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ALLOCATE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x854, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_PROTECT_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x955, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_FREE_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA56, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)



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


extern "C" __int64 request(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    std::uint32_t IoControlCode,
    PVOID InputBuffer,
    std::uint32_t InputBufferLength,
    PVOID OutputBuffer,
    std::uint32_t OutputBufferLength);

class kernel {

public:

     HANDLE g_driver_handle = INVALID_HANDLE_VALUE;
     INT32 g_process_id = 0;
     uintptr_t g_process_base;
     uintptr_t g_process_cr3;


    inline bool connect_driver() {
     
        g_driver_handle = CreateFileA(
            ("\\\\.\\*Udahhdrivetwan*"),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        return g_driver_handle != INVALID_HANDLE_VALUE;
    }

 

    inline bool read_physical(PVOID address, PVOID buffer, DWORD size) {
        IO_STATUS_BLOCK status_block = {};
        READ_REQUEST req = {
            .ProcessId = g_process_id,
            .Address = reinterpret_cast<UINT_PTR>(address),
            .Buffer = reinterpret_cast<UINT_PTR>(buffer),
            .Size = size
        };

        return request(g_driver_handle, nullptr, nullptr, nullptr, &status_block,
            IOCTL_READ_MEMORY, &req, sizeof(req), &req, sizeof(req));
    }

    inline bool write_physical(PVOID address, PVOID buffer, DWORD size) {
        IO_STATUS_BLOCK status_block = {};
        WRITE_REQUEST req = {
             .ProcessId = g_process_id,
            .Address = reinterpret_cast<UINT_PTR>(address),
            .Buffer = reinterpret_cast<UINT_PTR>(buffer),
            .Size = size
        };

        return request(g_driver_handle, nullptr, nullptr, nullptr, &status_block,
            IOCTL_WRITE_MEMORY, &req, sizeof(req), &req, sizeof(req));
    }

    inline bool clean(const char* driverName, bool useUsermode = false) {
        IO_STATUS_BLOCK status_block = {};

        CLEAN_REQUEST req = {};
        req.UseUsermode = useUsermode;
        if (driverName) {
            strncpy_s(req.Vulnerable, MAX_STRING_LEN, driverName, _TRUNCATE);
        }

        return request(
            g_driver_handle,
            nullptr, nullptr, nullptr,
            &status_block,
            IOCTL_CLEAN,
            &req, sizeof(req),
            &req, sizeof(req)
        );
    }


    inline uintptr_t get_base_address() {
        IO_STATUS_BLOCK status_block = {};
        uintptr_t image_address = 0;
        BASE_REQUEST req = {
            .ProcessId = g_process_id,
            .Address = reinterpret_cast<UINT_PTR*>(&image_address)
        };

        request(g_driver_handle, nullptr, nullptr, nullptr, &status_block,
            IOCTL_FETCH_BASE, &req, sizeof(req), &req, sizeof(req));

        return image_address;
    }

    inline uintptr_t get_cr3() {
        IO_STATUS_BLOCK status_block = {};
        uintptr_t cr3_address = 0;
        CACHE_REQUEST req = {
            .ProcessId = g_process_id,
            .Address = reinterpret_cast<UINT_PTR*>(&cr3_address)
        };

        request(g_driver_handle, nullptr, nullptr, nullptr, &status_block,
            IOCTL_CACHE_CR3, &req, sizeof(req), &req, sizeof(req));

        return cr3_address;
    }

    INT32 get_process_id(LPCTSTR process_name) {
        PROCESSENTRY32 pt;
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pt.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hsnap, &pt)) {
            do {
                if (!lstrcmpi(pt.szExeFile, process_name)) {
                    CloseHandle(hsnap);
                    g_process_id = pt.th32ProcessID;
                    return pt.th32ProcessID;
                }
            } while (Process32Next(hsnap, &pt));
        }
        CloseHandle(hsnap);
        return { NULL };
    }

    template <typename T>
    inline T read(uintptr_t address) {
        T buffer{};
        read_physical(reinterpret_cast<PVOID>(address), &buffer, sizeof(T));
        return buffer;
    }

    template <typename T>
    inline void write(uintptr_t address, const T& data) {
        write_physical(reinterpret_cast<PVOID>(address), const_cast<T*>(&data), sizeof(T));
    }

    void test_rpm_call_sec(uint64_t addr) {
        std::printf("===== TEST 1: Number of rpm calls in 1 second =====\n");

        uint64_t call_count = 0;
        auto start = std::chrono::high_resolution_clock::now();
        auto end = start + std::chrono::seconds(1);

        while (std::chrono::high_resolution_clock::now() < end) {
            auto value = read<uint64_t>(addr);
              
            call_count++;
        }

        auto actual_duration = std::chrono::high_resolution_clock::now() - start;
        double seconds = std::chrono::duration<double>(actual_duration).count();

        std::printf("Completed %llu calls in %.6f seconds\n", call_count, seconds);
        std::printf("Rate: %.2f calls per second\n",

            static_cast<double>(call_count) / seconds);
    }

    inline bool allocate_virtual_memory(PVOID* baseAddress, SIZE_T regionSize, ULONG allocationType, ULONG protect) {
        IO_STATUS_BLOCK status_block = {};
        ALLOCATE_REQUEST req = {
            .ProcessId = g_process_id,
            .BaseAddress = baseAddress ? *baseAddress : nullptr,
            .RegionSize = regionSize,
            .AllocationType = allocationType,
            .Protect = protect
        };

        bool result = request(g_driver_handle, nullptr, nullptr, nullptr, &status_block,
            IOCTL_ALLOCATE_MEMORY, &req, sizeof(req), &req, sizeof(req));

        if (result && baseAddress) {
            *baseAddress = req.BaseAddress;
        }

        return result && NT_SUCCESS(status_block.Status);
    }

    inline bool protect_virtual_memory(PVOID* baseAddress, SIZE_T regionSize, ULONG newProtect, ULONG* oldProtect) {
        IO_STATUS_BLOCK status_block = {};
        PROTECT_REQUEST req = {
            .ProcessId = g_process_id,
            .BaseAddress = baseAddress ? *baseAddress : nullptr,
            .RegionSize = regionSize,
            .NewProtect = newProtect,
            .OldProtect = 0
        };

        bool result = request(g_driver_handle, nullptr, nullptr, nullptr, &status_block,
            IOCTL_PROTECT_MEMORY, &req, sizeof(req), &req, sizeof(req));

        if (result) {
            if (baseAddress) *baseAddress = req.BaseAddress;
            if (oldProtect) *oldProtect = req.OldProtect;
        }

        return result && NT_SUCCESS(status_block.Status);
    }

    inline bool free_virtual_memory(PVOID* baseAddress, SIZE_T regionSize, ULONG freeType) {
        IO_STATUS_BLOCK status_block = {};
        FREE_REQUEST req = {
            .ProcessId = g_process_id,
            .BaseAddress = baseAddress ? *baseAddress : nullptr,
            .RegionSize = regionSize,
            .FreeType = freeType
        };

        bool result = request(g_driver_handle, nullptr, nullptr, nullptr, &status_block,
            IOCTL_FREE_MEMORY, &req, sizeof(req), &req, sizeof(req));

        if (result && baseAddress) {
            *baseAddress = req.BaseAddress;
        }

        return result && NT_SUCCESS(status_block.Status);
    }
};



inline const auto Kernel = std::make_unique<kernel>();

