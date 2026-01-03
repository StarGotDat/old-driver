#include "funcs.h"

char tolower_kernel(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

static char* stristr(const char* str1, const char* str2) {
    const char* p1 = str1;
    const char* p2 = str2;
    const char* r = *p2 == 0 ? str1 : 0;
    while (*p1 != 0 && *p2 != 0)
    {
        if ((tolower_kernel)((unsigned char)*p1) == (tolower_kernel)((unsigned char)*p2))
        {
            if (r == 0)
            {
                r = p1;
            }
            p2++;
        }
        else
        {
            p2 = str2;
            if (r != 0)
            {
                p1 = r + 1;
            }
            if ((tolower_kernel)((unsigned char)*p1) == (tolower_kernel)((unsigned char)*p2))
            {
                r = p1;
                p2++;
            }
            else
            {
                r = 0;
            }
        }
        p1++;
    }
    return *p2 == 0 ? (char*)r : 0;
}

int wcscmp_kernel(const wchar_t* str1, const wchar_t* str2)
{
    while (*str1 && (*str1 == *str2))
    {
        str1++;
        str2++;
    }
    return *(const unsigned short*)str1 - *(const unsigned short*)str2;
}

int wcsicmp_kernel1(const wchar_t* str1, const wchar_t* str2)
{
    while (*str1 && *str2)
    {
        wchar_t c1 = *str1;
        wchar_t c2 = *str2;

        // Convert to lowercase if uppercase
        if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
        if (c2 >= L'A' && c2 <= L'Z') c2 += 32;

        if (c1 != c2)
            return (int)c1 - (int)c2;

        str1++;
        str2++;
    }

    // If one string is longer
    return (int)(*str1) - (int)(*str2);
}


wchar_t towupper_kernel(wchar_t wc)
{
    if (wc >= L'a' && wc <= L'z')
        return wc - (L'a' - L'A');
    return wc;
}


int _wcsicmp_kernel(const wchar_t* str1, const wchar_t* str2)
{
    wchar_t c1, c2;
    do {
        c1 = towupper_kernel(*str1++);
        c2 = towupper_kernel(*str2++);
    } while (c1 && (c1 == c2));
    return c1 - c2;
}

size_t wcslen_kernel(const wchar_t* str)
{
    const wchar_t* eos = str;
    while (*eos++);
    return (eos - str - 1);
}

wchar_t* wcsrchr_kernel(const wchar_t* str, wchar_t ch)
{
    const wchar_t* last = nullptr;
    while (*str)
    {
        if (*str == ch)
            last = str;
        str++;
    }
    return (wchar_t*)last;
}


size_t strlen_kernel(const char* str)
{
    const char* eos = str;
    while (*eos++);
    return (eos - str - 1);
}

int memcmp_kernel(const void* ptr1, const void* ptr2, size_t num)
{
    const unsigned char* p1 = (const unsigned char*)ptr1;
    const unsigned char* p2 = (const unsigned char*)ptr2;

    for (size_t i = 0; i < num; i++)
    {
        if (p1[i] != p2[i])
            return p1[i] - p2[i];
    }
    return 0;
}

PVOID
GetKernelModuleBase(
    CHAR* ModuleName
) {
    PVOID ModuleBase = NULL;

    ULONG size = NULL;
    NTSTATUS status = (DynZwQuerySystemInformation)(SystemModuleInformation, 0, 0, &size);
    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        return ModuleBase;
    }

    PSYSTEM_MODULE_INFORMATION Modules = (PSYSTEM_MODULE_INFORMATION)(DynExAllocatePool)(NonPagedPool, size);
    if (!Modules) {
        return ModuleBase;
    }

    if (!NT_SUCCESS(status = (DynZwQuerySystemInformation)(SystemModuleInformation, Modules, size, 0))) {
        (DynExFreePoolWithTag)(Modules, 0);
        return ModuleBase;
    }

    for (UINT i = 0; i < Modules->ulModuleCount; i++) {
        CHAR* CurrentModuleName = reinterpret_cast<CHAR*>(Modules->Modules[i].FullPathName);
        if (stristr(CurrentModuleName, ModuleName)) {
            ModuleBase = Modules->Modules[i].ImageBase;
            break;
        }
    }

    (DynExFreePoolWithTag)(Modules, 0);
    return ModuleBase;
}


PVOID GetKernelBase2() {
    PVOID KernelBase = NULL;

    ULONG size = NULL;
    NTSTATUS status = DynZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        return KernelBase;
    }

    PSYSTEM_MODULE_INFORMATION Modules = (PSYSTEM_MODULE_INFORMATION)DynExAllocatePool(NonPagedPool, size);
    if (!Modules) {
        return KernelBase;
    }

    if (!NT_SUCCESS(status = DynZwQuerySystemInformation(SystemModuleInformation, Modules, size, 0))) {
        (DynExFreePoolWithTag)(Modules, 0);
        return KernelBase;
    }

    if (Modules->ulModuleCount > 0) {
        KernelBase = Modules->Modules[0].ImageBase;
    }

    (DynExFreePoolWithTag)(Modules, 0);
    return KernelBase;
}



BOOL CheckMask(PCHAR Base, PCHAR Pattern, PCHAR Mask) {
    for (; *Mask; ++Base, ++Pattern, ++Mask) {
        if (*Mask == 'x' && *Base != *Pattern) {
            return FALSE;
        }
    }

    return TRUE;
}

PVOID FindPattern2( PCHAR Base,  DWORD Length,  PCHAR Pattern,  PCHAR Mask) {
    Length -= (DWORD)(strlen_kernel)(Mask);
    for (DWORD i = 0; i <= Length; ++i) {
        PVOID Addr = &Base[i];
        if (CheckMask((PCHAR)Addr, Pattern, Mask)) {
            return Addr;
        }
    }

    return 0;
}

PVOID FindPatternImage(PCHAR Base,PCHAR Pattern,PCHAR Mask) {
    PVOID Match = 0;

    PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
    PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);
    for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER Section = &Sections[i];
        if (*(PINT)Section->Name == 'EGAP' || memcmp_kernel(Section->Name, skCrypt(".text"), 5) == 0) {
            Match = FindPattern2(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);
            if (Match) {
                break;
            }
        }
    }

    return Match;
}

PVOID FindPatternImage(
    PCHAR Base,
    const char* SectionName,
    PCHAR Pattern,
    PCHAR Mask
)
{
    PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
    PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);

    for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) {
        PIMAGE_SECTION_HEADER Section = &Sections[i];
        
        // Compare section name (up to 8 chars, not null-terminated)
        if (utils.strnicmp((const char*)Section->Name, SectionName, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            return FindPattern2(
                Base + Section->VirtualAddress,
                Section->Misc.VirtualSize,
                Pattern,
                Mask
            );
        }
    }
    return NULL;
}


PVOID ResolveRelativeAddress(_In_ PVOID Instruction,_In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
{
    ULONG_PTR Instr = (ULONG_PTR)Instruction;
    LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
    PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

    return ResolvedAddr;
}

PERESOURCE
GetPsLoaded() {
	PCHAR base = (PCHAR)GetKernelBase2();


	ERESOURCE PsLoadedModuleResource;
	auto cPsLoadedModuleResource = reinterpret_cast<decltype(&PsLoadedModuleResource)>(nt::g_resolver.get_system_routine(oxorany("PsLoadedModuleResource")));

	return cPsLoadedModuleResource;
}

#define MM_UNLOADED_DRIVERS_SIZE 50

#define MmuPattern "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9"
#define MmuMask "xxx????xxx"

#define MmlPattern "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32"
#define MmlMask "xx????xxx"


PMM_UNLOADED_DRIVER
GetMmuAddress() {
    PCHAR base = (PCHAR)GetKernelBase2();

    char* pMmuPattern = _(MmuPattern);
    char* pMmuMask = _(MmuMask);

    PVOID MmUnloadedDriversInstr = FindPatternImage(base, pMmuPattern, pMmuMask);

    if (MmUnloadedDriversInstr == NULL)
        return { };

    return *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(MmUnloadedDriversInstr, 3, 7);
}

PULONG
GetMmlAddress() {
	PCHAR Base = (PCHAR)GetKernelBase2();

	char* pMmlPattern = _(MmlPattern);
	char* pMmlMask = _(MmlMask);

	PVOID mmlastunloadeddriverinst = FindPatternImage(Base, pMmlPattern, pMmlMask);

	if (mmlastunloadeddriverinst == NULL)
		return { };

	return (PULONG)ResolveRelativeAddress(mmlastunloadeddriverinst, 2, 6);
}

BOOL
VerifyMmu() {
	return (GetMmuAddress() != NULL && GetMmlAddress() != NULL);
}

BOOL
IsUnloadEmpty(
    PMM_UNLOADED_DRIVER Entry
) {
    if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
        return TRUE;

    return FALSE;
}

BOOL
IsMmuFilled() {
    for (ULONG Idx = 0; Idx < MM_UNLOADED_DRIVERS_SIZE; ++Idx) {
        PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Idx];
        if (IsUnloadEmpty(Entry))
            return FALSE;
    }
    return TRUE;
}


UCHAR
RandomNumber() {
    PVOID Base = GetKernelBase2();



    ULONG Seed = 1234765;
    ULONG Rand = DynRtlRandomEx(&Seed) % 100;

    UCHAR RandInt = 0;

    if (Rand >= 101 || Rand <= -1)
        RandInt = 72;

    return (UCHAR)(Rand);
}


#define BB_POOL_TAG 'Esk' // For Recognition


NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, int index = 0)
{
    ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
    if (ppFound == NULL || pattern == NULL || base == NULL)
        return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER;
    int cIndex = 0;
    for (ULONG_PTR i = 0; i < size - len; i++)
    {
        BOOLEAN found = TRUE;
        for (ULONG_PTR j = 0; j < len; j++)
        {
            if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
            {
                found = FALSE;
                break;
            }
        }

        if (found != FALSE && cIndex++ == index)
        {
            *ppFound = (PUCHAR)base + i;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;

PVOID GetKernelBase(OUT PULONG pSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    PRTL_PROCESS_MODULES pMods = NULL;
    PVOID checkPtr = NULL;
    UNICODE_STRING routineName;

    // Already found
    if (g_KernelBase != NULL)
    {
        if (pSize)
            *pSize = g_KernelSize;
        return g_KernelBase;
    }

   // RtlUnicodeStringInit(&routineName, _(L"NtOpenFile"));

    checkPtr = (PVOID)nt::g_resolver.get_system_routine(oxorany("NtOpenFile"));
    if (checkPtr == NULL)
        return NULL;

    // Protect from UserMode AV
    status = DynZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0)
    {
       // DbgPrint(_("Invalid SystemModuleInformation size"));
        return NULL;
    }

    pMods = (PRTL_PROCESS_MODULES)DynExAllocatePoolWithTag(NonPagedPool, bytes, BB_POOL_TAG);
    if (pMods) {
        RtlZeroMemory(pMods, bytes);
    }
    else {
     //   DbgPrint(_("pMods = NULL"));
        return NULL;
    }

    status = DynZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

    if (NT_SUCCESS(status))
    {
        PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

        for (ULONG i = 0; i < pMods->NumberOfModules; i++)
        {
            // System routine is inside module
            if (checkPtr >= pMod[i].ImageBase &&
                checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
            {
                g_KernelBase = pMod[i].ImageBase;
                g_KernelSize = pMod[i].ImageSize;
                if (pSize)
                    *pSize = g_KernelSize;
                break;
            }
        }
    }

    if (pMods)
       DynExFreePoolWithTag(pMods, BB_POOL_TAG);
    //log("g_KernelBase: %x", g_KernelBase);
    //log("g_KernelSize: %x", g_KernelSize);
    return g_KernelBase;
}

// PE parsing functions


NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base = nullptr)
{
    //ASSERT(ppFound != NULL);
    if (ppFound == NULL)
        return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER

    if (nullptr == base)
        base = GetKernelBase(&g_KernelSize);
    if (base == nullptr)
        return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;

    PIMAGE_NT_HEADERS64 pHdr = DynRtlImageNtHeader(base);
    if (!pHdr)
        return STATUS_ACCESS_DENIED; // STATUS_INVALID_IMAGE_FORMAT;

    //PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

    for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
    {
        //DbgPrint("section: %s\r\n", pSection->Name);
        ANSI_STRING s1, s2;
         DynRtlInitAnsiString(&s1, section);
        DynRtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
        if (DynRtlCompareString(&s1, &s2, TRUE) == 0)
        {
            PVOID ptr = NULL;
            NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
            if (NT_SUCCESS(status)) {
                *(PULONG64)ppFound = (ULONG_PTR)(ptr); //- (PUCHAR)base
                //DbgPrint("found\r\n");
                return status;
            }
            //we continue scanning because there can be multiple sections with the same name.
        }
    }

    return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;
}

UCHAR PiDDBLockPtr_sig_win10[] = "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24";

/* 22H2 */
UCHAR PiDDBLockPtr_sig_win11[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8";

UCHAR PiDDBCacheTablePtr_sig[] = "\x66\x03\xD2\x48\x8D\x0D";

extern "C" bool LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
    PVOID PiDDBLockPtr = nullptr, PiDDBCacheTablePtr = nullptr;

    if (NT_SUCCESS(BBScanSection(_("PAGE"), PiDDBLockPtr_sig_win10, 0, sizeof(PiDDBLockPtr_sig_win10) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
        /* Win10 Signature Captured */
        PiDDBLockPtr = PVOID((uintptr_t)PiDDBLockPtr + 28);
       // DbgPrint(_("Win10 Signature Found"));
    }
    else {
        /* Win10 Signature Failed */
        if (NT_SUCCESS(BBScanSection(_("PAGE"), PiDDBLockPtr_sig_win11, 0, sizeof(PiDDBLockPtr_sig_win11) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
            /* Win11 Signature Captured */
            PiDDBLockPtr = PVOID((uintptr_t)PiDDBLockPtr + 16);
          //  DbgPrint(_("Win11 Signature Found"));
        }
        else {
            /* Both Failed */
        //    DbgPrint(_("Could not find PiDDB for Win10 or Win11..."));
            return 1;
        }

    }

    if (!NT_SUCCESS(BBScanSection(_("PAGE"), PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBCacheTablePtr)))) {
      //  DbgPrint(_("Unable to find PiDDBCacheTablePtr sig"));
        return false;
    }

    PiDDBCacheTablePtr = PVOID((uintptr_t)PiDDBCacheTablePtr + 3);

    *lock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));
    *table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

    return true;
}



SIZE_T UnicodeToAnsi(PCUNICODE_STRING Src, CHAR* Dest, SIZE_T MaxLen)
{
    if (!Src || !Dest || MaxLen == 0)
        return 0;

    SIZE_T len = (Src->Length / sizeof(WCHAR));
    if (len >= MaxLen)
        len = MaxLen - 1;

    for (SIZE_T i = 0; i < len; i++) {
        // Naive cast; only works for ASCII/ANSI characters
        Dest[i] = (CHAR)Src->Buffer[i];
    }

    Dest[len] = '\0';
    return len;
}

namespace cleaner {

   
    ULONG GetTimeDateStampFromModule(PVOID ImageBase)
    {
        if (!ImageBase)
            return 0;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return 0;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return 0;

        return nt->FileHeader.TimeDateStamp;
    }

    VOID PrintWdFilterDriverList()
    {
        char* CIDLLString = E("WdFilter.sys");
        // DbgPrint("[clearHashBucket] Looking for ci.dll base");

        PVOID WdFilterBase = GetKernelModuleBase(CIDLLString);
        if (!WdFilterBase) {
          //  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
          //      "[Kernel] WdFilter.sys base not found.\n");
            return;
        }

        // Find RuntimeDriversList pattern
        PVOID RuntimeDriversListRef = FindPatternImage(
            (PCHAR)WdFilterBase,
            "PAGE",
            (PCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05",
            (PCHAR)"xxx????xx"
        );

        if (!RuntimeDriversListRef) {
           /// DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            //    "[Kernel] RuntimeDriversList pattern not found.\n");
            return;
        }

        uintptr_t RuntimeDriversList = (uintptr_t)ResolveRelativeAddress(RuntimeDriversListRef, 3, 7);
        if (!DynMmIsAddressValid((PVOID)RuntimeDriversList)) return;

        uintptr_t RuntimeDriversListHead = RuntimeDriversList - 0x8;
        LIST_ENTRY* ListHead = (LIST_ENTRY*)RuntimeDriversListHead;

        if (!DynMmIsAddressValid(ListHead)) return;

        LIST_ENTRY* Entry = ListHead->Flink;
     //   DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[Kernel] WdFilter driver list:\n");

        while (Entry != ListHead) {
            if (!DynMmIsAddressValid(Entry)) break;

            UNICODE_STRING* EntryName = (UNICODE_STRING*)((BYTE*)Entry + 0x10);
            if (!DynMmIsAddressValid(EntryName) || !DynMmIsAddressValid(EntryName->Buffer)) {
                Entry = Entry->Flink;
                continue;
            }

            // Print driver name
         //   DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
         //       " - %wZ\n", EntryName);

            Entry = Entry->Flink;
        }
    }


    typedef void(*MPFREEDRIVERINFOEX)(PVOID DriverInfo);

    BOOL ClearLoadedDriverFromListKernel(UNICODE_STRING DriverName)
    {
        char* CIDLLString = E("WdFilter.sys");
        // DbgPrint("[clearHashBucket] Looking for ci.dll base");

        PVOID WdFilterBase = GetKernelModuleBase(CIDLLString);
        if (!WdFilterBase) {
           // DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
         //       "[Kernel] WdFilter.sys base not found.\n");
            return FALSE;
        }

        // -------------------------------
        // Pattern scan: RuntimeDriversList
        // -------------------------------
        PVOID RuntimeDriversListRef = FindPatternImage(
            (PCHAR)WdFilterBase,
            "PAGE",
            (PCHAR)"\x48\x8B\x0D\x00\x00\x00\x00\xFF\x05",
            (PCHAR)skCrypt("xxx????xx")
        );
        if (!RuntimeDriversListRef) {
          ///  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
          //      "[Kernel] RuntimeDriversList pattern not found.\n");
            return FALSE;
        }

        PVOID RuntimeDriversCountRef = FindPatternImage(
            (PCHAR)WdFilterBase,
            "PAGE",
            (PCHAR)"\xFF\x05\x00\x00\x00\x00\x48\x39\x11",
            (PCHAR)skCrypt("xx????xxx")
        );
        if (!RuntimeDriversCountRef) {
          //  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
             //   "[Kernel] RuntimeDriversCount pattern not found.\n");
            return FALSE;
        }

        // -------------------------------
        // Pattern scan: MpFreeDriverInfoEx
        // -------------------------------
        PVOID MpFreeDriverInfoExRef = FindPatternImage(
            (PCHAR)WdFilterBase,
            "PAGE",
            (PCHAR)"\x89\x00\x08\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9",
            (PCHAR)skCrypt("x?xx???????????x")
        );

        if (!MpFreeDriverInfoExRef) {
            MpFreeDriverInfoExRef = FindPatternImage(
                (PCHAR)WdFilterBase,
                "PAGE",
                (PCHAR)"\x89\x00\x08\x00\x00\x00\xE8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xE9",
                (PCHAR)skCrypt("x?x???x???????????x")
            );
            if (!MpFreeDriverInfoExRef) {
               // DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
               //     "[Kernel] MpFreeDriverInfoEx pattern not found.\n");
                return FALSE;
            }

            MpFreeDriverInfoExRef = (PVOID)((uintptr_t)MpFreeDriverInfoExRef + 0x3);
        }

        MpFreeDriverInfoExRef = (PVOID)((uintptr_t)MpFreeDriverInfoExRef + 0x3);

        // -------------------------------
        // Resolve relative addresses
        // -------------------------------
        uintptr_t RuntimeDriversList = (uintptr_t)ResolveRelativeAddress(RuntimeDriversListRef, 3, 7);
        if (!DynMmIsAddressValid((PVOID)RuntimeDriversList)) {
           // DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
             //   "[Kernel] RuntimeDriversList resolved to invalid address.\n");
            return FALSE;
        }

        uintptr_t RuntimeDriversListHead = RuntimeDriversList - 0x8;

        uintptr_t RuntimeDriversCount = (uintptr_t)ResolveRelativeAddress(RuntimeDriversCountRef, 2, 6);
        if (!DynMmIsAddressValid((PVOID)RuntimeDriversCount)) {
          //  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
              //  "[Kernel] RuntimeDriversCount resolved to invalid address.\n");
            return FALSE;
        }

        uintptr_t RuntimeDriversArray = *(uintptr_t*)(RuntimeDriversCount + 0x8);
        if (!DynMmIsAddressValid((PVOID)RuntimeDriversArray)) {
           // DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
            //    "[Kernel] RuntimeDriversArray resolved to invalid address.\n");
            return FALSE;
        }

        uintptr_t MpFreeDriverInfoExAddr = (uintptr_t)ResolveRelativeAddress(MpFreeDriverInfoExRef, 1, 5);
        if (!DynMmIsAddressValid((PVOID)MpFreeDriverInfoExAddr)) {
           // DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
             //   "[Kernel] MpFreeDriverInfoEx resolved to invalid address.\n");
            return FALSE;
        }

        MPFREEDRIVERINFOEX MpFreeDriverInfoEx = (MPFREEDRIVERINFOEX)MpFreeDriverInfoExAddr;

        // -------------------------------
        // Traverse RuntimeDriversList
        // -------------------------------
        LIST_ENTRY* ListHead = (LIST_ENTRY*)RuntimeDriversListHead;
        if (!DynMmIsAddressValid(ListHead)) {
         //   DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
             //   "[Kernel] ListHead invalid.\n");
            return FALSE;
        }

        LIST_ENTRY* Entry = ListHead->Flink;

        while (Entry != ListHead) {
            if (!DynMmIsAddressValid(Entry)) break;

            UNICODE_STRING* EntryName = (UNICODE_STRING*)((BYTE*)Entry + 0x10);
            if (!DynMmIsAddressValid(EntryName) || !DynMmIsAddressValid(EntryName->Buffer)) {
               // DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
             //       "[Kernel] Invalid UNICODE_STRING in list entry.\n");
                Entry = Entry->Flink;
                continue;
            }


            UNICODE_STRING entryNameOnly = *EntryName;

            // Find last backslash
            PWSTR lastSlash = utils.c_wcsrchr(entryNameOnly.Buffer, L'\\');
            if (lastSlash) {
                entryNameOnly.Buffer = lastSlash + 1;
                entryNameOnly.Length = (USHORT)(utils.c_wcslen(entryNameOnly.Buffer) * sizeof(WCHAR));
            }


            if (DynRtlCompareUnicodeString(&entryNameOnly, &DriverName, TRUE) == 0) {
          
                // Unlink
                if (DynMmIsAddressValid(Entry->Blink) && DynMmIsAddressValid(Entry->Flink)) {
                    Entry->Blink->Flink = Entry->Flink;
                    Entry->Flink->Blink = Entry->Blink;
                }

                // Remove from array
                ULONG* Count = (ULONG*)RuntimeDriversCount;
                PVOID* Array = (PVOID*)RuntimeDriversArray;
                if (DynMmIsAddressValid(Count) && DynMmIsAddressValid(Array)) {
                    for (ULONG i = 0; i < *Count; i++) {
                        if (Array[i] == Entry) {
                            Array[i] = NULL;
                            break;
                        }
                    }
                    (*Count)--;
                }

                // Free driver info
                PVOID DriverInfo = (BYTE*)Entry - 0x20;
                if (DynMmIsAddressValid(DriverInfo)) {
                    USHORT Magic = *(USHORT*)DriverInfo;
                    if (Magic == 0xDA18 && MpFreeDriverInfoEx) {
                    //    __try {
                            MpFreeDriverInfoEx(DriverInfo);
                       // }
                       // __except (EXCEPTION_EXECUTE_HANDLER) {
                          //  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL,
                               // "[Kernel] Exception in MpFreeDriverInfoEx call.\n");
                      //  }
                    }
                }

              //  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
              //      "[WdFilter] Cleared driver %wZ\n", &DriverName);
                return TRUE;
            }

            Entry = Entry->Flink;
        }

      //  DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL,
       //     "[WdFilter] DID NOT CLEAR driver %wZ\n", &DriverName);
        return FALSE;
    }



    BOOL clearCache(UNICODE_STRING DriverName, ULONG timeDateStamp) {

      //  DbgPrint("[Cache] Called clearCache for %wZ, TimeDateStamp: 0x%X\n",
    //       &DriverName, timeDateStamp);

        PERESOURCE PiDDBLock;
        PRTL_AVL_TABLE PiDDBCacheTable;

        if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable)) {
       //     DbgPrint("[Cache] LocatePiDDB FAILED\n");
            return 1;
        }

    //    DbgPrint("[Cache] PiDDBLock: %p, PiDDBCacheTable: %p\n", PiDDBLock, PiDDBCacheTable);

        PiDDBCacheEntry lookupEntry = { };
        lookupEntry.DriverName = DriverName;
        lookupEntry.TimeDateStamp = timeDateStamp;

        DynExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
    //    DbgPrint("[Cache] Acquired PiDDBLock\n");

        auto pFoundEntry = (PiDDBCacheEntry*)DynRtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
    //    DbgPrint("[PiDDBCache] pFoundEntry: %p\n", pFoundEntry);

        if (!pFoundEntry) {
            DynExReleaseResourceLite(PiDDBLock);
       //   DbgPrint("[Cache] Entry not found, released PiDDBLock\n");
            return 1;
        }

     //   DbgPrint("[PiDDBCache] Entry found: %wZ, TimeDateStamp: 0x%X\n",
      //     &pFoundEntry->DriverName, pFoundEntry->TimeDateStamp);

       RemoveEntryList(&pFoundEntry->List);
      if (!DynRtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
      //    DbgPrint(_("RtlDeleteElementFromTableAVL Failed!"));
      //    DbgPrint("[Cache] RtlDeleteElementFromTableAVL Failed!)\n");

         return 1;
      }

        DynExReleaseResourceLite(PiDDBLock);
     //   DbgPrint("[Cache] Released PiDDBLock\n");

        return 0;
    }


    //BOOL clearCache(UNICODE_STRING DriverName, ULONG timeDateStamp) {

    //    DbgPrint(("calling cache fnuction"));

    //    PERESOURCE PiDDBLock; PRTL_AVL_TABLE PiDDBCacheTable;
    //    if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable)) {
    //        DbgPrint(("ClearCache Failed"));
    //        return 1;
    //    }
    //    else
    //    {
    //        DbgPrint(("Found PIDB"));

    //    }

    //    PiDDBCacheEntry lookupEntry = { };


    //    lookupEntry.DriverName = DriverName;
    //    lookupEntry.TimeDateStamp = timeDateStamp;

    //    DynExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
    //    auto pFoundEntry = (PiDDBCacheEntry*)DynRtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
    //    if (pFoundEntry == nullptr)
    //    {
    //        // release the ddb resource lock
    //        DynExReleaseResourceLite(PiDDBLock);
    //        DbgPrint(("ClearCache Failed (Not found)"));
    //        return 1;
    //    }
    //    else
    //    {
    //        DbgPrint(("not null balh blah"));

    //    }
    //    // first, unlink from the list
    //    //RemoveEntryList(&pFoundEntry->List);
    //    //// then delete the element from the avl table
    //    //if (!DynRtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry)) {
    //    //   DbgPrint(_("RtlDeleteElementFromTableAVL Failed!"));
    //    //    return 1;
    //    //}

    //    // release the ddb resource lock
    //    DynExReleaseResourceLite(PiDDBLock);

    //    DbgPrint(("chache cleared"));
    //    return 0;
    //}


    //BOOL
    //    CleanMmu(
    //        UNICODE_STRING DriverName
    //    ) {
    //    auto ps_loaded = GetPsLoaded();

    //    if (ps_loaded == NULL) {
    //     //   DbgPrint("[-] Failed to get ps_loaded resource");
    //        return 1;
    //    }

    //    DynExAcquireResourceExclusiveLite(ps_loaded, TRUE);

    //    BOOLEAN Modified = FALSE;
    //    BOOLEAN Filled = IsMmuFilled();

    // //   DbgPrint("[*] Scanning MM_UNLOADED_DRIVERS for: %wZ", &DriverName);

    //    for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
    //        PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];

    //        if (IsUnloadEmpty(Entry)) {
    //         //   DbgPrint("[*] [%02lu] <Empty>", Index);
    //            continue;
    //        }

    //       // DbgPrint("[*] [%02lu] Driver: %wZ | Time: %llu", Index, &Entry->Name, Entry->UnloadTime);

    //        if (Modified) {
    //            PMM_UNLOADED_DRIVER PrevEntry = &GetMmuAddress()[Index - 1];
    //            utils.copy(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));

    //            if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) {
    //                RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
    //              //  DbgPrint("[+] Cleared last entry after shifting");
    //            }
    //        }
    //        else if (DynRtlEqualUnicodeString(&DriverName, &Entry->Name, TRUE)) {

    //            clearCache(DriverName, Entry->UnloadTime);
    //            PVOID BufferPool = Entry->Name.Buffer;
    //            RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
    //            DynExFreePoolWithTag(BufferPool, 'TDmM');

    //            *GetMmlAddress() = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *GetMmlAddress()) - 1;
    //            Modified = TRUE;

    //          //  DbgPrint("[+] Cleared unloaded driver entry for: %wZ", &DriverName);
    //        }
    //    }

    //    if (Modified) {
    //        ULONG64 PreviousTime = 0;

    //        for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
    //            PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
    //            if (IsUnloadEmpty(Entry)) {
    //                continue;
    //            }

    //            if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) {
    //                ULONG64 oldTime = Entry->UnloadTime;
    //                Entry->UnloadTime = PreviousTime - RandomNumber();
    //             //   DbgPrint("[~] Time adjusted: %wZ | Old: %llu -> New: %llu",
    //                  //  &Entry->Name, oldTime, Entry->UnloadTime);
    //            }

    //            PreviousTime = Entry->UnloadTime;
    //        }

    //     //   DbgPrint("[*] Recursively cleaning MMU for consistency...");
    //        CleanMmu(DriverName);
    //    }

    //    DynExReleaseResourceLite(ps_loaded);

    //    if (!Modified) {
    //        //DbgPrint("[clearMMU] ERROR: No modifications were made to MMU list");
    //        return 1;
    //    }
    //    else {
    //      //  DbgPrint("[clearMMU] Sucesss: Modifications to MMU/MML were made and cleared");

    //        return 0;
    //    }
    //}


    VOID PrintLoadedModules()
    {
        ULONG size = 0;
        NTSTATUS status = DynZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &size);

        if (status != STATUS_INFO_LENGTH_MISMATCH)
            return;

        PSYSTEM_MODULE_INFORMATION modules = (PSYSTEM_MODULE_INFORMATION)DynExAllocatePoolWithTag(NonPagedPool, size, 'modp');
        if (!modules)
            return;

        status = DynZwQuerySystemInformation(SystemModuleInformation, modules, size, NULL);
        if (!NT_SUCCESS(status)) {
            DynExFreePoolWithTag(modules, 'modp');
            return;
        }

   //     DbgPrint("[LoadedModules] Current kernel modules:\n");
        for (ULONG i = 0; i < modules->ulModuleCount; i++) {
            CHAR* modName = (CHAR*)modules->Modules[i].FullPathName;
            PVOID base = modules->Modules[i].ImageBase;
            ULONG modSize = modules->Modules[i].ImageSize;

   //         DbgPrint("[LoadedModules] %s | Base: %p | Size: 0x%X\n", modName, base, modSize);
        }

        DynExFreePoolWithTag(modules, 'modp');
    }

    BOOL clearHashBucket(UNICODE_STRING DriverName, bool remove_sys) {
      //  DbgPrint("[clearHashBucket] Starting for driver: %wZ\n", &DriverName);

        char* CIDLLString = E("ci.dll");
        // DbgPrint("[clearHashBucket] Looking for ci.dll base");
        CONST PVOID CIDLLBase = GetKernelModuleBase(CIDLLString);

        if (!CIDLLBase) {
            // DbgPrint("[clearHashBucket] ERROR: Failed to find ci.dll base");
            return 1;
        }
        //  DbgPrint("[clearHashBucket] ci.dll base found at 0x%p", CIDLLBase);

        char* pKernelBucketHashPattern_21H1 = (KernelBucketHashPattern_21H1);
        char* pKernelBucketHashMask_21H1 = (KernelBucketHashMask_21H1);
        char* pKernelBucketHashPattern_22H2 = (KernelBucketHashPattern_22H2);
        char* pKernelBucketHashMask_22H2 = (KernelBucketHashMask_22H2);

        // DbgPrint("[clearHashBucket] Searching for 21H1 pattern...");
        PVOID SignatureAddress = FindPatternImage((PCHAR)CIDLLBase, pKernelBucketHashPattern_21H1, pKernelBucketHashMask_21H1);

        if (!SignatureAddress) {
            //  DbgPrint("[clearHashBucket] 21H1 pattern not found, trying 22H2...");
            SignatureAddress = FindPatternImage((PCHAR)CIDLLBase, pKernelBucketHashPattern_22H2, pKernelBucketHashMask_22H2);

            if (!SignatureAddress) {
                // DbgPrint("[clearHashBucket] ERROR: No signature patterns found");
                return 1;
            }
        }
        //    DbgPrint("[clearHashBucket] Signature found at 0x%p", SignatureAddress);

         //   DbgPrint("[clearHashBucket] Resolving relative address...");
        CONST ULONGLONG* g_KernelHashBucketList = (ULONGLONG*)ResolveRelativeAddress(SignatureAddress, 3, 7);
        if (!g_KernelHashBucketList) {
            //  DbgPrint("[clearHashBucket] ERROR: Failed to resolve relative address");
            return 1;
        }
        //   DbgPrint("[clearHashBucket] Hash bucket list at 0x%p (value: 0x%llx)",
              // g_KernelHashBucketList, *g_KernelHashBucketList);

        LARGE_INTEGER Time{};
        DynKeQuerySystemTimePrecise(&Time);
        //       DbgPrint("[clearHashBucket] System time: %llu\n", Time.QuadPart);

        WCHAR upperDriverName[64];
        size_t nameLen = min(DriverName.Length / sizeof(WCHAR), sizeof(upperDriverName) - 1);
        for (size_t i = 0; i < nameLen; i++) {
            upperDriverName[i] = towupper_kernel(DriverName.Buffer[i]);
        }
        upperDriverName[nameLen] = L'\0';

        if (remove_sys)
        {
            size_t len = wcslen_kernel(upperDriverName);
            if (len > 4 && _wcsicmp_kernel(upperDriverName + len - 4, L".SYS") == 0) {
                upperDriverName[len - 4] = L'\0'; // truncate the string
            }
        }


   //    DbgPrint("Normalized driver name: %ws\n", upperDriverName);
        BOOL Status = FALSE;
        for (ULONGLONG i = *g_KernelHashBucketList; i; i = *(ULONGLONG*)i) {
            CONST PWCHAR wsName = PWCH(i + 0x48);
            if (!wsName) continue;

            // Extract just the filename part
            PWCHAR filename = wcsrchr_kernel(wsName, L'\\');
            filename = filename ? filename + 1 : wsName;

            // Remove .sys extension if present
            size_t len = wcslen_kernel(filename);
            if (len > 4 && _wcsicmp_kernel(filename + len - 4, L".sys") == 0) {
                len -= 4;
            }

            // Compare normalized names
            WCHAR upperFilename[64];
            for (size_t j = 0; j < len && j < sizeof(upperFilename) - 1; j++) {
                upperFilename[j] = towupper_kernel(filename[j]);
            }
            upperFilename[len] = L'\0';

         //   DbgPrint("Comparing against: %ws (original: %ws)\n", upperFilename, filename);

            if (wcscmp_kernel(upperDriverName, upperFilename) == 0) {
              //  DbgPrint("MATCH FOUND! Modifying hashes at 0x%llx\n", i);
                PUCHAR Hash = PUCHAR(i + 0x18);
                for (UINT j = 0; j < 20; j++) {
                    Hash[j] = UCHAR(DynRtlRandomEx(&Time.LowPart) % 255);
                }
                Status = TRUE;
            }
        }

        if (!Status) {
       //     DbgPrint("[clearHashBucket] Operation FAILED for driver: %wZ\n", &DriverName);

            //DbgPrint("[clearHashBucket] ERROR: No matching driver found in buckets\n");
            return 1;
        }
  //      DbgPrint("[clearHashBucket] Operation completed successfull for driver: %wZ\n", &DriverName);
     //   DbgPrint("[clearHashBucket] Operation completed successfully\n");
        return 0;
    }



    BOOL CleanMmu(UNICODE_STRING DriverName)
    {
        auto ps_loaded = GetPsLoaded();
        if (!ps_loaded) {
          //  DbgPrint("[CleanMmu] Failed to acquire ps_loaded resource\n");
            return TRUE;
        }

        DynExAcquireResourceExclusiveLite(ps_loaded, TRUE);

        BOOLEAN Modified = FALSE;
        BOOLEAN Filled = IsMmuFilled();

        // Prepare driver name with .sys if needed
        UNICODE_STRING tempName = { 0 };
        WCHAR buffer[MAX_PATH] = { 0 };
        SIZE_T nameLen = DriverName.Length / sizeof(WCHAR);

        utils.copy(buffer, DriverName.Buffer, DriverName.Length);

        if (nameLen < MAX_PATH - 4) {
            if (!(nameLen >= 4 &&
                buffer[nameLen - 4] == L'.' &&
                buffer[nameLen - 3] == L's' &&
                buffer[nameLen - 2] == L'y' &&
                buffer[nameLen - 1] == L's')) {

                wcscat(buffer, L".sys");
            }
        }

        utils.unicode_string(&tempName, buffer);

    //    DbgPrint("[CleanMmu] Using driver name for comparison: %wZ\n", &tempName);

        // all mmu shi over there 

     
       
        // Original name for MMU cleaning
        UNICODE_STRING mmuName = DriverName;

        // Prepare separate name for loaded module / timestamp lookup
        UNICODE_STRING loadedName = { 0 };
        WCHAR buffer1[MAX_PATH] = { 0 };
        SIZE_T nameLen1 = DriverName.Length / sizeof(WCHAR);

        // Copy original driver name
        utils.copy(buffer1, DriverName.Buffer, DriverName.Length);

        // Append '1' if not already there
        if (nameLen1 < MAX_PATH - 5) { // reserve space for '1' + ".sys"
            if (buffer1[nameLen1 - 1] != L'1') {
                buffer1[nameLen1] = L'1';
                nameLen1++;
                buffer1[nameLen1] = L'\0';
            }

            // Append .sys if missing
            if (!(nameLen1 >= 4 &&
                buffer1[nameLen1 - 4] == L'.' &&
                buffer1[nameLen1 - 3] == L's' &&
                buffer1[nameLen1 - 2] == L'y' &&
                buffer1[nameLen1 - 1] == L's')) {

                wcscat(buffer1, L".sys");
            }
        }

        // Convert to UNICODE_STRING for loaded module operations
        utils.unicode_string(&loadedName, buffer1);

     //   DbgPrint("[CleanMmu] MMU driver name: %wZ\n", &mmuName);
     //  DbgPrint("[Module] Loaded module name: %wZ\n", &loadedName);

        // Convert to ANSI for GetKernelModuleBase / timeDateStamp
        CHAR moduleName[MAX_PATH] = { 0 };
        UnicodeToAnsi(&loadedName, moduleName, sizeof(moduleName));



    //    PrintLoadedModules();
        PVOID imageBase = GetKernelModuleBase(moduleName);
        ULONG timeDateStamp = 0;

        if (imageBase) {
            timeDateStamp = GetTimeDateStampFromModule(imageBase);
      //     DbgPrint("[Module] Found module %s at base %p, TimeDateStamp: 0x%X\n",
           //     moduleName, imageBase, timeDateStamp);


           if (timeDateStamp != 0)
              clearCache(loadedName, timeDateStamp);

        }
        else {
      //     DbgPrint("[CleanMmu] Could not find module %s\n", moduleName);
        }

        PVOID imageBase1 = GetKernelModuleBase(moduleName);
        ULONG timeDateStamp1 = 0;

        if (imageBase1) {
            timeDateStamp1 = GetTimeDateStampFromModule(imageBase1);
            //     DbgPrint("[Module] Found module %s at base %p, TimeDateStamp: 0x%X\n",
                 //     moduleName, imageBase, timeDateStamp);

            cleaner::ClearLoadedDriverFromListKernel(tempName);

            if (timeDateStamp1 != 0)
                clearCache(tempName, timeDateStamp1);

        }
        else {
            //     DbgPrint("[CleanMmu] Could not find module %s\n", moduleName);
        }

        // Iterate MMU and clear matching driver
        for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
            PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
            if (IsUnloadEmpty(Entry))
                continue;

      //      DbgPrint("[CleanMmu] Comparing %wZ with MMU entry: %wZ\n", &tempName, &Entry->Name);

            if (Modified) {
                PMM_UNLOADED_DRIVER PrevEntry = &GetMmuAddress()[Index - 1];
                utils.copy(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));
                if (Index == MM_UNLOADED_DRIVERS_SIZE - 1)
                    RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
            }
            else if (DynRtlEqualUnicodeString(&tempName, &Entry->Name, TRUE)) {

         

                PVOID BufferPool = Entry->Name.Buffer;
                RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
                DynExFreePoolWithTag(BufferPool, 'TDmM');

                *GetMmlAddress() = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *GetMmlAddress()) - 1;
                Modified = TRUE;

                //DbgPrint("[CleanMmu] Cleared unloaded driver entry for: %wZ\n", &tempName);
            }
        }

        // Adjust unload times if modified
        if (Modified) {
            ULONG64 PreviousTime = 0;

            for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
                PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
                if (IsUnloadEmpty(Entry))
                    continue;

                if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) {
                    Entry->UnloadTime = PreviousTime - RandomNumber();
                }

                PreviousTime = Entry->UnloadTime;
            }

            CleanMmu(DriverName); // recursive clean
        }

       

        DynExReleaseResourceLite(ps_loaded);

        if (!Modified)
         //   DbgPrint("[CleanMmu] No modifications were made to MMU list for: %wZ\n", &tempName);

        return !Modified;
    }

}

int ultow_kernel(unsigned int value, wchar_t* buffer, size_t bufferSize, int base = 10, bool negative = false)
{
    if (!buffer || bufferSize == 0 || base < 2 || base > 36)
        return 0;

    wchar_t* p = buffer;
    size_t index = 0;

    // Convert digits in reverse order
    do {
        if (index >= bufferSize - 1)
            break;

        unsigned int digit = value % base;
        p[index++] = (digit < 10) ? (L'0' + digit) : (L'A' + digit - 10);
        value /= base;
    } while (value > 0);

    if (negative && index < bufferSize - 1)
    {
        p[index++] = L'-';
    }

    // Reverse the string
    for (size_t i = 0; i < index / 2; i++)
    {
        wchar_t temp = p[i];
        p[i] = p[index - i - 1];
        p[index - i - 1] = temp;
    }

    p[index] = L'\0';
    return (int)index;

}

// Integer to wide string conversion
int itow_kernel(int value, wchar_t* buffer, size_t bufferSize)
{
    if (!buffer || bufferSize == 0)
        return 0;

    bool negative = false;
    if (value < 0)
    {
        negative = true;
        value = -value;
    }

    return ultow_kernel((unsigned int)value, buffer, bufferSize, 10, negative);
}

// Unsigned long to wide string conversion
int vswprintf_kernel(wchar_t* buffer, size_t count, const wchar_t* format, va_list args)
{
    if (!buffer || !format || count == 0)
        return -1;

    wchar_t* dest = buffer;
    const wchar_t* src = format;
    size_t remaining = count - 1; // Leave space for null terminator

    while (*src && remaining > 0)
    {
        if (*src != L'%')
        {
            *dest++ = *src++;
            remaining--;
            continue;
        }

        // Handle format specifiers
        src++; // Skip '%'
        if (!*src) break;

        switch (*src)
        {
        case L's':
        {
            const wchar_t* str = va_arg(args, const wchar_t*);
            if (!str) str = L"(null)";

            while (*str && remaining > 0)
            {
                *dest++ = *str++;
                remaining--;
            }
            break;
        }
        case L'd':
        {
            int num = va_arg(args, int);
            wchar_t numBuf[32];
            int len = itow_kernel(num, numBuf, ARRAYSIZE(numBuf));

            for (int i = 0; i < len && remaining > 0; i++)
            {
                *dest++ = numBuf[i];
                remaining--;
            }
            break;
        }
        case L'c':
        {
            wchar_t ch = (wchar_t)va_arg(args, int);
            if (remaining > 0)
            {
                *dest++ = ch;
                remaining--;
            }
            break;
        }
        case L'x':
        case L'X':
        {
            unsigned int num = va_arg(args, unsigned int);
            wchar_t numBuf[32];
            int len = ultow_kernel(num, numBuf, ARRAYSIZE(numBuf), 16);

            for (int i = 0; i < len && remaining > 0; i++)
            {
                *dest++ = numBuf[i];
                remaining--;
            }
            break;
        }
        default:
            // Unsupported format specifier - just copy it
            if (remaining > 0)
            {
                *dest++ = L'%';
                *dest++ = *src;
                remaining -= 2;
            }
            break;
        }
        src++;
    }

    // Null-terminate the buffer
    *dest = L'\0';

    return (int)(dest - buffer);
}

int swprintf_kernel(wchar_t* buffer, size_t count, const wchar_t* format, ...)
{
    if (!buffer || !format || count == 0)
        return -1;

    va_list args;
    va_start(args, format);
    int result = vswprintf_kernel(buffer, count, format, args);
    va_end(args);

    return result;
}

//POBJECT_TYPE GetIoDriverObjectType() {
//    UNICODE_STRING routineName;
//    utils.unicode_string(&routineName, L"IoDriverObjectType");
//    return *(POBJECT_TYPE*)DynMmGetSystemRoutineAddress(&routineName);
//}


NTSTATUS __fastcall IoCreateDriver(_In_ NTSTATUS(__fastcall* entry_point)(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING))
{
    auto timestamp = DynKeQueryUnbiasedInterruptTime();

    std::uint16_t name_buffer[100];
    auto pos = 0;

    constexpr std::uint16_t prefix[] = { '\\', 'D', 'r', 'i', 'v', 'e', 'r', '\\', 0 };
    for (auto p = prefix; *p != 0; ++p)
        name_buffer[pos++] = *p;

    for (auto i = 0; i < 8; ++i) {
        auto digit = (timestamp >> (28 - i * 4)) & 0xF;
        name_buffer[pos++] = digit < 10 ? (L'0' + digit) : (L'A' + digit - 10);
    }

    name_buffer[pos] = 0;

    UNICODE_STRING driver_name;

    utils.unicode_string(&driver_name, reinterpret_cast<std::uint16_t*>(name_buffer));
    if (!driver_name.Length)
        return STATUS_UNSUCCESSFUL;

    OBJECT_ATTRIBUTES obj_attrs;
  //  initialize_object_attributes(&obj_attrs, &driver_name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr);
    InitializeObjectAttributes(&obj_attrs, &driver_name, OBJ_PERMANENT | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    auto obj_size = sizeof(DRIVER_OBJECT) + sizeof(void*) * 10;
    auto IoDriverObjectType = *(void**)nt::g_resolver.get_export_address(oxorany("IoDriverObjectType"));

    void* driver_obj_ptr = nullptr;
    auto status = DynObCreateObject(0, (POBJECT_TYPE)IoDriverObjectType, &obj_attrs, 0, nullptr, obj_size, 0, 0, &driver_obj_ptr);
    if (status || !driver_obj_ptr)
        return status;

    auto driver_obj = static_cast<DRIVER_OBJECT*>(driver_obj_ptr);
    volatile auto ptr = reinterpret_cast<std::uint8_t*>(driver_obj);
    for (auto i = 0ull; i < obj_size; ++i)
        ptr[i] = 0;

    driver_obj->Type = 4;
    driver_obj->Size = sizeof(DRIVER_OBJECT);
    driver_obj->Flags = 2;

    driver_obj->DriverExtension = reinterpret_cast<PDRIVER_EXTENSION>(reinterpret_cast<std::uint8_t*>(driver_obj) + sizeof(DRIVER_OBJECT));
    if (!driver_obj->DriverExtension) {
        DynObMakeTemporaryObject(driver_obj);
        DynObfDereferenceObject(driver_obj);
        return STATUS_UNSUCCESSFUL;
    }

    volatile auto major_function = driver_obj->MajorFunction;
    for (auto i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
        major_function[i] = nullptr;

    status = entry_point(driver_obj, nullptr);
    DynObMakeTemporaryObject(driver_obj);
    DynObfDereferenceObject(driver_obj);

    return status;
}

//
//NTSTATUS __fastcall IoCreateDriver(_In_ NTSTATUS(__fastcall* EntryPoint)(_In_ PDRIVER_OBJECT, _In_ PUNICODE_STRING))
//{
//
//
//    HANDLE drv_handle = NULL;
//    USHORT name_length;
//    WCHAR name_buffer[100];
//    PDRIVER_OBJECT drv_obj = NULL;
//    OBJECT_ATTRIBUTES obj_attribs;
//    UNICODE_STRING local_drv_name;
//    UNICODE_STRING service_key_name;
//    NTSTATUS status = STATUS_SUCCESS;
//    ULONG obj_size = sizeof(DRIVER_OBJECT) + sizeof(EXTENDED_DRIVER_EXTENSION);
//
//    name_length = (USHORT)swprintf_kernel(
//        name_buffer,
//        ARRAYSIZE(name_buffer),  
//        E(L"\\Driver\\%08u"),       
//        (ULONG)DynKeQueryUnbiasedInterruptTime()  
//    );
//    local_drv_name.Length = name_length * sizeof(WCHAR);
//    local_drv_name.MaximumLength = local_drv_name.Length + sizeof(UNICODE_NULL);
//    local_drv_name.Buffer = name_buffer;
//
//    InitializeObjectAttributes(&obj_attribs, &local_drv_name, OBJ_PERMANENT | OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//
//   
//    auto IoDriverObjectType = *(void**)nt::g_resolver.get_export_address(oxorany("IoDriverObjectType"));
//
//    status = DynObCreateObject(KernelMode, (POBJECT_TYPE)IoDriverObjectType, &obj_attribs, KernelMode, NULL, obj_size, 0, 0, (PVOID*)&drv_obj);
//    if (!NT_SUCCESS(status))
//        return status;
//
//    RtlZeroMemory(drv_obj, obj_size);  // Cleaning up
//    drv_obj->Type = IO_TYPE_DRIVER;    // Specifying the driver type
//    drv_obj->Size = sizeof(DRIVER_OBJECT); // Setting its size
//    drv_obj->Flags = DRVO_BUILTIN_DRIVER; // Setting it as a BUILTIN_DRIVER					
//    drv_obj->DriverExtension = (PDRIVER_EXTENSION)(drv_obj + 1);  // Setting up the driver extension
//    drv_obj->DriverExtension->DriverObject = drv_obj; // Assigning the driver 
//    drv_obj->DriverInit = EntryPoint; // Setting the driver entry point
//
//    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
//    {
//        drv_obj->MajorFunction[i] = IopInvalidDeviceRequest;
//    }
//
//    service_key_name.MaximumLength = local_drv_name.Length + sizeof(UNICODE_NULL);
//    service_key_name.Buffer = (PWCH)DynExAllocatePool2(POOL_FLAG_PAGED, local_drv_name.MaximumLength, (ULONG)DynKeQueryUnbiasedInterruptTime());
//    if (!service_key_name.Buffer)
//    {
//        DynObMakeTemporaryObject(drv_obj);
//        DynObfDereferenceObject(drv_obj);
//        return STATUS_INSUFFICIENT_RESOURCES;
//    }
//
//    utils.CustomRtlCopyUnicodeString(&service_key_name, &local_drv_name);
//    service_key_name.Buffer[service_key_name.Length / sizeof(WCHAR)] = UNICODE_NULL;
//    drv_obj->DriverExtension->ServiceKeyName = service_key_name;
//
//    drv_obj->DriverName.MaximumLength = local_drv_name.Length;
//    drv_obj->DriverName.Buffer = (PWCH)DynExAllocatePool2(POOL_FLAG_PAGED, drv_obj->DriverName.MaximumLength, (ULONG)DynKeQueryUnbiasedInterruptTime());
//    if (!drv_obj->DriverName.Buffer)
//    {
//        DynExFreePoolWithTag(service_key_name.Buffer, 0);  // Free service key name memory
//        DynObMakeTemporaryObject(drv_obj);
//        DynObfDereferenceObject(drv_obj);
//        return STATUS_INSUFFICIENT_RESOURCES;
//    }
//
//    utils.CustomRtlCopyUnicodeString(&drv_obj->DriverName, &local_drv_name);
//
//    status = DynObInsertObject(drv_obj, NULL, FILE_READ_DATA, 0, NULL, &drv_handle);
//    DynZwClose(drv_handle);
//    if (!NT_SUCCESS(status))
//    {
//        DynExFreePoolWithTag(service_key_name.Buffer, 0);  // Free service key name memory
//        DynExFreePoolWithTag(drv_obj->DriverName.Buffer, 0);  // Free driver name memory
//        DynObMakeTemporaryObject(drv_obj);
//        DynObfDereferenceObject(drv_obj);
//        return status;
//    }
//
//    status = EntryPoint(drv_obj, NULL);
//    if (!NT_SUCCESS(status))
//    {
//        DynExFreePoolWithTag(service_key_name.Buffer, 0);  // Free service key name memory
//        DynExFreePoolWithTag(drv_obj->DriverName.Buffer, 0);  // Free driver name memory
//        DynObMakeTemporaryObject(drv_obj);
//        DynObDereferenceObject(drv_obj);
//        return status;
//    }
//
//    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
//    {
//        if (!drv_obj->MajorFunction[i])
//        {
//            drv_obj->MajorFunction[i] = IopInvalidDeviceRequest;
//        }
//    }
//
//
//
//
//    DynExFreePoolWithTag(service_key_name.Buffer, 0);
//    DynExFreePoolWithTag(drv_obj->DriverName.Buffer, 0);
//
//    drv_obj->DriverSection = 0;
//    drv_obj->DriverName.Length = 0;
//
//    DynObDereferenceObject(drv_obj);
//
//    return status;
//}
