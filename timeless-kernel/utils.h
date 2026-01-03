#include "defs.h"
#include <climits>

struct Utils
{
    SIZE_T c_wcslen(PCWSTR str) {
        SIZE_T length = 0;
        while (str && *str++) {
            length++;
        }
        return length;
    }

    PWCHAR c_wcsrchr(PWCHAR str, WCHAR ch) {
        if (!str)
            return NULL;

        PWCHAR last_occurrence = NULL;
        for (PWCHAR current = str; *current; current++) {
            if (*current == ch) {
                last_occurrence = current;
            }
        }
        return last_occurrence;
    }



    VOID unicode_string(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
        if (!DestinationString) return;

        if (SourceString) {
            SIZE_T length = c_wcslen(SourceString) * sizeof(WCHAR);
            DestinationString->Buffer = (PWSTR)SourceString;
            DestinationString->Length = (USHORT)length;
            DestinationString->MaximumLength = (USHORT)(length + sizeof(WCHAR));
        }
        else {
            DestinationString->Buffer = NULL;
            DestinationString->Length = 0;
            DestinationString->MaximumLength = 0;
        }
    }
    std::int32_t strcmp(
        const char* string,
        const char* string_cmp
    ) {
        while (*string != '\0')
        {
            if (*string != *string_cmp)
                break;
            string++;
            string_cmp++;
        }
        return *string - *string_cmp;
    }

    VOID InitEmptyUnicodeString(PUNICODE_STRING UnicodeString) {
        if (!UnicodeString)
            return;

        UnicodeString->Length = 0;
        UnicodeString->MaximumLength = 0;
        UnicodeString->Buffer = NULL;
    }

    VOID CustomRtlCopyUnicodeString(PUNICODE_STRING DestinationString, const UNICODE_STRING* SourceString) {
        if (!DestinationString || !SourceString) return;

        if (SourceString->Buffer && SourceString->Length > 0) {
            SIZE_T length = SourceString->Length;

            if (DestinationString->MaximumLength < length) {
                // Allocate memory for the destination string buffer if it's too small
                if (DestinationString->Buffer != NULL) {
                    DynExFreePoolWithTag(DestinationString->Buffer, 0);  // Free any previously allocated memory
                }

                DestinationString->Buffer = (PWSTR)DynExAllocatePoolWithTag(NonPagedPool, length + sizeof(WCHAR), 'Strg');
                if (!DestinationString->Buffer) {
                    DestinationString->Length = 0;
                    DestinationString->MaximumLength = 0;
                    return; // Allocation failed, return early
                }

                DestinationString->MaximumLength = (USHORT)(length + sizeof(WCHAR));  // Including space for null terminator
            }

            // Copy the string data (including the null terminator)
            copy(DestinationString->Buffer, SourceString->Buffer, length);

            // Set the length of the destination string
            DestinationString->Length = (USHORT)length;
        }
        else {
            // Handle the case when the source string is NULL or empty
            DestinationString->Buffer = NULL;
            DestinationString->Length = 0;
            DestinationString->MaximumLength = 0;
        }
    }

    SIZE_T c_min(SIZE_T a, SIZE_T b) {
        return (a < b) ? a : b;
    }

    int c_strcmp(const char* str1, const char* str2) {
        while (*str1 && (*str1 == *str2)) {
            str1++;
            str2++;
        }
        return (unsigned char)*str1 - (unsigned char)*str2;
    }



    unsigned long strtoul(
        const char* str,
        char** endptr,
        int base
    ) {
        while (*str == ' ' || *str == '\t' || *str == '\n' || *str == '\r')
            str++;

        bool negative = false;
        if (*str == '-') {
            negative = true;
            str++;
        }
        else if (*str == '+') {
            str++;
        }

        if (base == 0) {
            if (*str == '0') {
                str++;
                if (*str == 'x' || *str == 'X') {
                    base = 16;
                    str++;
                }
                else {
                    base = 8;
                }
            }
            else {
                base = 10;
            }
        }
        else if (base == 16) {
            if (*str == '0' && (*(str + 1) == 'x' || *(str + 1) == 'X')) {
                str += 2;
            }
        }

        unsigned long result = 0;
        bool valid_digit_found = false;

        while (*str) {
            int digit;

            if (*str >= '0' && *str <= '9') {
                digit = *str - '0';
            }
            else if (*str >= 'a' && *str <= 'z') {
                digit = *str - 'a' + 10;
            }
            else if (*str >= 'A' && *str <= 'Z') {
                digit = *str - 'A' + 10;
            }
            else {
                break;
            }

            if (digit >= base) {
                break;
            }

            valid_digit_found = true;

            if (result > (ULONG_MAX - digit) / base) {
                result = ULONG_MAX;
                break;
            }

            result = result * base + digit;
            str++;
        }

        if (endptr) {
            *endptr = const_cast<char*>(valid_digit_found ? str : str - valid_digit_found);
        }

        return negative ? static_cast<unsigned long>(-static_cast<long>(result)) : result;
    }


    inline std::int32_t strnicmp(const char* s1, const char* s2, std::uint64_t count) {
        while (count-- && *s1 && *s2) {
            auto c1 = static_cast<std::uint8_t>(*s1);
            auto c2 = static_cast<std::uint8_t>(*s2);

            if (c1 >= 'A' && c1 <= 'Z')
                c1 += 'a' - 'A';
            if (c2 >= 'A' && c2 <= 'Z')
                c2 += 'a' - 'A';

            if (c1 != c2)
                return c1 - c2;

            ++s1;
            ++s2;
        }

        if (count == static_cast<std::uint64_t>(-1))
            return 0;

        return static_cast<std::uint8_t>(*s1) - static_cast<std::uint8_t>(*s2);
    }

    [[ nodiscard ]]
    size_t strlen(
        const char* str
    ) {
        const char* s;
        for (s = str; *s; ++s);
        return (s - str);
    }

    static inline void c_memcpy(void* dstp, const void* srcp, SIZE_T len) {
        if (!dstp || !srcp || len == 0)
            return;

        UCHAR* dst = (UCHAR*)dstp;
        const UCHAR* src = (const UCHAR*)srcp;

        for (SIZE_T i = 0; i < len; i++) {
            dst[i] = src[i];
        }
    }

    VOID copy(PVOID Destination, const PVOID Source, SIZE_T Length) {
        PUCHAR dest = (PUCHAR)Destination;
        PUCHAR src = (PUCHAR)Source;

        for (SIZE_T i = 0; i < Length; i++) {
            dest[i] = src[i];
        }
    }

    UNICODE_STRING concatenate(const wchar_t* str1, const wchar_t* str2) {
        UNICODE_STRING result = { 0 };

        if (!str1 || !str2) {
            return result;
        }

        size_t length1 = c_wcslen(str1);
        size_t length2 = c_wcslen(str2);
        size_t totalLength = length1 + length2;

        result.Buffer = (wchar_t*)DynExAllocatePool(NonPagedPool, (totalLength + 1) * sizeof(wchar_t));

        if (result.Buffer) {
            result.Length = (USHORT)(totalLength * sizeof(wchar_t));
            result.MaximumLength = (USHORT)((totalLength + 1) * sizeof(wchar_t));

            c_memcpy(result.Buffer, str1, length1 * sizeof(wchar_t));
            c_memcpy(result.Buffer + length1, str2, length2 * sizeof(wchar_t));

            result.Buffer[totalLength] = L'\0';
        }

        return result;
    }
}; 
Utils utils ;

