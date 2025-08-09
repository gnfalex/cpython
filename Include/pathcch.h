#ifndef CUSTOM_PATCHCCH
#define CUSTOM_PATCHCCH 1
#include <stdarg.h>
#include <string.h>
#include <windows.h>

//#include "windef.h"
//#include "winbase.h"
//#include "strsafe.h"
//#include "shlwapi.h"
//#include "wininet.h"
//#include "intshcut.h"
//#include "winternl.h"

#define PATHCCH_NONE                            0x00
#define PATHCCH_ALLOW_LONG_PATHS                0x01
#define PATHCCH_FORCE_ENABLE_LONG_NAME_PROCESS  0x02
#define PATHCCH_FORCE_DISABLE_LONG_NAME_PROCESS 0x04
#define PATHCCH_DO_NOT_NORMALIZE_SEGMENTS       0x08
#define PATHCCH_ENSURE_IS_EXTENDED_LENGTH_PATH  0x10
#define PATHCCH_ENSURE_TRAILING_SLASH           0x20

#define PATHCCH_MAX_CCH 0x8000

#define STRSAFE_E_INSUFFICIENT_BUFFER   ((HRESULT)0x8007007AL)

#define heap_alloc malloc

HRESULT  PathAllocCanonicalize(const WCHAR *path_in, DWORD flags, WCHAR **path_out);
HRESULT  PathAllocCombine(const WCHAR *path1, const WCHAR *path2, DWORD flags, WCHAR **out);
HRESULT  PathCchAddBackslash(WCHAR *path, SIZE_T size);
HRESULT  PathCchAddBackslashEx(WCHAR *path, SIZE_T size, WCHAR **end, SIZE_T *remaining);
HRESULT  PathCchAddExtension(WCHAR *path, SIZE_T size, const WCHAR *extension);
HRESULT  PathCchAppend(WCHAR *path1, SIZE_T size, const WCHAR *path2);
HRESULT  PathCchAppendEx(WCHAR *path1, SIZE_T size, const WCHAR *path2, DWORD flags);
HRESULT  PathCchCanonicalize(WCHAR *out, SIZE_T size, const WCHAR *in);
HRESULT  PathCchCanonicalizeEx(WCHAR *out, SIZE_T size, const WCHAR *in, DWORD flags);
HRESULT  PathCchCombine(WCHAR *out, SIZE_T size, const WCHAR *path1, const WCHAR *path2);
HRESULT  PathCchCombineEx(WCHAR *out, SIZE_T size, const WCHAR *path1, const WCHAR *path2, DWORD flags);
HRESULT  PathCchFindExtension(const WCHAR *path, SIZE_T size, const WCHAR **extension);
BOOL     PathCchIsRoot(const WCHAR *path);
HRESULT  PathCchRemoveBackslash(WCHAR *path, SIZE_T path_size);
HRESULT  PathCchRemoveBackslashEx(WCHAR *path, SIZE_T path_size, WCHAR **path_end, SIZE_T *free_size);
HRESULT  PathCchRemoveExtension(WCHAR *path, SIZE_T size);
HRESULT  PathCchRemoveFileSpec(WCHAR *path, SIZE_T size);
HRESULT  PathCchRenameExtension(WCHAR *path, SIZE_T size, const WCHAR *extension);
HRESULT  PathCchSkipRoot(const WCHAR *path, const WCHAR **root_end);
HRESULT  PathCchStripPrefix(WCHAR *path, SIZE_T size);
HRESULT  PathCchStripToRoot(WCHAR *path, SIZE_T size);
BOOL     PathIsUNCEx(const WCHAR *path, const WCHAR **server);

#endif
