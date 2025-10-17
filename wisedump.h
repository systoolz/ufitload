#ifndef __WISEDUMP_H
#define __WISEDUMP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>

enum {
  WISE_OK = 0,
  WISE_INVALID_NAME,
  WISE_ERROR_OPEN,
  WISE_INVALID_DATA,
  WISE_INVALID_FORMAT,
  WISE_NO_MEMORY,
  WISE_ERROR_SAVE
};

DWORD WiseDumpFile(TCHAR *szFileName, CCHAR *szStopList);

#ifdef __cplusplus
}
#endif

#endif
