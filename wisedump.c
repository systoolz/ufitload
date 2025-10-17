#include "wisedump.h"

#define NO_CRC32 1
#include "tinflate.c"

/* data structures - valid only for ancient 16 bit installer! */
#pragma pack(push, 1)
typedef struct {
  DWORD hdr_flag; /* (hdr_flag & 0x100) - PKZipMode */
} wise_hd1;

typedef struct {
  DWORD not_know[3];
} wise_hd2;

typedef struct {
  DWORD not_used[2];
} wise_hd3;

typedef struct {
  DWORD len_uscr; /* [raw] unpacked script size */
  DWORD len_pscr; /* [pak] packed script size */
  DWORD len_pdll; /* [pak] packed WISE0001.DLL library size */
  DWORD unk_val1;
  DWORD unk_val2;
  DWORD unk_val3;
  DWORD unk_val4;
  DWORD unk_val5;
  DWORD unk_val6;
  DWORD len_pexc; /* [pak] packed DOS executable for exec and delete files */
  DWORD len_prnt; /* [pak] packed REBOOTNT.EXE executable size */
  DWORD len_pmsg; /* [pak] packed insert new disk messages */
  DWORD len_umsg; /* [raw] unpacked insert new disk messages */
  DWORD len_file; /* whole archive size */
} wise_hd4;

typedef struct {
  wise_hd1 hdr1; /* flags? */
  wise_hd2 hdr2; /* colors? */
  wise_hd3 hdr3; /* extra? */
  wise_hd4 hdr4; /* archive? */
} wise_hdr;

typedef struct {
  BYTE  bFileAttr; /* is it really file attributes? */
  BYTE  bFileFlag;
  DWORD dwOffsFrom; /* Till-From == packed size (include 4 byte CRC32? after) */
  DWORD dwOffsTill;
  WORD  wFileDate; /* DOS packed file date and time */
  WORD  wFileTime;
  DWORD dwFileSize;
  DWORD dwZero[5];
  DWORD dwFileCRC; /* CRC32? */
} wise_dat;
#pragma pack(pop)

/* script commands code length - valid only for ancient 16 bit installer! */
const static BYTE len_code[128] = {
  0x2B, 0x00, 0x02, 0x02, 0x02, 0x01, 0x13, 0x02, 0x02, 0x02, 0x03, 0x02, 0x02, 0x01, 0x00, 0x01,
  0x01, 0x01, 0x2B, 0x00, 0x0D, 0x02, 0x01, 0x06, 0x01, 0x02, 0x02, 0x01, 0x01, 0x01, 0x02, 0x00,
  0x02, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x04, 0x03, 0x01, 0x02, 0x00, 0x00, 0x00,
  0x00, 0x01, 0x03, 0x00, 0x02, 0x02, 0x01, 0x01, 0x00, 0x03, 0x02, 0x00, 0x01, 0x02, 0x01, 0x00,
  0x01, 0x00, 0x04, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x02, 0x02, 0x02, 0x02, 0x01, 0x02, 0x02, 0x02, 0x00, 0x03, 0x03, 0x03, 0x00, 0x01, 0x00, 0x02,
  0x02, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};

int TestPath(const CCHAR *name, const CCHAR *mask) {
const CCHAR *q;
CCHAR n, m;
  if (!*mask) { return(1); }
  while (*mask) {
    if (*mask == '*') {
      mask++;
      q = name;
      while (*q) {
        if (TestPath(q, mask)) { return(1); }
        q++;
      }
      continue;
    }
    if (!*name) { return(0); }
    if (*mask == '?') { name++; mask++; continue; }
    n = (*name == '/') ? '\\' : *name;
    m = (*mask == '/') ? '\\' : *mask;
    n -= ((n >= 'a') && (n <= 'z')) ? ('a' - 'A') : 0;
    m -= ((m >= 'a') && (m <= 'z')) ? ('a' - 'A') : 0;
    if (n != m) { return(0); }
    name++;
    mask++;
  }
  return(!*name);
}

void MakePath(CCHAR *path) {
CCHAR *s;
  if (path) {
    for (s = path; *s; s++) {
      if ((*s == '\\') || (*s == '/')) {
        *s = 0;
        CreateDirectory(path, NULL);
        *s = '\\';
      }
    }
  }
}

DWORD SkipText(BYTE *p) {
DWORD i;
  i = 0;
  if (p) {
    while (p[i]) { i++; }
    i++;
  }
  return(i);
}

DWORD SizeNEPE(HANDLE fl) {
IMAGE_DOS_HEADER mz;
IMAGE_OS2_HEADER ne;
IMAGE_NT_HEADERS pe;
IMAGE_SECTION_HEADER sh;
WORD si[4], ri[4], rn[6], a;
DWORD dwSize, dw, i, j;
  dwSize = 0;
  if (fl != INVALID_HANDLE_VALUE) {
    do {
      SetFilePointer(fl, 0, NULL, FILE_BEGIN);
      ZeroMemory(&mz, sizeof(mz));
      ReadFile(fl, &mz, sizeof(mz), &dw, NULL);
      if ((mz.e_magic != IMAGE_DOS_SIGNATURE) || (mz.e_lfanew < sizeof(mz))) { break; }
      /* NE */
      SetFilePointer(fl, mz.e_lfanew, NULL, FILE_BEGIN);
      ZeroMemory(&ne, sizeof(ne));
      ReadFile(fl, &ne, sizeof(ne), &dw, NULL);
      /* PE */
      SetFilePointer(fl, mz.e_lfanew, NULL, FILE_BEGIN);
      ZeroMemory(&pe, sizeof(pe));
      ReadFile(fl, &pe, sizeof(pe), &dw, NULL);
      i = 0;
      if (ne.ne_magic == IMAGE_OS2_SIGNATURE) { i = 1; }
      if (pe.Signature == IMAGE_NT_SIGNATURE) { i = 2; }
      if (!i) { break; }
      if (i == 1) {
        /* New Executable */
        SetFilePointer(fl, mz.e_lfanew + ne.ne_segtab, NULL, FILE_BEGIN);
        ne.ne_align = ne.ne_align ? ne.ne_align : 9;
        dw = mz.e_lfanew + ne.ne_segtab + (sizeof(si) * ne.ne_cseg);
        dwSize = (dwSize < dw) ? dw : dwSize;
        /* segment */
        for (i = 0; i < ne.ne_cseg; i++) {
          ZeroMemory(&si, sizeof(si));
          ReadFile(fl, &si, sizeof(si), &dw, NULL);
          if (si[0]) {
            dw = (si[0] << ne.ne_align) + (si[1] ? si[1] : 0x10000);
            dwSize = (dwSize < dw) ? dw : dwSize;
          }
        }
        /* resources */
        if (ne.ne_rsrctab > sizeof(mz)) {
          SetFilePointer(fl, mz.e_lfanew + ne.ne_rsrctab, NULL, FILE_BEGIN);
          /* read shift value */
          a = 0;
          ReadFile(fl, &a, sizeof(a), &dw, NULL);
          /* ne.ne_cres can be zero and it still valid for some reason */
          i = GetFileSize(fl, NULL);
          while (SetFilePointer(fl, 0, NULL, FILE_CURRENT) < i) {
            ZeroMemory(&ri, sizeof(ri));
            ReadFile(fl, &ri, sizeof(ri), &dw, NULL);
            /* workaround for zero ne.ne_cres value */
            if (!ri[0]) { break; }
            for (j = 0; j < ri[1]; j++) {
              ZeroMemory(&rn, sizeof(rn));
              ReadFile(fl, &rn, sizeof(rn), &dw, NULL);
              /* both offset and length must be shifted */
              dw = (rn[0] << a) + (rn[1] << a);
              dwSize = (dwSize < dw) ? dw : dwSize;
            }
          }
        }
        /* TODO: any segments after resources? */
      } else {
        /* Portable Executable */
        SetFilePointer(fl,
          mz.e_lfanew + sizeof(pe) - sizeof(pe.OptionalHeader) + pe.FileHeader.SizeOfOptionalHeader,
          NULL, FILE_BEGIN
        );
        for (i = 0; i < pe.FileHeader.NumberOfSections; i++) {
          ZeroMemory(&sh, sizeof(sh));
          ReadFile(fl, &sh, sizeof(sh), &dw, NULL);
          if (sh.SizeOfRawData) {
            dw = sh.PointerToRawData + sh.SizeOfRawData;
            dwSize = (dwSize < dw) ? dw : dwSize;
          }
        }
        /* TODO: signed executable with certificates at the end? */
      }
    } while (0);
  }
  return(dwSize);
}

DWORD WiseDumpFile(TCHAR *szFileName, CCHAR *szStopList) {
DWORD dwResult, i, sz, dw, size, offs;
BYTE b, v, *h, *scr;
CCHAR *name, *s;
FILETIME ft, wt;
wise_hdr head;
wise_dat *item;
HANDLE fl, f;
  dwResult = WISE_INVALID_NAME;
  if (szFileName && *szFileName) {
    dwResult = WISE_ERROR_OPEN;
    fl = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
    if (fl != INVALID_HANDLE_VALUE) {
      do {
        dwResult = WISE_INVALID_DATA;
        offs = SizeNEPE(fl);
        if (!offs) { break; }
        size = GetFileSize(fl, NULL);
        if (size <= (offs + sizeof(b) + sizeof(head))) { break; }
        SetFilePointer(fl, offs, NULL, FILE_BEGIN);
        /* skip external .DLL information */
        b = 0;
        ReadFile(fl, &b, sizeof(b), &dw, NULL);
        if (b) { SetFilePointer(fl, b, NULL, FILE_CURRENT); }
        /* read header */
        ZeroMemory(&head, sizeof(head));
        ReadFile(fl, &head, sizeof(head), &dw, NULL);
        /* invalid file or unsupported format */
        dwResult = WISE_INVALID_FORMAT;
        if (head.hdr4.len_file != size) { break; }
        /* file offsets */
        offs = SetFilePointer(fl, 0, NULL, FILE_CURRENT) + head.hdr4.len_pscr +
          head.hdr4.len_pdll +  head.hdr4.len_pexc + head.hdr4.len_prnt + head.hdr4.len_pmsg;
        /* read and unpack script */
        dwResult = WISE_NO_MEMORY;
        scr = (BYTE *) LocalAlloc(LPTR, head.hdr4.len_pscr);
        if (!scr) { break; }
        ReadFile(fl, scr, head.hdr4.len_pscr, &dw, NULL);
        h = (BYTE *) LocalAlloc(LPTR, head.hdr4.len_uscr);
        if (h) {
          dw = head.hdr4.len_uscr;
          i = head.hdr4.len_pscr;
          /*puff(h, &dw, scr, &i);*/
          tinflate(scr, i, h, dw);
        }
        LocalFree(scr);
        if (!h) { break; }
        /* parse script - valid only for ancient 16 bit installer! */
        scr = h;
        /* skip various initial data */
        i = sizeof(BYTE) + (sizeof(DWORD) * 9);
        for (dw = 0; dw < 4; dw++) { i += SkipText(&scr[i]); }
        i += (sizeof(BYTE) * 2) + sizeof(DWORD);
        v = scr[i]; i++; /* read special value required later */
        for (dw = 0; dw < 7; dw++) { i += SkipText(&scr[i]); }
        if (v <= 1) {
          i += SkipText(&scr[i]);
        } else {
          for (dw = 0; dw < 2; dw++) { i += SkipText(&scr[i]); }
          /* something more here?.. */
        }
        for (dw = 0; dw < 53; dw++) { i += SkipText(&scr[i]); }
        while (i < head.hdr4.len_uscr) {
          b = scr[i];
          /* file block found */
          if (b == 0x00) {
            item = (wise_dat *) &scr[i + sizeof(BYTE)];
            name = (CCHAR *) &scr[i + sizeof(BYTE) + sizeof(item[0])];
            /* check for banned files */
            s = szStopList;
            if (s) {
              while (*s) {
                if (TestPath(name, s)) { break; }
                s += SkipText((BYTE *) s);
              }
              s = (*s) ? szStopList : NULL;
            }
            /* file allowed */
            if (!s) {
              /* skip special path: %TEMP%, %WIN%, %SYS%, %MAINDIR%, etc. */
              if (name[0] == '%') {
                name++;
                while ((*name) && (*name != '%')) { name++; }
                name += (*name) ? 1 : 0;
                name += ((*name == '/') || (*name == '\\')) ? 1 : 0;
              }
              if (*name) {
                /* DWORD CRC at the end not required */
                sz = item->dwOffsTill - item->dwOffsFrom - sizeof(DWORD);
                dw = item->dwFileSize;
                h = (BYTE *) LocalAlloc(LPTR, dw + sz);
                if (!h) { break; }
                SetFilePointer(fl, offs + item->dwOffsFrom, NULL, FILE_BEGIN);
                ReadFile(fl, &h[dw], sz, &dw, NULL);
                dw = item->dwFileSize;
                /*puff(h, &dw, &h[dw], &sz);*/
                tinflate(&h[dw], sz, h, dw);
                /* create path */
                MakePath(name);
                /* save file */
                f = CreateFile(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
                if (f != INVALID_HANDLE_VALUE) {
                  WriteFile(f, h, item->dwFileSize, &dw, NULL);
                  /* restore correct date */
                  DosDateTimeToFileTime(item->wFileDate, item->wFileTime, &ft);
                  LocalFileTimeToFileTime(&ft, &wt);
                  SetFileTime(f, NULL, NULL, &wt);
                  CloseHandle(f);
                }
                LocalFree(h);
                /* memory cleaned - can exit on errors */
                if (f == INVALID_HANDLE_VALUE) { break; }
              }
            }
          }
          /* skip this block */
          i += len_code[b];
          dw = len_code[32 + b] + (v * len_code[64 + b]);
          while (dw--) { i += SkipText(&scr[i]); }
          /* special case for type 6 */
          if (b == 6) { i += (v * 12) - 12; }
        }
        LocalFree(scr);
        dwResult = (i < head.hdr4.len_uscr) ? WISE_ERROR_SAVE : WISE_OK;
      } while (0);
      CloseHandle(fl);
    }
  }
  return(dwResult);
}
