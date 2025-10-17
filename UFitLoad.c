#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shlwapi.h>

#include "SysToolX.h"

#include "wisedump.h"

#include "resource/UFitLoad.h"

DWORD FastFind(BYTE *p, DWORD ps, BYTE *q, BYTE qs) {
BYTE t[256];
DWORD i, s;
  if (p && ps && q && qs && (ps >= qs)) {
    //FillMemory(t, sizeof(t), qs);
    for (i = 0; i < sizeof(t); i++) {
      t[i] = qs;
    }
    qs--;
    for (i = 0; i < qs; i++) {
      t[q[i]] = qs - i;
    }
    s = 0;
    while ((ps - s) > qs) {
      for (i = qs; (p[s + i] == q[i]); i--) {
        if (!i) {
          return(s + 1);
        }
      }
      s += t[p[s + qs]];
    }
  }
  return(0);
}

void ProcWrite(HANDLE hpc, void *dst, void *src, DWORD len) {
DWORD old;
  if (VirtualProtectEx(hpc, dst, len, PAGE_EXECUTE_READWRITE, &old)) {
    WriteProcessMemory(hpc, dst, src, len, NULL);
    FlushInstructionCache(hpc, dst, len);
    VirtualProtectEx(hpc, dst, len, old, &old);
  }
}

#define CODESECT (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)

BOOL CodePatch(HANDLE h, BYTE *p) {
IMAGE_SECTION_HEADER sh, *t;
IMAGE_NT_HEADERS pe;
IMAGE_DOS_HEADER mz;
BOOL result;
DWORD i, l;
BYTE *d, b;
  result = FALSE;
  do {
    if (!p) { break; }
    // DOS header
    if (!ReadProcessMemory(h, p, &mz, sizeof(mz), NULL)) { break; }
    if (mz.e_magic != IMAGE_DOS_SIGNATURE) { break; }
    if (mz.e_lfanew < sizeof(mz)) { break; }
    // PE header
    if (!ReadProcessMemory(h, &p[mz.e_lfanew], &pe, sizeof(pe), NULL)) { break; }
    if (pe.Signature != IMAGE_NT_SIGNATURE) { break; }
    // sections
    t = (IMAGE_SECTION_HEADER *) &p[
      mz.e_lfanew + sizeof(pe) - sizeof(pe.OptionalHeader) + pe.FileHeader.SizeOfOptionalHeader
    ];
    for (i = 0; i < pe.FileHeader.NumberOfSections; i++) {
      if (!ReadProcessMemory(h, &t[i], &sh, sizeof(sh), NULL)) { break; }
      // code section found
      if ((sh.Characteristics & CODESECT) == CODESECT) {
        d = (BYTE *) LocalAlloc(LPTR, sh.Misc.VirtualSize);
        if (d) {
          if (ReadProcessMemory(h, &p[sh.VirtualAddress], d, sh.Misc.VirtualSize, NULL)) {
            l = FastFind(d, sh.Misc.VirtualSize, (BYTE *) "\x25\xFF\xFF\xFF\x3F\x50\xFF", 7);
            if (l) {
              // make software portable
              l = l - 1 + 5;
              // swap arguments for GetWindowsDirectoryA(path, size)
              // since this will be GetCurrentDirectoryA(size, path)
              b = d[l];
              //MoveMemory(&d[l], &d[l + 1], 6);
              d[l +  0] = d[l +  1];
              d[l +  1] = d[l +  2];
              d[l +  2] = d[l +  3];
              d[l +  3] = d[l +  4];
              d[l +  4] = d[l +  5];
              d[l +  5] = d[l +  6];
              d[l +  6] = b;
              // replace GetWindowsDirectoryA() with GetCurrentDirectoryA
              // this call only to get the string path length
              *((DWORD *) &d[l +  9]) += 1720;
              // replace call to internal GfaWin23.ocx funcion
              // system directory => current directory
              *((DWORD *) &d[l + 21]) += 4;
              // skip "%WIN%\System\unifit 200?.ini" reading - use current directory
              d[l + 25] = 0xEB;
              d[l + 26] = 0x75;
              // write updated data back
              ProcWrite(h, &p[sh.VirtualAddress + l], &d[l], 27);
              result = TRUE;
            }
          }
          LocalFree(d);
        }
        break;
      }
    }
  } while (0);
  return(result);
}

BOOL StartProcess(BOOL bRun) {
PROCESS_INFORMATION pi;
STARTUPINFO si;
WIN32_FIND_DATA fd;
HANDLE fh;
BOOL r;
  r = FALSE;
  fh = FindFirstFile(TEXT("Unifit 200?*.exe"), &fd);
  if (fh != INVALID_HANDLE_VALUE) {
    do {
      if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { continue; }
      if (!bRun) { r = TRUE; break; }
      ZeroMemory(&si, sizeof(si));
      si.cb = sizeof(si);
      r = CreateProcess(NULL, fd.cFileName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
      if (r) {
        r = CodePatch(pi.hProcess, (BYTE *) 0x400000);
        if (r) {
          ResumeThread(pi.hThread);
          CloseHandle(pi.hThread);
          CloseHandle(pi.hProcess);
          break;
        } else {
          TerminateProcess(pi.hProcess, 0);
        }
      }
    } while (FindNextFile(fh, &fd));
    FindClose(fh);
  }
  return(r);
}

// https://devblogs.microsoft.com/oldnewthing/20031114-00/?p=41823
// https://devblogs.microsoft.com/oldnewthing/20031111-00/?p=41883
// unfortunately SetWindowSubclass/RemoveWindowSubclass from commctrl.h requires at least NT 5.0
LRESULT CALLBACK EditNoSelProc(HWND wnd, UINT umsg, WPARAM wparm, LPARAM lparm) {
WNDPROC lpDefPrc;
  lpDefPrc = (WNDPROC) GetWindowLong(wnd, GWL_USERDATA);
  switch (umsg) {
    case WM_NCDESTROY:
      SubclassWindow(wnd, lpDefPrc);
      break;
    case WM_GETDLGCODE:
      return(CallWindowProc(lpDefPrc, wnd, umsg, wparm, lparm) & ~DLGC_HASSETSEL);
      break;
  }
  return(CallWindowProc(lpDefPrc, wnd, umsg, wparm, lparm));
}

BOOL CALLBACK DlgPrc(HWND wnd, UINT umsg, WPARAM wparm, LPARAM lparm) {
TCHAR *s;
DWORD i;
  switch (umsg) {
    case WM_INITDIALOG:
      // add icons
      lparm = (LPARAM) LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON));
      SendMessage(wnd, WM_SETICON, ICON_BIG  , lparm);
      SendMessage(wnd, WM_SETICON, ICON_SMALL, lparm);
      // load form text
      s = LangLoadString(IDS_TEXT);
      if (s) {
        SetDlgItemText(wnd, IDC_TEXT, s);
        FreeMem(s);
      }
      // default installer name
      s = LangLoadString(IDS_FILE);
      if (s) {
        SetDlgItemText(wnd, IDC_FILE, s);
        FreeMem(s);
      }
      // not installed
      SetFocus(GetDlgItem(wnd, IDC_WORK));
      if (!StartProcess(FALSE)) {
        DialogEnableWindow(wnd, IDC_WORK, FALSE);
      }
      // subclass edit
      wnd = GetDlgItem(wnd, IDC_TEXT);
      SetWindowLong(wnd, GWL_USERDATA, (LONG) SubclassWindow(wnd, EditNoSelProc));
      break;
    case WM_COMMAND:
      if (HIWORD(wparm) == BN_CLICKED) {
        switch (LOWORD(wparm)) {
          case IDC_LOOK:
            s = OpenSaveDialog(
              wnd, TEXT("Executable files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0"), TEXT(".exe"), 0
            );
            if (s) {
              SetDlgItemText(wnd, IDC_FILE, s);
              FreeMem(s);
              SendMessage(GetDlgItem(wnd, IDC_FILE), EM_SETSEL, 0, -1);
            }
            break;
          case IDC_INIT:
            if (
              MsgBox(wnd, MAKEINTRESOURCE(IDS_CONFIRM_INSTALL), MB_OKCANCEL | MB_ICONQUESTION) == IDOK
            ) {
              s = GetWndText(GetDlgItem(wnd, IDC_FILE));
              if (s) {
                i = WiseDumpFile(
                  // file to unpack
                  s,
                  // skip some files since they are unused anyway
                  "*\\%W32INST_PATH_%\0"
                  "*\\Unifit 200?*.ini\0"
                  "*\\GfaWin1?.Ocx\0"
                  "*\\Unifit 200?.ico\0"
                  "*\\Unwise 200?.exe\0"
                  // 2001
                  "*\\Ctl3d1.dll\0"
                  // 2002/2003
                  "*\\INSTALL.LOG\0"
                );
                FreeMem(s);
                if (i == WISE_OK) {
                  DialogEnableWindow(wnd, IDC_WORK, TRUE);
                  SetFocus(GetDlgItem(wnd, IDC_WORK));
                }
                MsgBox(wnd, MAKEINTRESOURCE(
                    (i <= IDS_WISE_ERROR_SAVE) ? (i + IDS_WISE_OK) : IDS_WISE_UNKNOWN
                  ),
                  ((i == WISE_OK) ? MB_ICONINFORMATION : MB_ICONERROR) | MB_OK
                );
              }
            }
            break;
          case IDC_WORK:
            if (!StartProcess(TRUE)) {
              MsgBox(wnd, MAKEINTRESOURCE(IDS_ERROR_START), MB_ICONERROR | MB_OK);
              break;
            }
            // fall through
          case IDCANCEL:
            EndDialog(wnd, 0);
            break;
        }
      }
      break;
  }
  return(FALSE);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR lpCmdLine, int nCmdShow) {
  InitCommonControls();
  DialogBoxParam(GetModuleHandle(NULL), MAKEINTRESOURCE(IDD_MAINFORM), 0, &DlgPrc, 0);
  ExitProcess(0);
  return(0);
}
