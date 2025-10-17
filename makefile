# GCC mingw32-make makefile
CC=@gcc
RC=@windres
RM=@rm -rf

CFLAGS= -fno-exceptions -fno-rtti -Os -Wall -pedantic -I.
LDFLAGS= -s -nostdlib -mwindows -e_WinMain@16
LDLIBS= -l kernel32 -l user32 -l comctl32 -l comdlg32

EXE=UFitLoad
RES=${EXE}.res
EXT=.o
OBJ=UFitLoad${EXT} wisedump${EXT} SysToolX${EXT}

$(EXE):	$(OBJ) $(RES)

$(RES):	resource/${EXE}.rc resource/${EXE}.h
	${RC} --include-dir=resource -i resource/${EXE}.rc -O coff -o $@

wipe:
	${RM} *${EXT}
	${RM} ${RES}

all:	$(EXE)

clean:	wipe all
