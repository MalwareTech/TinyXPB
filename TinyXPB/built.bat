@echo off

cd /d %~dp0

Tools\FASM\fasm.exe mbr.asm bin\mbr.bin

IF NOT ERRORLEVEL 1 GOTO Success
echo FASM failed to compile
PAUSE
:Success

Tools\FASM\fasm.exe loader16.asm bin\loader16.bin

IF NOT ERRORLEVEL 1 GOTO Success
echo FASM failed to compile
PAUSE
:Success

Tools\FASM\fasm.exe loader32.asm bin\loader32.bin

IF NOT ERRORLEVEL 1 GOTO Success
echo FASM failed to compile
PAUSE
:Success

del floppy.img
cd bin
..\tools\MakeImage\imagefs c ..\floppy.img 20
..\tools\MakeImage\imagefs b ..\floppy.img mbr.bin
..\tools\MakeImage\imagefs a ..\floppy.img loader16.bin
..\tools\MakeImage\imagefs a ..\floppy.img loader32.bin
..\tools\MakeImage\imagefs a ..\floppy.img driver32.sys
echo Done!
PAUSE