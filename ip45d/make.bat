@echo off
SET PATH_ORIG=%PATH% 
SET PATH=%PATH%;C:\MINGW\BIN; 

gcc -DPKG_VERSION=\"w0.0\" ip45d.c inet_ntop45.c session_table.c compat_win.c -o ip45d.exe -I ../common -DWIN32 -DWIN32_LEAN_AND_MEAN -D__LITTLE_ENDIAN__ -Wall -lkernel32 -lwsock32 -lws2_32 
gcc -DPKG_VERSION=\"w0.0\"  ip45serv.c -o ip45serv.exe -DWIN32 -D_UNICODE -DUNICODE -Wall -lkernel32 -lwsock32 -lws2_32 

SET PATH=%PATH_ORIG%
