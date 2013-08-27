@echo off
SET PATH_ORIG=%PATH% 
SET PATH=%PATH%;C:\MINGW\BIN; 

gcc  ip45d.c inet_ntop45.c session_table.c compat_win.c -o ip45d.exe -I ../common -D__LITTLE_ENDIAN__ -Wall -lwsock32 -lws2_32 

SET PATH=%PATH_ORIG%
