
PATH=%PATH%;C:\MINGW\BIN; 
gcc  ip45d.c inet_ntop45.c session_table.c -o ip45d.exe -I ../common -D__LITTLE_ENDIAN__ -Wall -lwsock32 -lws2_32 

