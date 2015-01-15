.586
.model flat,stdcall
option casemap:none
   include windows.inc
   include user32.inc
   include kernel32.inc
   include masm32.inc
   include masm32rt.inc
   
   includelib user32.lib
   includelib kernel32.lib
   includelib masm32.lib
.data
msgcaption          		  BYTE                        "Demo", 0
msgtext         		 	  BYTE                        "Hello World !", 0
.code
start:
	invoke MessageBox,NULL,addr msgtext,addr msgcaption ,MB_OK
	invoke ExitProcess,0
end start