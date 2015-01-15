org 100h        
.data        
    count dw 1 
    count1 dw 1
.code
   mov ax,0
   mov cx,3
loop1:      
    mov ah,09h
    mov dx,offset message    
    int 21h
    mov count,ax
    mov count1,dx
loop2:          
    mov ax,0
    mov cx,5
    mov ah,09h
    mov dx,offset message1 
    int 21h
loop loop2
    mov ax,count
    mov cx,count1      
loop loop1    
    mov ah,4ch
    int 21h
message db  'hello,world !$'
message1 db 'loop $'
end 

 



