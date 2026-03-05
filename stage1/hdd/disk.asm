; *****************************
;     Reads bytes from disk
; *****************************

; IN:
; EAX = Start address to load low 32
; EBP = Start address to load high 32
; DL = Drive number
; ES = Buffer segment
; BX = Buffer offset
; ECX = Byte count

; OUT:
; Carry if error

read_sectors:
    pusha

    mov si, .da_struct

    mov word  [si],    16
    mov word  [si+2],  1
    mov word  [si+4],  bx
    mov word  [si+6],  es

    push dx
    push si

    push eax
    push ebp

    ; Get bytes per sector
    mov ah, 0x48
    mov si, .drive_params
    mov word [si], 30       ; buf_size
    int 0x13
    jc .done
    movzx ebp, word [si+24] ; bytes_per_sect

    ; ECX byte count to CX sector count
    mov ax, cx
    shr ecx, 16
    mov dx, cx
    xor cx, cx
    div bp
    test dx, dx
    setnz cl
    add cx, ax

    pop edx
    pop eax

    pop si

    ; EDX:EAX byte address to 64-bit LBA sector
    push eax
    mov eax, edx
    xor edx, edx
    div ebp
    mov ebx, eax
    pop eax
    div ebp
    mov dword [si+8],  eax
    mov dword [si+12], ebx

    pop dx

  .loop:
    mov ah, 0x42

    clc
    int 0x13
    jc .done

    add word  [si+4], bp
    add dword [si+8], 1
    adc dword [si+12], 0

    loop .loop

  .done:
    popa
    ret

  .da_struct:    equ 0x8000
  .drive_params: equ 0x8010
