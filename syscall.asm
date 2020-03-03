_DATA SEGMENT
_DATA ENDS
_TEXT SEGMENT

PUBLIC NtUserMessageCall
NtUserMessageCall PROC
    mov r10, rcx
    mov eax, 1007h      ; Win7 sp1
    syscall
    ret
NtUserMessageCall ENDP
_TEXT ENDS
END

