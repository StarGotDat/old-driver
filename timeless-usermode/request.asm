.code 

request PROC

	mov r10, rcx
	mov eax, 7
	syscall
	ret

request ENDP

END