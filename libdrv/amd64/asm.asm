.CODE

;Õª×Ô£ºnbp-0.32-public
GetGdtLimit PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
GetGdtLimit ENDP

END