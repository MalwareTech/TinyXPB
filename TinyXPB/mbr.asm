use16
ORG 0x00

;=============================================================================================
;Move this code from 0x7C00 to 0x80000 then call "realstart" at new address
;=============================================================================================
start:
	cld
	push 0x00
	pop ds

	mov sp, 0x7C00	;Stack grows downwards from address 0x7C00
	mov si, sp	
	mov di, 0x00
	mov cx, 0x100
	push 0x8000
	pop es
	rep movsw		;Copy code from DS:SI to ES:DI (0000:7C00 to 8000:0000)
	
	push 0x8000		;Segment to retf to
	push realstart	;Offset to retf to
	retf			;Jump to code at new address
	

;=============================================================================================
;Use int 0x13 to read loader16, loader32 and driver32 from the floppy disk, we have to use 
;normal read instead of extended read because it doesnt seem to work with floppy disks
;=============================================================================================
realstart:
	push es
	pop ds
	
	call LoadLdrs
	test ax, ax
	je Failed
	
	push 0x8020
	push 0x0000
	retf 		;Jump to loader16 (0x80200)
	
Failed:
	jmp $		;Infinite loop
	ret

	
;=============================================================================================
;Load Loader16.bin from floppy to 0x80200 (Directly after our new address) 
;Load Loader32.bin from floppy to 0x80400 (Leaving 512 byte space for loader16)
;Load Driver32.sys from floppy to 0x81000 (64kb aligned address)
;We can't use the int 0x13 Extended Read function because it doesn't seem to work with floppy
;int 0x13 can't read across segment boudaries so we read to 64kb aligned address, which allows 
;for driver of up to 64kb, we could write a work around but who needs a driver that big?
;=============================================================================================
LoadLdrs:
	push es
	push 0x00	
	pop es
	mov di, 0x00	;es:di must be 0000:0000
	
	mov ah, 0x08	;Read Drive Parameters
	mov dl, 0x00 	;Floppy Disk 1 
	int 0x13
	
	pop es
	
	xor ax, ax		;Calculate HeadsPerCylinder
	mov al, dh
	inc ax
	mov [HPC], ax

	xor     ax, ax	;Calculate SectorsPerTrack
	mov     al, cl
	and     al, 0x3F
	mov [SPT], ax
	
	push 0x200		;Read FAT directory to 0x80200
	push 0x8000		;Segment 0x80000
	push 0x01		;Read 1 Sector
	push 0x13		;Starting sector 19 (FAT12 Directory Table)
	call FloppyRead
	jc LoadFailed	

	push Ldr16
	call FindFATFile	;Get sector number and size of Loader16
	test ax, ax
	je LoadFailed
	
	mov [Ldr16.Address], bx
	mov [Ldr16.Size], ax
	
	push Ldr32
	call FindFATFile	;Get sector number and size of Loader32
	test ax, ax
	je LoadFailed
	
	mov [Ldr32.Address], bx
	mov [Ldr32.Size], ax
	
	push Drv32
	call FindFATFile	;Get sector number and size of Driver32
	test ax, ax
	je LoadFailed
	
	mov [Drv32.Address], bx
	mov [Drv32.Size], ax
	
	mov bx, [Ldr16.Address]
	mov ax, [Ldr16.Size]
	
	push 0x200		;Read Ldr16 to 0x80200
	push 0x8000		;Segment 0x80000
	push ax			;Number of sectors to read
	push bx			;Starting sector of file
	call FloppyRead
	jc LoadFailed
	
	mov bx, [Ldr32.Address]
	mov ax, [Ldr32.Size]
	
	push 0x400		;Read Ldr32 to 0x80400
	push 0x8000		;Segment 0x80000
	push ax			;Number of sectors to read
	push bx			;Starting sector of file
	call FloppyRead
	jc LoadFailed
	
	mov bx, [Drv32.Address]
	mov ax, [Drv32.Size]
	
	push 0x00		;Read Driver32 to 0x81000
	push 0x8100		;Segment 0x81000
	push ax			;Number of sectors to read
	push bx			;Starting sector of file
	call FloppyRead
	jc LoadFailed
	
	mov ax, 1
	
LoadFailed:
	ret

	
;=============================================================================================
;Simple wrapper for int 0x13 read from floppy without extended read function
;Parameters:
;1) Starting sector
;2) Number of sectors to read
;3) Offset to read to
;=============================================================================================
FloppyRead:
	push bp
	mov bp, sp
	
	mov dx, 0
	
TryReadAgain:
	cmp dx, 3	;Try a total of 3 times before declaring fail
	jz ReadFailed
	
	push dx
	
	mov ax, [ebp+0x04]
	call LBAToCHS
	
	mov ah, 0x02    	;Read Disk Sectors (Some reason Extended Read doesn't support floppy)
	mov al, [bp+0x06]	;Number of sectors to read
    mov dl, 0x00   		;Floppy Disk 1
    mov bx, [bp+0x08]   ;Segment
    mov es, bx
    mov bx, [bp+0x0A]	;Offset
	int 0x13	
	
	pop dx
	inc dx
	jc TryReadAgain
	
ReadFailed:
	mov sp, bp
	pop bp
	ret 0x08
	
	
;=============================================================================================
;Convert Logical Block Address to Cylinder Head Sector for using int 0x13 to read sectors
;=============================================================================================		
LBAToCHS:
	xor dx, dx
	div word [SPT]
	inc dl
	mov cl, dl ;Sector

	xor dx, dx
	div word [HPC]
	mov dh, dl ;Head
	mov ch, al ;Cylinder
	ret
	

;=============================================================================================
;Parse floppy disk FAT12 table and find the starting sector and size of a file by name
;bx = sector address of file | ax = size of file in sectors
;=============================================================================================	
FindFATFile:
	push bp
	mov bp, sp

	mov cx, 0xE0	;Maximum number of FAT directory entries
	mov si, 0x200	;We loaded the floppy root directory at 0x80200 (ds:si)

NextFATEntry:
	cmp cx, 1		;If this is the last file, exit
	jz GetLdr32Failed
	
	push si
	push cx
	
	push si				;Name of current FAT file
	push word [bp+4]	;Name of file we're looking for
	push 11				;FAT12 file names are 11 bytes max
	call MemCmp
	
	pop cx
	pop si
	
	test ax, ax	
	jne FoundLdr32
	
	add si, 0x20	;Each entry is 32 bytes in size
	dec cx			;One less entry left to process
	jmp NextFATEntry

FoundLdr32:
	mov ax, [si+26] ;Offset 26 is the sector number of the file
	add ax, 31		;To calculate the absolute sector it is (sector + 33 - 2)
	mov bx, ax

	mov ax, [si+28] ;Get the low 2 bytes of the file size

	xor dx, dx
	mov cx, 0x200	;Divide filesize by 512 to get number of sectors
	div cx
	
	test dx, dx		;If dx is non zero the file size isn't exactly x sectors in size
	je GetLdr32End
	
	add ax, 1		;Add extra sector if filesize isnt a multiple of 512
	jmp GetLdr32End
	
GetLdr32Failed:
	xor ax, ax
	
GetLdr32End:
	mov sp, bp
	pop bp
	ret 0x02
	
	
;=============================================================================================
;Simple Memcmp function used for FindFATFile to compare names
;Parameters:
;1) Memory block 1
;2) Memory Block 2
;3) Size of memory to compare
;=============================================================================================		
MemCmp:
	push bp
	mov bp, sp
	
	xor ax, ax
	mov cx, [bp+0x04] ;Size of memory to compare
	mov si, [bp+0x06] ;Memory block 1
	mov di, [bp+0x08] ;Memory block 2

	repe cmpsb
	jne MemCmpFailed
	
MemCmpSuccess:
	mov ax, 1

MemCmpFailed:

	mov sp, bp
	pop bp
	ret 0x06
	

;=============================================================================================	
; Data area
;=============================================================================================	
SPT				dw 0x00	;Sectors Per Track for int 0x13, ah = 0x02
HPC				dw 0x00 ;Heads Per Cylinder for int 0x13, ah = 0x02

Ldr16			db 'LOADER16BIN'	;Name of the 16-bit loader on floppy filesystem
	.Address	dw 0x00
	.Size		dw 0x00
	
Ldr32			db 'LOADER32BIN'	;Name of the 32-bit loader on floppy filesystem
	.Address	dw 0x00
	.Size		dw 0x00
	
Drv32			db 'DRIVER32SYS'	;Name of the 32-bit driver on floppy filesystem
	.Address	dw 0x00
	.Size		dw 0x00
	

times 510 - ($ - $$) db 0x00	;Fill rest of boot sector with 0s
dw 0xAA55						;Bootloader signature

	