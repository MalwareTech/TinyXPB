#include "..\Headers\Header.h"

WCHAR FileLocation[] = L"\\??\\C:\\MalwareTech.txt"; 
PDRIVER_OBJECT GlobalDriverObject;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = &DriverUnload;
	GlobalDriverObject = DriverObject;

	DbgPrint("System successfully infected.\n");

	//Wait till all the boot drivers have been loaded before continuing
	IoRegisterBootDriverReinitialization(DriverObject, &DriverReinitialize, NULL);
	return STATUS_SUCCESS;
}

//Will be called after all the boot drivers have been loaded
VOID DriverReinitialize(IN DRIVER_OBJECT *DriverObject, IN PVOID Context, IN ULONG Count)
{
	HANDLE FileHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING FileName;
	IO_STATUS_BLOCK IoStatusBlock;

	RtlInitUnicodeString(&FileName, FileLocation);
	InitializeObjectAttributes(&ObjectAttributes, &FileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	ZwCreateFile(&FileHandle, GENERIC_WRITE, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, NULL, FILE_SUPERSEDE, NULL, NULL, NULL);
	ZwClose(FileHandle);
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{

}