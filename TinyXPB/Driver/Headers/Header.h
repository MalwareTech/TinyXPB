extern "C" 
{ 
	#include <ntddk.h>	
}

VOID DriverReinitialize(IN DRIVER_OBJECT *DriverObject, IN PVOID Context, IN ULONG Count);
VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);

