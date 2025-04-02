#ifndef __FILE_OPERATION_TRACKER_H__
#define __FILE_OPERATION_TRACKER_H__

#include <fltKernel.h>

#define COMMUNICATION_PORT_NAME L"\\FileTrackerPort"

typedef struct S_FOTDATA {
	PFLT_FILTER RegisteredFilter;
	PFLT_PORT ServerPort;
	PFLT_PORT ClientPort;
} FOT_DATA, * PFOT_DATA;

extern FOT_DATA gFOT;

FLT_PREOP_CALLBACK_STATUS FOTPreOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

NTSTATUS FOTUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS FOTConnect(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionCookie);

VOID FOTDisconnect(
	_In_opt_ PVOID ConnectionCookie);

//NTSTATUS FOTMessage (
//	_In_opt_ PVOID PortCookie,
//	_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
//	_In_ ULONG InputBufferLength,
//	_Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
//	_In_ ULONG OutputBufferLength,
//	_Out_ PULONG ReturnOutputBufferLength
//	);

#endif //__FILE_OPERATION_TRACKER_H__