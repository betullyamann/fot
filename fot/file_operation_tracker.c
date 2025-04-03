#include "file_operation_tracker.h"

#include <fltKernel.h>

FOT_DATA gFOT;

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	DbgPrint("\n\n-----------------------------------------------------------------------------------\n\n");

	UNREFERENCED_PARAMETER(RegistryPath);

	CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
		{IRP_MJ_CREATE, 0, FOTPreOperationCallback, NULL}, // create, open
		{IRP_MJ_CLOSE,  0, FOTPreOperationCallback, NULL}, // delete, rename
		{IRP_MJ_READ,   0, FOTPreOperationCallback, NULL},
		{IRP_MJ_WRITE,  0, FOTPreOperationCallback, NULL},
		{IRP_MJ_CLEANUP,0, FOTPreOperationCallback, NULL}, //file handle closure
		{IRP_MJ_SET_INFORMATION,   0, FOTPreOperationCallback, NULL}, // delete, rename, move
		{IRP_MJ_OPERATION_END}
	};

	CONST FLT_REGISTRATION RegistrationData = {
		.Size = sizeof(FLT_REGISTRATION),
		.Version = FLT_REGISTRATION_VERSION,
		.Flags = 0,
		.ContextRegistration = NULL,
		.OperationRegistration = Callbacks,
		.FilterUnloadCallback = FOTUnload,
		.InstanceSetupCallback = NULL,
		.InstanceQueryTeardownCallback = NULL,
		.InstanceTeardownStartCallback = NULL,
		.InstanceTeardownCompleteCallback = NULL,
		.GenerateFileNameCallback = NULL,
		.NormalizeNameComponentCallback = NULL,
		.NormalizeContextCleanupCallback = NULL,
		.TransactionNotificationCallback = NULL,
		.NormalizeNameComponentExCallback = NULL,
		.SectionNotificationCallback = NULL,
	};

	gFOT.ClientPort = NULL;
	gFOT.ServerPort = NULL;

	NTSTATUS status = FltRegisterFilter(DriverObject,
		&RegistrationData,
		&gFOT.RegisteredFilter);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FltRegisterFilter failed. status 0x%x\n", status);
		return status;
	}


	PSECURITY_DESCRIPTOR security_descriptor = NULL;
	status = FltBuildDefaultSecurityDescriptor(&security_descriptor, FLT_PORT_ALL_ACCESS);
	if (NT_ERROR(status)) {
		DbgPrint("FltBuildDefaultSecurityDescriptor failed. status 0x%x\n", status);
		return status;
	}

	UNICODE_STRING portName;
	RtlInitUnicodeString(&portName, COMMUNICATION_PORT_NAME);

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes,
		&portName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		security_descriptor);

	status = FltCreateCommunicationPort(gFOT.RegisteredFilter,
		&gFOT.ServerPort,
		&objectAttributes,
		NULL,
		FOTConnect, // FltMgr calls this routine whenever a user-mode application calls FilterConnectCommunicationPort
		FOTDisconnect,
		NULL,//FOTMessage,
		1);

	if (!NT_SUCCESS(status)) {
		DbgPrint("FilterCreateCommunicationPort failed, status: 0x%x\n", status);
		FltUnregisterFilter(gFOT.RegisteredFilter);
		return status;
	}

	DbgPrint("FltCreateCommunicationPort opened !!\n");

	status = FltStartFiltering(gFOT.RegisteredFilter);
	if (!NT_SUCCESS(status)) {
		DbgPrint("FltStartFiltering failed, status: 0x%x\n", status);
		FltUnregisterFilter(gFOT.RegisteredFilter);
		return status;
	}
	DbgPrint("FltStartFiltering !!\n");


	return status;

}


FLT_PREOP_CALLBACK_STATUS FOTPreOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PFLT_FILE_NAME_INFORMATION FileNameInfo;
	NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &FileNameInfo);
	if (NT_SUCCESS(status)) {

		FltParseFileNameInformation(FileNameInfo);

		switch (Data->Iopb->MajorFunction) {
		case IRP_MJ_CREATE:
			break;

		case IRP_MJ_CLOSE:
			DbgPrint("File closed - %wZ\n", &FileNameInfo->Name);
			break;

		case IRP_MJ_READ:
			DbgPrint("File read - %wZ\n", &FileNameInfo->Name);
			break;

		case IRP_MJ_WRITE:
			DbgPrint("File written - %wZ\n", &FileNameInfo->Name);
			break;

		case IRP_MJ_SET_INFORMATION:
		{
			FILE_INFORMATION_CLASS FileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
			if (FileInfoClass == FileDispositionInformation ||
				FileInfoClass == FileDispositionInformationEx) {

				PFILE_DISPOSITION_INFORMATION FileInformation = (PFILE_DISPOSITION_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
				if (FileInformation->DeleteFile)
				{
					DbgPrint("File deleted - %wZ\n", &FileNameInfo->Name);

					//Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					//DbgPrint("File deletion blocked.\n");
					//return FLT_PREOP_COMPLETE;
				}
			}
			else if (FileInfoClass == FileRenameInformation ||
				FileInfoClass == FileRenameInformationEx) {

				PFILE_RENAME_INFORMATION FileInformation = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
				if (!FileInformation || FileInformation->FileNameLength == 0) {
					return FLT_PREOP_SUCCESS_NO_CALLBACK;
				}
				
				if (FileInformation->RootDirectory == NULL) {
					// Renaming within the same directory
					DbgPrint("File renamed - %wZ\n", &FileNameInfo->Name);
				}
				else {
					// Moving to a different directory
					DbgPrint("File moved - %wZ\n", &FileNameInfo->Name);

				}
			}
			break;
		}
		case IRP_MJ_DIRECTORY_CONTROL:
			DbgPrint("Directory changed detected - %wZ\n", &FileNameInfo->Name);
			break;

		case IRP_MJ_CLEANUP:
			DbgPrint("File Handle cleaned- %wZ\n", &FileNameInfo->Name);
			break;

		default:
			DbgPrint("Unknown file operation - %wZ\n", &FileNameInfo->Name);
			break;
		}

		FltReleaseFileNameInformation(FileNameInfo);
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS FOTUnload(
	FLT_FILTER_UNLOAD_FLAGS Flags) {
	UNREFERENCED_PARAMETER(Flags);

	if (gFOT.ServerPort) {
		FltCloseCommunicationPort(gFOT.ServerPort);
		gFOT.ServerPort = NULL;
	}

	if (gFOT.ClientPort) {
		FltCloseClientPort(gFOT.RegisteredFilter, &gFOT.ClientPort);
		gFOT.ClientPort = NULL;
	}

	if (gFOT.RegisteredFilter) {
		FltUnregisterFilter(gFOT.RegisteredFilter);
		gFOT.RegisteredFilter = NULL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS FOTConnect(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Outptr_result_maybenull_ PVOID* ConnectionCookie) {

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	ConnectionCookie = NULL;

	// the filter driver now knows which port to use for sending 
	// or receiving messages from the user-mode application.
	gFOT.ClientPort = ClientPort;
	DbgPrint("Communicaiton Request !!\n");
	return STATUS_SUCCESS;
}

VOID FOTDisconnect(
	_In_opt_ PVOID ConnectionCookie) {

	UNREFERENCED_PARAMETER(ConnectionCookie);

	if (NULL != gFOT.ClientPort)
	{
		FltCloseClientPort(gFOT.RegisteredFilter, &gFOT.ClientPort);
		gFOT.ClientPort = NULL;
	}
}

//NTSTATUS FOTMessage(
//	_In_opt_ PVOID PortCookie,
//	_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
//	_In_ ULONG InputBufferLength,
//	_Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
//	_In_ ULONG OutputBufferLength,
//	_Out_ PULONG ReturnOutputBufferLength
//) {
//	//TODO
//}