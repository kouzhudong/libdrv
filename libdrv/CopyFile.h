#pragma once

#include "pch.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


BOOLEAN CopyFile(IN PWCH DestinationFile, IN PWCH SourceFile, IN BOOLEAN bFailIfExists);
BOOLEAN CopyFileEx(IN UNICODE_STRING * FileName, IN UNICODE_STRING * newFileName);
BOOLEAN ZwCopyFile(IN UNICODE_STRING * FileName, IN UNICODE_STRING * newFileName);
NTSTATUS IrpCopyFile(UNICODE_STRING * name, UNICODE_STRING * newFileName);

BOOLEAN FltCopyFile(_In_ PFLT_FILTER Filter, __inout PFLT_CALLBACK_DATA Data, IN UNICODE_STRING * FileName, IN UNICODE_STRING * newFileName);


EXTERN_C_END


//////////////////////////////////////////////////////////////////////////////////////////////////
