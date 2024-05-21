#include "flt.h"
#include "misc.h"
#include "object.h"

#pragma warning(disable:6385)
#pragma warning(disable:6386)


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS FltGetFileNameInformationEx(__inout PFLT_CALLBACK_DATA Cbd,
                                     __in PCFLT_RELATED_OBJECTS FltObjects,
                                     OUT PUNICODE_STRING usFullPath
)
/*
д���������ԭ���ǣ�FltGetFileNameInformation���ڲ����ڵ�·���᷵��ʧ�ܡ�
Ҳ��Ӧ����������ʵ�����Ҳ����취�ˡ�
�����ʵ�ְ취�ǣ���������ʧ�ܣ��ͻ�ȡ�ļ���������ݡ�
*/
{
    PFLT_FILE_NAME_INFORMATION pfni{};
    NTSTATUS Status = STATUS_SUCCESS;

    /*
    FltGetFileNameInformation cannot get file name information if the TopLevelIrp field of the current thread is not NULL,
    because the resulting file system recursion could cause deadlocks or stack overflows. (For more information about this issue, see IoGetTopLevelIrp.)
    FltGetFileNameInformation cannot get file name information in the paging I/O path.
    FltGetFileNameInformation cannot get file name information in the post-close path.
    FltGetFileNameInformation cannot get the short name of a file in the pre-create path.
    */
    if (FlagOn(Cbd->Iopb->IrpFlags, IRP_PAGING_IO) ||
        FlagOn(Cbd->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO) ||
        IoGetTopLevelIrp()) //IRP_NOCACHE
    {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%wZ, IrpFlags:0x%#x",
              &FltObjects->FileObject->FileName, Cbd->Iopb->IrpFlags);
        return Status;
    }

    if (FlagOn(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {
        ClearFlag(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY);
        Status = FltGetFileNameInformation(Cbd, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_FILESYSTEM_ONLY, &pfni);
        if (!NT_SUCCESS(Status)) {
            //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�ļ�/Ŀ¼:%wZ��status:0x%#x", &FltObjects->FileObject->FileName, Status);          
        }
        SetFlag(Cbd->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY);
    } else {
        Status = FltGetFileNameInformation(Cbd, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &pfni);
        if (!NT_SUCCESS(Status)) {
            //Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�ļ�/Ŀ¼:%wZ��status:0x%#x", &FltObjects->FileObject->FileName, Status);
        }
    }

    if (NT_SUCCESS(Status)) {
        FltReleaseFileNameInformation(pfni);
        return Status;
    }

    if (!NT_SUCCESS(Status)) {
        UNICODE_STRING  VolumeName = {0};
        ULONG  BufferSizeNeeded = 0;

        Status = FltGetVolumeName(FltObjects->Volume, nullptr, &BufferSizeNeeded);
        ASSERT(!NT_SUCCESS(Status));//STATUS_BUFFER_TOO_SMALL

        //�����ɹ��ˣ��������ͷš�
        usFullPath->Buffer = (wchar_t *)ExAllocatePoolWithTag(NonPagedPool, BufferSizeNeeded, TAG);
        ASSERT(usFullPath->Buffer);
        RtlZeroMemory(usFullPath->Buffer, BufferSizeNeeded);
        RtlInitEmptyUnicodeString(usFullPath, usFullPath->Buffer, (USHORT)BufferSizeNeeded);//Ч����ֻ�Ǹı����ֵ,����ṹ��Ա.

        Status = FltGetVolumeName(FltObjects->Volume, usFullPath, &BufferSizeNeeded);
        if (!NT_SUCCESS(Status)) {
            KdPrint(("FltGetVolumeName fail with 0x%0x!\r\n", Status));
            FreeUnicodeString(usFullPath);
            return Status;
        }

        if (nullptr != FltObjects->FileObject->RelatedFileObject) {
            RtlAppendUnicodeStringToString(usFullPath, &FltObjects->FileObject->RelatedFileObject->FileName);
            RtlAppendUnicodeToString(usFullPath, L"\\");
        }

        Status = RtlAppendUnicodeStringToString(usFullPath, &FltObjects->FileObject->FileName);
        if (!NT_SUCCESS(Status)) {
            FreeUnicodeString(usFullPath);
            return Status;
        }

        return Status;;
    }

    return Status;
}


#if (NTDDI_VERSION < NTDDI_VISTA)
NTSTATUS FltQueryDirectoryFile(_In_ PFLT_INSTANCE Instance,
                               _In_ PFILE_OBJECT FileObject,
                               _Out_writes_bytes_(Length) PVOID FileInformationBuffer,
                               _In_ ULONG Length,
                               _In_ FILE_INFORMATION_CLASS FileInformationClass,
                               _In_ BOOLEAN ReturnSingleEntry,
                               _In_opt_ PUNICODE_STRING FileName,
                               _In_ BOOLEAN RestartScan,
                               _Out_opt_ PULONG LengthReturned
)
/*++
Routine Description:
    ΪXP��������FltQueryDirectoryFile
    ���Ҫ��XP�����У�����XP�±��룬������������ʧ�ܡ�
    This function is like ZwQueryDirectoryFile for filters
    ����Ϊ��ZwQueryDirectoryFile_LongNameɶ�ĽϺá�
    ע�⣺FltQueryDirectoryFile��Vista���У�ZwQueryDirectoryFile��Xp���С�
Arguments:
    Instance - Supplies the Instance initiating this IO.
    FileObject - Supplies the file object about which the requested information should be changed.
    FileInformation - Supplies a buffer containing the information which should be changed on the file.
    Length - Supplies the length, in bytes, of the FileInformation buffer.
    FileInformationClass - Specifies the type of information which should be changed about the file.
    ReturnSingleEntry - If this parameter is TRUE, FltQueryDirectoryFile returns only the first entry that is found.
    FileName - An optional pointer to a caller-allocated Unicode string containing the name of a file (or multiple files, if wildcards are used)  within the directory specified by FileHandle.
               This parameter is optional and can be NULL.
    RestartScan - Set to TRUE if the scan is to start at the first entry in the directory. Set to FALSE if resuming the scan from a previous call.
Return Value:
    The Status returned is the final completion Status of the operation.
--*/
{
    PFLT_CALLBACK_DATA data;
    NTSTATUS Status;

    PAGED_CODE();

    //  Customized FltQueryDirectoryFile if it is not exported from FltMgr.
    Status = FltAllocateCallbackData(Instance, FileObject, &data);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    data->Iopb->MajorFunction = IRP_MJ_DIRECTORY_CONTROL;
    data->Iopb->MinorFunction = IRP_MN_QUERY_DIRECTORY;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length = Length;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName = FileName;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass = FileInformationClass;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileIndex = 0;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = FileInformationBuffer;
    data->Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress = nullptr;

    if (RestartScan) {
        data->Iopb->OperationFlags |= SL_RESTART_SCAN;
    }
    if (ReturnSingleEntry) {
        data->Iopb->OperationFlags |= SL_RETURN_SINGLE_ENTRY;
    }

    FltPerformSynchronousIo(data);//  Perform a synchronous operation.

    Status = data->IoStatus.Status;

    if (ARGUMENT_PRESENT(LengthReturned) && NT_SUCCESS(Status)) {
        *LengthReturned = (ULONG)data->IoStatus.Information;
    }

    FltFreeCallbackData(data);

    return Status;
}
#endif


VOID PrintVolume(__in PCFLT_RELATED_OBJECTS FltObjects)
/*
���ܣ���ӡ���صĶ������Ϣ��

�˺���һ�㽨������InstanceSetup�С�
*/
{
    NTSTATUS Status{};
    PVOID Buffer{};
    ULONG BufferSizeNeeded{};
    UNICODE_STRING Volume{};

    Status = FltGetVolumeName(FltObjects->Volume, nullptr, &BufferSizeNeeded);
    if (Status != STATUS_BUFFER_TOO_SMALL) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
        return;
    }

    Buffer = ExAllocatePoolWithTag(PagedPool, (SIZE_T)BufferSizeNeeded + 2, TAG);
    if (Buffer == nullptr) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "%s", "�����ڴ�ʧ��");
        return;
    }
    RtlZeroMemory(Buffer, (size_t)BufferSizeNeeded + 2);

    Volume.Buffer = (PWCH)Buffer;
    Volume.Length = (USHORT)BufferSizeNeeded;
    Volume.MaximumLength = (USHORT)BufferSizeNeeded + 2;
    Status = FltGetVolumeName(FltObjects->Volume, &Volume, &BufferSizeNeeded);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
    } else {
        PrintEx(DPFLTR_FLTMGR_ID, DPFLTR_INFO_LEVEL, "��Ϣ��attached device:%wZ", &Volume);
    }

    ExFreePoolWithTag(Buffer, TAG);
}


/*
�ļ���:EnumerateFilters.C

΢������ʹ��:IoEnumerateRegisteredFiltersList.

����:enumerates all registered minifilter drivers in the system����һЩ��Ϣ����ʾ.
Ŀ��:ʾ��һЩminifilter��һЩö�ٺ������÷�,���,����.

����Ҫ����fltMgr.lib.
���صķ�ʽ����һ�������(nt����).

�ο�����:
http://hi.baidu.com/kernelkit/item/95dab957bf115711aaf6d743
http://www.inreverse.net/?p=1334
http://blogs.msdn.com/b/alexcarp/archive/2009/08/11/issuing-io-in-minifilters-part-1-fltcreatefile.aspx
http://blogs.msdn.com/b/alexcarp/archive/2009/09/01/issuing-io-in-minifilters-part-2-flt-vs-zw.aspx
http://blogs.msdn.com/b/alexcarp/archive/2009/06/16/filter-manager-concepts-part-3-flt-filter.aspx
http://blogs.msdn.com/b/alexcarp/archive/2009/06/24/filter-manager-concepts-part-4-flt-instance.aspx
��.

����֮��,����ָ��.
made by correy
made at 2013.10.23

���˸о�FltEnumerateInstances��FltEnumerateVolumes���.
������ǰ���ܻ�ȡ���е�minifilter�����е�ʵ������Ϣ,����ֻ��ȡĳ��minifilter�����еľ��豸����Ϣ.
������ת������ϵ�ĺ���.

��ʼ��Ϊ:FltEnumerateVolumes�ǻ�ȡ��һ��PFLT_FILTER���˵ľ��豸�Ķ���,����ȫ���Ĵ����ϵľ�.
��������:��ȡ���ؼ�����ϵĿ��õľ�.һ���ǻ�ȡ������:
1.��������û�й���.
2.������������������ľ��豸.
3.����ӳ����̷�.
4.subst����������������.
5.����û�в���.
���������ȱ���ǵ�һ������,���һ�������0,���˽�����ȥ���������.
������minifilter���������������������.
*/


void PrintFilterFullInformation(PFLT_FILTER pf)
{
    //��һ��˼·��ʹ��:FltEnumerateFilterInformation

    NTSTATUS Status = STATUS_SUCCESS;
    PVOID  Buffer{};
    ULONG  BufferSize = 0;
    ULONG  BytesReturned = 0;
    PFILTER_FULL_INFORMATION pfi{};
    UNICODE_STRING FilterName{};

    Status = FltGetFilterInformation(pf, FilterFullInformation, Buffer, BufferSize, &BytesReturned);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return;
        }
    }

    BufferSize = sizeof(PFLT_FILTER) * BytesReturned * 2;//������һ��.
    Buffer = static_cast<PFLT_FILTER *>(ExAllocatePoolWithTag(NonPagedPool, BufferSize, TAG));
    if (Buffer == nullptr) {
        return;
    }
    RtlZeroMemory(Buffer, BufferSize);

    Status = FltGetFilterInformation(pf, FilterFullInformation, Buffer, BufferSize, &BytesReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, TAG);
        return;
    }

    pfi = static_cast<PFILTER_FULL_INFORMATION>(Buffer);

    FilterName.Buffer = pfi->FilterNameBuffer;
    FilterName.Length = pfi->FilterNameLength;
    FilterName.MaximumLength = pfi->FilterNameLength;//���ټ�2.

    //DbgPrint("FrameID:%d\n", pfi->FrameID);
    //DbgPrint("NumberOfInstances:%d\n", pfi->NumberOfInstances);
    DbgPrint("FilterName:%wZ\n", &FilterName);

    /*
    ��ӡ����������:
    FrameID:0
    NumberOfInstances:5
    FilterName:TFsFlt
    FrameID:0
    NumberOfInstances:6
    FilterName:QQSysMonX64
    FrameID:0
    NumberOfInstances:1
    FilterName:luafv ע��:΢���LUA�ļ����⻯ɸѡ����������.
    */

    ExFreePoolWithTag(Buffer, TAG);
}


void PrintVolumeStandardInformation(PFLT_VOLUME pv)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID  Buffer{};
    ULONG  BufferSize = 0;
    ULONG  BytesReturned = 0;
    PFILTER_VOLUME_STANDARD_INFORMATION pvsi{};
    UNICODE_STRING VolumeName{};

    Status = FltGetVolumeInformation(pv, FilterVolumeStandardInformation, Buffer, BufferSize, &BytesReturned);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return;
        }
    }

    BufferSize = sizeof(PFLT_FILTER) * BytesReturned * 2;//������һ��.
    Buffer = static_cast<PFLT_FILTER *>(ExAllocatePoolWithTag(NonPagedPool, BufferSize, TAG));
    if (Buffer == nullptr) {
        return;
    }
    RtlZeroMemory(Buffer, BufferSize);

    Status = FltGetVolumeInformation(pv, FilterVolumeStandardInformation, Buffer, BufferSize, &BytesReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, TAG);
        return;
    }

    pvsi = static_cast<PFILTER_VOLUME_STANDARD_INFORMATION>(Buffer);

    VolumeName.Buffer = pvsi->FilterVolumeName;
    VolumeName.Length = pvsi->FilterVolumeNameLength;
    VolumeName.MaximumLength = pvsi->FilterVolumeNameLength;//���ټ�2.

    //DbgPrint("Flags:%d\n", pvsi->Flags);
    //DbgPrint("FrameID:%d\n", pvsi->FrameID);
    DbgPrint("VolumeName:%wZ\n", &VolumeName);

    switch (pvsi->FileSystemType) {
    case FLT_FSTYPE_UNKNOWN:
        DbgPrint("FileSystemType :%ls\n", L"Unknown file system type.");
        break;
    case FLT_FSTYPE_RAW:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\RAW.");
        break;
    case FLT_FSTYPE_NTFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Ntfs.");
        break;
    case FLT_FSTYPE_FAT:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Fat.");
        break;
    case FLT_FSTYPE_CDFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Cdfs.");
        break;
    case FLT_FSTYPE_UDFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Udfs.");
        break;
    case FLT_FSTYPE_LANMAN:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\MRxSmb.");
        break;
    case FLT_FSTYPE_WEBDAV:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\MRxDav.");
        break;
    case FLT_FSTYPE_RDPDR:
        DbgPrint("FileSystemType :%ls\n", L"\\Driver\\rdpdr.");
        break;
    case FLT_FSTYPE_NFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\NfsRdr.");
        break;
    case FLT_FSTYPE_MS_NETWARE:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\nwrdr.");
        break;
    case FLT_FSTYPE_NETWARE:
        DbgPrint("FileSystemType :%ls\n", L"Novell NetWare redirector.");
        break;
    case FLT_FSTYPE_BSUDF:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\BsUDF.");
        break;
    case FLT_FSTYPE_MUP:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Mup.");
        break;
    case FLT_FSTYPE_RSFX:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\RsFxDrv.");
        break;
    case FLT_FSTYPE_ROXIO_UDF1:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\cdudf_xp.");
        break;
    case FLT_FSTYPE_ROXIO_UDF2:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\UdfReadr_xp.");
        break;
    case FLT_FSTYPE_ROXIO_UDF3:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\DVDVRRdr_xp.");
        break;
    case FLT_FSTYPE_TACIT:
        DbgPrint("FileSystemType :%ls\n", L"\\Device\\TCFSPSE.");
        break;
    case FLT_FSTYPE_FS_REC:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\Fs_rec.");
        break;
    case FLT_FSTYPE_INCD:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\InCDfs.");
        break;
    case FLT_FSTYPE_INCD_FAT:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\InCDFat.");
        break;
    case FLT_FSTYPE_EXFAT:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\exfat.");
        break;
    case FLT_FSTYPE_PSFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\psfs.");
        break;
    case FLT_FSTYPE_GPFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\gpfs.");
        break;
    case FLT_FSTYPE_NPFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\npfs.");
        break;
    case FLT_FSTYPE_MSFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\msfs.");
        break;
    case FLT_FSTYPE_CSVFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\csvfs.");
        break;
    case FLT_FSTYPE_REFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\refs.");
        break;
    case FLT_FSTYPE_OPENAFS:
        DbgPrint("FileSystemType :%ls\n", L"\\FileSystem\\AFSRedirector.");
        break;
    default:
        DbgPrint("FileSystemType :%ls\n", L"��������!");
        break;
    }

    //����ҲҪ��FltObjectDereference���ͷ�һ��?
    FltObjectDereference(pv);

    ExFreePoolWithTag(Buffer, TAG);
}


void EnumerateInstances(PFLT_FILTER pf)
{
    //FltEnumerateInstances
    //FltGetInstanceInformation �����ȡ��ȫ������,���Է���ʹ��.
    //FltEnumerateInstanceInformationByFilter �����ȡ��ȫ������,���Է���ʹ��.
    //FltEnumerateInstanceInformationByVolume �����ȡ��ȫ������,���Է���ʹ��.

    NTSTATUS Status = STATUS_SUCCESS;
    PFLT_INSTANCE * InstanceList{};
    ULONG  InstanceListSize = 0;
    ULONG  NumberInstancesReturned = 0;
    ULONG i{};

    Status = FltEnumerateInstances(nullptr, pf, InstanceList, InstanceListSize, &NumberInstancesReturned);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return;
        }
    }

    InstanceListSize = sizeof(PFLT_INSTANCE) * NumberInstancesReturned * 2;//������һ��.
    InstanceList = static_cast<PFLT_INSTANCE *>(ExAllocatePoolWithTag(NonPagedPool, InstanceListSize, TAG));
    if (InstanceList == nullptr) {
        return;
    }
    RtlZeroMemory(InstanceList, InstanceListSize);

    Status = FltEnumerateInstances(nullptr, pf, InstanceList, InstanceListSize, &NumberInstancesReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(InstanceList, TAG);
        return;
    }

    for (i = 0; i < NumberInstancesReturned; i++) {
        //��ӡÿ��ʵ������Ϣ.
        //���ź;��豸��һ����,ת��Ϊ���豸�ٴ�ӡ,����Ͳ���ӡ��ϸ��Ϣ��,ֻ��ӡʵ���ĵ�ַ.
        DbgPrint("PFLT_FILTER:%p\tInstances:%p\n", pf, InstanceList[i]);

        FltObjectDereference(InstanceList[i]);
    }

    //����ҲҪ��FltObjectDereference���ͷ�һ��?
    FltObjectDereference(pf);

    ExFreePoolWithTag(InstanceList, TAG);
}


void EnumerateVolumes(PFLT_FILTER pf)
{
    //FltEnumerateVolumes�����ȡȫ��,Ҫö��.
    //FltGetVolumeInformation
    //FltEnumerateVolumeInformation�������,�ǻ�ȡ������,Ҫѭ��.

    NTSTATUS Status = STATUS_SUCCESS;
    PFLT_VOLUME * VolumeList{};
    ULONG  VolumeListSize = 0;
    ULONG  NumberVolumesReturned = 0;
    ULONG i{};

    Status = FltEnumerateVolumes(pf, VolumeList, VolumeListSize, &NumberVolumesReturned);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return;
        }
    }

    VolumeListSize = sizeof(PFLT_VOLUME) * NumberVolumesReturned * 2;//������һ��.

    VolumeList = static_cast<PFLT_VOLUME *>(ExAllocatePoolWithTag(NonPagedPool, VolumeListSize, TAG));
    if (VolumeList == nullptr) {
        return;
    }
    RtlZeroMemory(VolumeList, VolumeListSize);

    Status = FltEnumerateVolumes(pf, VolumeList, VolumeListSize, &NumberVolumesReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(VolumeList, TAG);
        return;
    }

    for (i = 0; i < NumberVolumesReturned; i++) {
        //��ӡÿ�����豸����Ϣ.
        PrintVolumeStandardInformation(VolumeList[i]);

        FltObjectDereference(VolumeList[i]);
    }

    //����ҲҪ��FltObjectDereference���ͷ�һ��?
    FltObjectDereference(pf);

    ExFreePoolWithTag(VolumeList, TAG);
}


NTSTATUS EnumerateFilters()
{
    NTSTATUS Status = STATUS_SUCCESS;
    PFLT_FILTER * FilterList{};
    ULONG FilterListSize = 0;
    ULONG NumberFiltersReturned = 0;
    ULONG i{};

    //Because filters can register at any time, two calls to FltEnumerateFilters are not guaranteed to return the same result.
    //ȷ�����ε���FltEnumerateFilters�ڼ䲻Ҫ���ػ���ж��minifilter.����ʹ��rundown����.
    Status = FltEnumerateFilters(nullptr, FilterListSize, &NumberFiltersReturned);
    if (!NT_SUCCESS(Status)) //#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
    {
        if (Status != STATUS_BUFFER_TOO_SMALL) {
            return Status;
        }
    }

    //����ÿ�γɹ��ĵ���֮�󶼵���:VOID FltObjectDereference(_Inout_  PVOID FltObject);

    FilterListSize = sizeof(PFLT_FILTER) * NumberFiltersReturned * 2;//������һ��.
    FilterList = (PFLT_FILTER *)ExAllocatePoolWithTag(NonPagedPool, FilterListSize, TAG);
    if (FilterList == nullptr) {
        return Status;
    }
    RtlZeroMemory(FilterList, FilterListSize);

    Status = FltEnumerateFilters(FilterList, FilterListSize, &NumberFiltersReturned);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(FilterList, TAG);
        return Status;
    }

    //ж�������Ѿ�ע���minifilter.�����ϱ�Ĩȥδ�����Ľṹ��.������ʱע�͵�.
    //for (i = 0;i < NumberFiltersReturned;i++)
    //{
    //    FltUnregisterFilter(FilterList[i]);//�е���������Զֹͣ������.
    //}

    /*
    ����������о�һЩminifilter����Ϣ
    ����ÿ��minifilter���˵�ÿ�����豸����Ϣ.

    PFLT_FILTER�Ǹ�Ϊ���������ݽṹ,�����汾�Ľṹ��һ.

    0: kd> vertarget
    Windows 7 Kernel Version 7601 (Service Pack 1) MP (2 procs) Free x64
    Built by: 7601.18229.amd64fre.win7sp1_gdr.130801-1533
    Machine Name:
    Kernel base = 0xfffff800`0185f000 PsLoadedModuleList = 0xfffff800`01aa26d0
    Debug session time: Wed Oct 23 16:25:06.039 2013 (UTC + 8:00)
    System Uptime: 0 days 0:04:08.664
    0: kd> dt _FLT_FILTER fffffa80`04306c60
    fltmgr!_FLT_FILTER
    +0x000 Base             : _FLT_OBJECT
    +0x020 Frame            : 0xfffffa80`03f30630 _FLTP_FRAME
    +0x028 Name             : _UNICODE_STRING "TFsFlt"
    +0x038 DefaultAltitude  : _UNICODE_STRING "389700"
    +0x048 Flags            : 2 ( FLTFL_FILTERING_INITIATED )
    +0x050 DriverObject     : 0xfffffa80`042fde70 _DRIVER_OBJECT
    +0x058 InstanceList     : _FLT_RESOURCE_LIST_HEAD
    +0x0d8 VerifierExtension : (null)
    +0x0e0 VerifiedFiltersLink : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
    +0x0f0 FilterUnload     : 0xfffff880`0245f320     long  +0
    +0x0f8 InstanceSetup    : 0xfffff880`0248d0ec     long  +0
    +0x100 InstanceQueryTeardown : 0xfffff880`0248d118     long  +0
    +0x108 InstanceTeardownStart : (null)
    +0x110 InstanceTeardownComplete : 0xfffff880`0248d138     void  +0
    +0x118 SupportedContextsListHead : 0xfffffa80`04306890 _ALLOCATE_CONTEXT_HEADER
    +0x120 SupportedContexts : [6] (null)
    +0x150 PreVolumeMount   : (null)
    +0x158 PostVolumeMount  : (null)
    +0x160 GenerateFileName : (null)
    +0x168 NormalizeNameComponent : (null)
    +0x170 NormalizeNameComponentEx : (null)
    +0x178 NormalizeContextCleanup : (null)
    +0x180 KtmNotification  : (null)
    +0x188 Operations       : 0xfffffa80`04306ef0 _FLT_OPERATION_REGISTRATION
    +0x190 OldDriverUnload  : (null)
    +0x198 ActiveOpens      : _FLT_MUTEX_LIST_HEAD
    +0x1e8 ConnectionList   : _FLT_MUTEX_LIST_HEAD
    +0x238 PortList         : _FLT_MUTEX_LIST_HEAD
    +0x288 PortLock         : _EX_PUSH_LOCK

    �ٸ��������ṹ:
    1: kd> dt _FLT_INSTANCE
    fltmgr!_FLT_INSTANCE
    +0x000 Base             : _FLT_OBJECT
    +0x020 OperationRundownRef : Ptr64 _EX_RUNDOWN_REF_CACHE_AWARE
    +0x028 Volume           : Ptr64 _FLT_VOLUME
    +0x030 Filter           : Ptr64 _FLT_FILTER
    +0x038 Flags            : _FLT_INSTANCE_FLAGS
    +0x040 Altitude         : _UNICODE_STRING
    +0x050 Name             : _UNICODE_STRING
    +0x060 FilterLink       : _LIST_ENTRY
    +0x070 ContextLock      : _EX_PUSH_LOCK
    +0x078 Context          : Ptr64 _CONTEXT_NODE
    +0x080 TransactionContexts : _CONTEXT_LIST_CTRL
    +0x088 TrackCompletionNodes : Ptr64 _TRACK_COMPLETION_NODES
    +0x090 CallbackNodes    : [50] Ptr64 _CALLBACK_NODE
    1: kd> dt _FLT_VOLUME
    fltmgr!_FLT_VOLUME
    +0x000 Base             : _FLT_OBJECT
    +0x020 Flags            : _FLT_VOLUME_FLAGS
    +0x024 FileSystemType   : _FLT_FILESYSTEM_TYPE
    +0x028 DeviceObject     : Ptr64 _DEVICE_OBJECT
    +0x030 DiskDeviceObject : Ptr64 _DEVICE_OBJECT
    +0x038 FrameZeroVolume  : Ptr64 _FLT_VOLUME
    +0x040 VolumeInNextFrame : Ptr64 _FLT_VOLUME
    +0x048 Frame            : Ptr64 _FLTP_FRAME
    +0x050 DeviceName       : _UNICODE_STRING
    +0x060 GuidName         : _UNICODE_STRING
    +0x070 CDODeviceName    : _UNICODE_STRING
    +0x080 CDODriverName    : _UNICODE_STRING
    +0x090 InstanceList     : _FLT_RESOURCE_LIST_HEAD
    +0x110 Callbacks        : _CALLBACK_CTRL
    +0x4f8 ContextLock      : _EX_PUSH_LOCK
    +0x500 VolumeContexts   : _CONTEXT_LIST_CTRL
    +0x508 StreamListCtrls  : _FLT_RESOURCE_LIST_HEAD
    +0x588 FileListCtrls    : _FLT_RESOURCE_LIST_HEAD
    +0x608 NameCacheCtrl    : _NAME_CACHE_VOLUME_CTRL
    +0x6b8 MountNotifyLock  : _ERESOURCE
    +0x720 TargetedOpenActiveCount : Int4B
    +0x728 TxVolContextListLock : _EX_PUSH_LOCK
    +0x730 TxVolContexts    : _TREE_ROOT

    ��������ʹ��:FltEnumerateFilterInformation����FltGetFilterInformation��ȡ������Ϣ.
    */

    //��ӡÿ����������Ϣ,����ѡ��FilterFullInformation����.
    for (i = 0; i < NumberFiltersReturned; i++) {
        PrintFilterFullInformation(FilterList[i]);//��ӡϵͳ�����е�minifilter ����.
        EnumerateInstances(FilterList[i]);//ö��ÿ��minifilter������ÿ�������豸��ʵ��,������Ի�ȡ�������Ϣ.
        EnumerateVolumes(FilterList[i]);//ö��ÿ��minifilter������ÿ�����豸����Ϣ,������Ի�ȡ�������Ϣ,��ʵ������Ĳ��.

        DbgPrint("\n\n");
    }

    /*
    FltEnumerateFilters adds a rundown reference to each of the opaque filter pointers returned in the array that the FilterList parameter points to.
    When these pointers are no longer needed, the caller must release them by calling FltObjectDereference on each one.
    Thus every successful call to FltEnumerateFilters must be matched by a subsequent call to FltObjectDereference for each returned filter pointer.
    */
    for (i = 0; i < NumberFiltersReturned; i++) {
        FltObjectDereference(FilterList[i]);
    }

    ExFreePoolWithTag(FilterList, TAG);

    return Status;
}


/*
Ч������:
0: kd> g
FilterName:TFsFlt
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA8004432C60
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA8004346C60
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA80047D3C60
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA80047B9C60
PFLT_FILTER:FFFFFA800433E010	Instances:FFFFFA80040DF7F0
VolumeName:\Device\Mup
FileSystemType :\FileSystem\Mup.
VolumeName:\Device\HarddiskVolume1
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume2
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume5
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume3
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume4
FileSystemType :\FileSystem\Ntfs.


FilterName:QQSysMonX64
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004A9A760
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004A9D760
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004AA0C50
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004AA0170
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004AA34F0
PFLT_FILTER:FFFFFA8004A8B160	Instances:FFFFFA8004AA4C50
VolumeName:\Device\Mup
FileSystemType :\FileSystem\Mup.
VolumeName:\Device\HarddiskVolume1
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume2
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume5
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume3
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume4
FileSystemType :\FileSystem\Ntfs.


FilterName:luafv
PFLT_FILTER:FFFFFA8004A8A010	Instances:FFFFFA8004A8C010
VolumeName:\Device\Mup
FileSystemType :\FileSystem\Mup.
VolumeName:\Device\HarddiskVolume1
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume2
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume5
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume3
FileSystemType :\FileSystem\Ntfs.
VolumeName:\Device\HarddiskVolume4
FileSystemType :\FileSystem\Ntfs.

��֤һ��:
0: kd> !fltkd.filters

Filter List: fffffa8003e690c0 "Frame 0"
   FLT_FILTER: fffffa800433e010 "TFsFlt" "389700"
      FLT_INSTANCE: fffffa8004432c60 "TFsFlt Instance" "389700"
      FLT_INSTANCE: fffffa8004346c60 "TFsFlt Instance" "389700"
      FLT_INSTANCE: fffffa80047d3c60 "TFsFlt Instance" "389700"
      FLT_INSTANCE: fffffa80047b9c60 "TFsFlt Instance" "389700"
      FLT_INSTANCE: fffffa80040df7f0 "TFsFlt Instance" "389700"
   FLT_FILTER: fffffa8004a8b160 "QQSysMonX64" "327125"
      FLT_INSTANCE: fffffa8004a9a760 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004a9d760 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004aa0c50 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004aa0170 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004aa34f0 "QQSysMonx64 Instance" "327125"
      FLT_INSTANCE: fffffa8004aa4c50 "QQSysMonx64 Instance" "327125"
   FLT_FILTER: fffffa8004a8a010 "luafv" "135000"
      FLT_INSTANCE: fffffa8004a8c010 "luafv" "135000"

0: kd> !fltkd.instance fffffa8004432c60

FLT_INSTANCE: fffffa8004432c60 "TFsFlt Instance" "389700"
   FLT_OBJECT: fffffa8004432c60  [01000000] Instance
      RundownRef               : 0x0000000000000000 (0)
      PointerCount             : 0x00000002
      PrimaryLink              : [fffffa8004a9d770-fffffa800404d108]
   OperationRundownRef      : fffffa80044310b0
Could not read field "Number" of fltmgr!_EX_RUNDOWN_REF_CACHE_AWARE from address: fffffa80044310b0
   Flags                    : [00000000]
   Volume                   : fffffa800404d010 "\Device\HarddiskVolume1"
   Filter                   : fffffa800433e010 "TFsFlt"
   TrackCompletionNodes     : fffffa8004432a20
   ContextLock              : (fffffa8004432cd0)
   Context                  : fffffa800433a770
   CallbackNodes            : (fffffa8004432cf0)
   VolumeLink               : [fffffa8004a9d770-fffffa800404d108]
   FilterLink               : [fffffa8004346cc0-fffffa800433e0d0]

*/


//////////////////////////////////////////////////////////////////////////////////////////////////
