#include "pch.h"
#include "Network.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


const wchar_t * GetProtocolName(UINT8 protocol)
{
    const wchar_t * protocol_name = nullptr;

    switch (protocol) {
    case IPPROTO_TCP:
        protocol_name = L"TCP";
        break;
    case IPPROTO_UDP:
        protocol_name = L"UDP";
        break;
    case IPPROTO_IPV4:
        protocol_name = L"IPV4";
        break;
    case IPPROTO_IPV6:
        protocol_name = L"IPV6";
        break;
    case IPPROTO_ICMP:
        protocol_name = L"ICMP";
        break;
    case IPPROTO_IGMP:
        protocol_name = L"IGMP";
        break;
    case IPPROTO_ICMPV6:
        protocol_name = L"ICMPV6";
        break;
    default:
        protocol_name = L"未知";//也可打印一个数值。
        break;
    }

    return protocol_name;
}


VOID EnumerateFilterModules(NDIS_HANDLE  NdisHandle)
/*
If the handle is an NDIS miniport adapter handle,
NDIS returns information about all the interface modules that are currently attached to the miniport adapter,
starting with the top-most filter module.

If the handle is an NDIS binding handle,
NDIS returns information about all the filter modules that are currently attached to the underlying miniport adapter,
starting with the top-most filter module.

If the handle is an NDIS filter module handle,
NDIS returns information about all the filter modules that are currently attached to the underlying miniport adapter to which the specified filter module is attached,
starting with the top-most filter module.

这个函数写好了，但是用在哪儿呢？
这里以NDISLWF为例。
在驱动入口的NdisFRegisterFilterDriver函数之后，
但是传递哪个参数呢？全局变量和这个函数都有两个类型是NDIS_HANDLE，都使用的结果是都不行，返回c000000d，参数不对。在收发包的地方也是如此。
最后在AttachHandler的处理函数处用它的第一个参数成功。注意：这里会调用多次。

made by correy
made at 2014.12.25
*/
{
    NDIS_STATUS Status = STATUS_UNSUCCESSFUL;
    PVOID  InterfaceBuffer{};
    ULONG  InterfaceBufferLength = 0;
    ULONG  BytesNeeded = 0;//sizeof(NDIS_ENUM_FILTERS) + sizeof(NDIS_FILTER_INTERFACE) * 9;//其实还可以设置更小点。
    ULONG  BytesWritten = 0;
    PNDIS_ENUM_FILTERS pefs{};
    PNDIS_FILTER_INTERFACE pfi{};
    ULONG i = 0;

    Status = NdisEnumerateFilterModules(NdisHandle, InterfaceBuffer, InterfaceBufferLength, &BytesNeeded, &BytesWritten);
    if (Status != NDIS_STATUS_BUFFER_TOO_SHORT) {
        return;
    }

    InterfaceBuffer = ExAllocatePoolWithTag(NonPagedPool, BytesNeeded, TAG);
    if (InterfaceBuffer == nullptr) {
        return;// STATUS_INSUFFICIENT_RESOURCES ;
    }
    RtlZeroMemory(InterfaceBuffer, BytesNeeded);

    InterfaceBufferLength = BytesNeeded;

    Status = NdisEnumerateFilterModules(NdisHandle, InterfaceBuffer, InterfaceBufferLength, &BytesNeeded, &BytesWritten);
    if (Status != NDIS_STATUS_SUCCESS) {
        ExFreePoolWithTag(InterfaceBuffer, TAG);
        return;
    }

    pefs = (PNDIS_ENUM_FILTERS)InterfaceBuffer;

    for (; i < pefs->NumberOfFilters; i++) {
        pfi = &pefs->Filter[i];

        KdPrint(("FilterClass:%wZ\n", &pfi->FilterClass));
        KdPrint(("FilterInstanceName:%wZ\n", &pfi->FilterInstanceName));
    }

    ExFreePoolWithTag(InterfaceBuffer, TAG);
}


NTSTATUS TdiQueryAddress(IN PDEVICE_OBJECT DeviceObject, IN PFILE_OBJECT FileObject, OUT PTDI_ADDRESS_INFO LocalAddress)
/*
功能：此函数用于TDI过滤驱动中获取本地的IP（IPv4/6）地址。

注意：
1.此函数的运行时机。
2.此函数的运行环境（IRQL和锁等）。
3.此函数的输入参数，特别说明TDI的DeviceObject/FileObject分好几种（至少三种），要严格的区分。
*/
{
    KEVENT Event{};
    IO_STATUS_BLOCK IoStatus{};
    PIRP Irp{};
    PMDL Mdl{};
    NTSTATUS Status{};

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION, DeviceObject, FileObject, &Event, &IoStatus);
    if (Irp == 0) {
        KdPrint(("__FILE__:%s, __FUNCTION__:%s, __LINE__:%d.\r\n", __FILE__, __FUNCTION__, __LINE__));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Mdl = IoAllocateMdl(LocalAddress, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, Irp);
    if (!Mdl) {
        KdPrint(("__FILE__:%s, __FUNCTION__:%s, __LINE__:%d.\r\n", __FILE__, __FUNCTION__, __LINE__));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(Mdl);
        Mdl = nullptr;
    }

    TdiBuildQueryInformation(Irp, DeviceObject, FileObject, nullptr, nullptr, TDI_QUERY_ADDRESS_INFO, Mdl);

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        Status = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, nullptr);
    }

    if (!NT_SUCCESS(Status)) {
        Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
    }

    return Status == STATUS_SUCCESS ? IoStatus.Status : Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS EnumUnicastIpAddressTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552594(v=vs.85)
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_UNICASTIPADDRESS_TABLE Table = nullptr;

    Status = GetUnicastIpAddressTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_UNICASTIPADDRESS_ROW pTable = &Table->Table[i];

        Status = GetUnicastIpAddressEntry(pTable);
        //Status = SetUnicastIpAddressEntry(pTable);        

        switch (pTable->Address.si_family) {
        case AF_INET:
        {
            WCHAR S[32 + 1] = {0};
            (void)RtlIpv4AddressToString(&pTable->Address.Ipv4.sin_addr, S);

            KdPrint(("ipv4:%ls.\r\n", S));
        }
        break;
        case AF_INET6:
        {
            WCHAR S[MAX_ADDRESS_STRING_LENGTH + 1] = {0};
            (void)RtlIpv6AddressToStringW(&pTable->Address.Ipv6.sin6_addr, S);

            KdPrint(("ipv6:%ws.\r\n", S));
        }
        break;
        default:
            ASSERT(FALSE);
            break;
        }
    }

    FreeMibTable(Table);

    return Status;
}


NTSTATUS EnumIpPathTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552559(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552556(v=vs.85)
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_IPPATH_TABLE Table = nullptr;

    Status = GetIpPathTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPPATH_ROW pTable = &Table->Table[i];

        Status = GetIpPathEntry(pTable);

        switch (pTable->Source.si_family) {
        case AF_INET:
        {
            WCHAR S[32 + 1] = {0};
            (void)RtlIpv4AddressToString(&pTable->Source.Ipv4.sin_addr, S);

            KdPrint(("ipv4:%ls.\r\n", S));
        }
        break;
        case AF_INET6:
        {
            WCHAR S[MAX_ADDRESS_STRING_LENGTH + 1] = {0};
            (void)RtlIpv6AddressToStringW(&pTable->Source.Ipv6.sin6_addr, S);

            KdPrint(("ipv6:%ws.\r\n", S));
        }
        break;
        default:
            ASSERT(FALSE);
            break;
        }

        switch (pTable->Destination.si_family) {
        case AF_INET:
        {
            WCHAR S[32 + 1] = {0};
            (void)RtlIpv4AddressToString(&pTable->Destination.Ipv4.sin_addr, S);

            KdPrint(("ipv4:%ls.\r\n", S));
        }
        break;
        case AF_INET6:
        {
            WCHAR S[MAX_ADDRESS_STRING_LENGTH + 1] = {0};
            (void)RtlIpv6AddressToStringW(&pTable->Destination.Ipv6.sin6_addr, S);

            KdPrint(("ipv6:%ws.\r\n", S));
        }
        break;
        default:
            ASSERT(FALSE);
            break;
        }
    }

    FreeMibTable(Table);

    return Status;
}


NTSTATUS EnumAnycastIpAddressTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552508(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552504(v=vs.85)
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_ANYCASTIPADDRESS_TABLE Table = nullptr;

    Status = GetAnycastIpAddressTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_ANYCASTIPADDRESS_ROW pTable = &Table->Table[i];

        Status = GetAnycastIpAddressEntry(pTable);

        switch (pTable->Address.si_family) {
        case AF_INET:
        {
            WCHAR S[32 + 1] = {0};
            (void)RtlIpv4AddressToString(&pTable->Address.Ipv4.sin_addr, S);

            KdPrint(("ipv4:%ls.\r\n", S));
        }
        break;
        case AF_INET6:
        {
            WCHAR S[MAX_ADDRESS_STRING_LENGTH + 1] = {0};
            (void)RtlIpv6AddressToStringW(&pTable->Address.Ipv6.sin6_addr, S);

            KdPrint(("ipv6:%ws.\r\n", S));
        }
        break;
        default:
            ASSERT(FALSE);
            break;
        }
    }

    FreeMibTable(Table);

    return Status;
}


NTSTATUS EnumIfTable2()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552524(v=vs.85)

Your driver can use a similar function, GetIfTable2Ex,
to specify the level of interfaces to return.
A call to the GetIfTable2Ex function with the Level parameter set to MibIfTableNormal retrieves the same results as calling the GetIfTable2 function.
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_IF_TABLE2 Table = nullptr;

    Status = GetIfTable2(&Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IF_ROW2 pTable = &Table->Table[i];

        Status = GetIfEntry2(pTable);

        KdPrint(("Alias:%ls.\r\n", pTable->Alias));
        KdPrint(("Description:%ls.\r\n", pTable->Description));
    }

    FreeMibTable(Table);

    return Status;
}


NTSTATUS EnumIfTable2Ex()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552528(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552517(v=vs.85)
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_IF_TABLE2 Table = nullptr;

    Status = GetIfTable2Ex(MibIfTableRaw, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IF_ROW2 pTable = &Table->Table[i];

        Status = GetIfEntry2(pTable);

        KdPrint(("Alias:%ls.\r\n", pTable->Alias));
        KdPrint(("Description:%ls.\r\n", pTable->Description));
    }

    FreeMibTable(Table);

    return Status;
}


NTSTATUS EnumIpInterfaceTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552543(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552540(v=vs.85)
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_IPINTERFACE_TABLE  Table = nullptr;

    Status = GetIpInterfaceTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPINTERFACE_ROW pTable = &Table->Table[i];

        Status = GetIpInterfaceEntry(pTable);

        KdPrint(("Family:%u.\r\n", pTable->Family));
    }

    FreeMibTable(Table);

    return Status;
}


NTSTATUS EnumIpForwardTable2()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552536(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552535(v=vs.85)
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_IPFORWARD_TABLE2   Table = nullptr;

    Status = GetIpForwardTable2(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPFORWARD_ROW2 pTable = &Table->Table[i];

        Status = GetIpForwardEntry2(pTable);

        KdPrint(("Loopback:%u.\r\n", pTable->Loopback));
    }

    FreeMibTable(Table);

    return Status;
}


NTSTATUS EnumIfStackTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552521(v=vs.85)
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_IFSTACK_TABLE    Table = nullptr;

    Status = GetIfStackTable(&Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IFSTACK_ROW pTable = &Table->Table[i];

    #if !DBG 
        DBG_UNREFERENCED_LOCAL_VARIABLE(pTable);
    #endif

        KdPrint(("HigherLayerInterfaceIndex:%u.\r\n", pTable->HigherLayerInterfaceIndex));
        KdPrint(("LowerLayerInterfaceIndex:%u.\r\n", pTable->LowerLayerInterfaceIndex));
    }

    FreeMibTable(Table);

    return Status;
}


NTSTATUS EnumIpNetTable2()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552551(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552546(v=vs.85)
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_IPNET_TABLE2 Table = nullptr;

    Status = GetIpNetTable2(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPNET_ROW2 pTable = &Table->Table[i];

        Status = GetIpNetEntry2(pTable);

        switch (pTable->Address.si_family) {
        case AF_INET:
        {
            WCHAR S[32 + 1] = {0};
            (void)RtlIpv4AddressToString(&pTable->Address.Ipv4.sin_addr, S);

            KdPrint(("ipv4:%ls.\r\n", S));
        }
        break;
        case AF_INET6:
        {
            WCHAR S[MAX_ADDRESS_STRING_LENGTH + 1] = {0};
            (void)RtlIpv6AddressToStringW(&pTable->Address.Ipv6.sin6_addr, S);

            KdPrint(("ipv6:%ws.\r\n", S));
        }
        break;
        default:
            ASSERT(FALSE);
            break;
        }
    }

    FreeMibTable(Table);

    return Status;
}


NTSTATUS EnumMulticastIpAddressTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552570(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552565(v=vs.85)
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PMIB_MULTICASTIPADDRESS_TABLE  Table = nullptr;

    Status = GetMulticastIpAddressTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_MULTICASTIPADDRESS_ROW pTable = &Table->Table[i];

        Status = GetMulticastIpAddressEntry(pTable);

        switch (pTable->Address.si_family) {
        case AF_INET:
        {
            WCHAR S[32 + 1] = {0};
            (void)RtlIpv4AddressToString(&pTable->Address.Ipv4.sin_addr, S);

            KdPrint(("ipv4:%ls.\r\n", S));
        }
        break;
        case AF_INET6:
        {
            WCHAR S[MAX_ADDRESS_STRING_LENGTH + 1] = {0};
            (void)RtlIpv6AddressToStringW(&pTable->Address.Ipv6.sin6_addr, S);

            KdPrint(("ipv6:%ws.\r\n", S));
        }
        break;
        default:
            ASSERT(FALSE);
            break;
        }
    }

    FreeMibTable(Table);

    return Status;
}


void NetioEnumTest()
{
    EnumUnicastIpAddressTable();

    EnumIpPathTable();

    EnumAnycastIpAddressTable();

    EnumIfTable2();

    EnumIfTable2Ex();

    EnumIpInterfaceTable();

    EnumIpForwardTable2();

    EnumIfStackTable();

    EnumIpNetTable2();

    EnumMulticastIpAddressTable();
}


//////////////////////////////////////////////////////////////////////////////////////////////////
