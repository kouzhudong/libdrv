#include "pch.h"
#include "Network.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


const wchar_t * GetProtocolName(UINT8 protocol)
{
    wchar_t * protocol_name = 0;

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
        protocol_name = L"δ֪";//Ҳ�ɴ�ӡһ����ֵ��
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

�������д���ˣ����������Ķ��أ�
������NDISLWFΪ����
��������ڵ�NdisFRegisterFilterDriver����֮��
���Ǵ����ĸ������أ�ȫ�ֱ��������������������������NDIS_HANDLE����ʹ�õĽ���Ƕ����У�����c000000d���������ԡ����շ����ĵط�Ҳ����ˡ�
�����AttachHandler�Ĵ������������ĵ�һ�������ɹ���ע�⣺�������ö�Ρ�

made by correy
made at 2014.12.25
*/
{
    NDIS_STATUS Status = STATUS_UNSUCCESSFUL;
    PVOID  InterfaceBuffer = 0;
    ULONG  InterfaceBufferLength = 0;
    ULONG  BytesNeeded = 0;//sizeof(NDIS_ENUM_FILTERS) + sizeof(NDIS_FILTER_INTERFACE) * 9;//��ʵ���������ø�С�㡣
    ULONG  BytesWritten = 0;
    PNDIS_ENUM_FILTERS pefs = 0;
    PNDIS_FILTER_INTERFACE pfi = 0;
    ULONG i = 0;

    Status = NdisEnumerateFilterModules(NdisHandle, InterfaceBuffer, InterfaceBufferLength, &BytesNeeded, &BytesWritten);
    if (Status != NDIS_STATUS_BUFFER_TOO_SHORT) {
        return;
    }

    InterfaceBuffer = ExAllocatePoolWithTag(NonPagedPool, BytesNeeded, TAG);
    if (InterfaceBuffer == NULL) {
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


NTSTATUS TdiQueryAddress(IN PDEVICE_OBJECT DeviceObject,
                         IN PFILE_OBJECT FileObject,
                         OUT PTDI_ADDRESS_INFO LocalAddress
)
/*
���ܣ��˺�������TDI���������л�ȡ���ص�IP��IPv4/6����ַ��

ע�⣺
1.�˺���������ʱ����
2.�˺��������л�����IRQL�����ȣ���
3.�˺���������������ر�˵��TDI��DeviceObject/FileObject�ֺü��֣��������֣���Ҫ�ϸ�����֡�
*/
{
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    PIRP Irp;
    PMDL Mdl;
    NTSTATUS Status;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION, DeviceObject, FileObject, &Event, &IoStatus);
    if (Irp == 0) {
        KdPrint(("__FILE__:%s, __FUNCTION__:%s, __LINE__:%d.\r\n", __FILE__, __FUNCTION__, __LINE__));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Mdl = IoAllocateMdl(LocalAddress, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, Irp);
    if (Mdl == 0) {
        KdPrint(("__FILE__:%s, __FUNCTION__:%s, __LINE__:%d.\r\n", __FILE__, __FUNCTION__, __LINE__));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(Mdl);
        Mdl = NULL;
    }

    TdiBuildQueryInformation(Irp, DeviceObject, FileObject, 0, 0, TDI_QUERY_ADDRESS_INFO, Mdl);

    Status = IoCallDriver(DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        Status = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, 0);
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
    PMIB_UNICASTIPADDRESS_TABLE Table = NULL;

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
    PMIB_IPPATH_TABLE Table = NULL;

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
    PMIB_ANYCASTIPADDRESS_TABLE Table = NULL;

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
    PMIB_IF_TABLE2 Table = NULL;

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
    PMIB_IF_TABLE2 Table = NULL;

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
    PMIB_IPINTERFACE_TABLE  Table = NULL;

    Status = GetIpInterfaceTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPINTERFACE_ROW pTable = &Table->Table[i];

        Status = GetIpInterfaceEntry(pTable);

        KdPrint(("Family:%d.\r\n", pTable->Family));
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
    PMIB_IPFORWARD_TABLE2   Table = NULL;

    Status = GetIpForwardTable2(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPFORWARD_ROW2 pTable = &Table->Table[i];

        Status = GetIpForwardEntry2(pTable);

        KdPrint(("Loopback:%d.\r\n", pTable->Loopback));
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
    PMIB_IFSTACK_TABLE    Table = NULL;

    Status = GetIfStackTable(&Table);
    ASSERT(NT_SUCCESS(Status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IFSTACK_ROW pTable = &Table->Table[i];

#if !DBG 
        DBG_UNREFERENCED_LOCAL_VARIABLE(pTable);
#endif

        KdPrint(("HigherLayerInterfaceIndex:%d.\r\n", pTable->HigherLayerInterfaceIndex));
        KdPrint(("LowerLayerInterfaceIndex:%d.\r\n", pTable->LowerLayerInterfaceIndex));
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
    PMIB_IPNET_TABLE2 Table = NULL;

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
    PMIB_MULTICASTIPADDRESS_TABLE  Table = NULL;

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
