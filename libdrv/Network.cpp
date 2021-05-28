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
        protocol_name = L"未知";//也可打印一个数值。
        break;
    }

    return protocol_name;
}


BOOLEAN LayerIsIPv4(_In_ UINT32 layerID)
/**
Purpose: Determine if the layer is an IPv4 layer.

说明：
1.摘自Windows Filtering Platform Sample工程的KrnlHlprFwpmLayerIsIPv4函数。
2.inspect工程有个GetAddressFamilyForLayer函数，功能类似，但是简单。
3.DDProxy工程是直接和FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4比较的，这个最简单。
*/
{
    BOOLEAN isIPv4 = FALSE;

    if (layerID == FWPS_LAYER_INBOUND_IPPACKET_V4 ||
        layerID == FWPS_LAYER_INBOUND_IPPACKET_V4_DISCARD ||
        layerID == FWPS_LAYER_OUTBOUND_IPPACKET_V4 ||
        layerID == FWPS_LAYER_OUTBOUND_IPPACKET_V4_DISCARD ||
        layerID == FWPS_LAYER_IPFORWARD_V4 ||
        layerID == FWPS_LAYER_IPFORWARD_V4_DISCARD ||
        layerID == FWPS_LAYER_INBOUND_TRANSPORT_V4 ||
        layerID == FWPS_LAYER_INBOUND_TRANSPORT_V4_DISCARD ||
        layerID == FWPS_LAYER_OUTBOUND_TRANSPORT_V4 ||
        layerID == FWPS_LAYER_OUTBOUND_TRANSPORT_V4_DISCARD ||
        layerID == FWPS_LAYER_STREAM_V4 ||
        layerID == FWPS_LAYER_STREAM_V4_DISCARD ||
        layerID == FWPS_LAYER_DATAGRAM_DATA_V4 ||
        layerID == FWPS_LAYER_DATAGRAM_DATA_V4_DISCARD ||
        layerID == FWPS_LAYER_INBOUND_ICMP_ERROR_V4 ||
        layerID == FWPS_LAYER_INBOUND_ICMP_ERROR_V4_DISCARD ||
        layerID == FWPS_LAYER_OUTBOUND_ICMP_ERROR_V4 ||
        layerID == FWPS_LAYER_OUTBOUND_ICMP_ERROR_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4 ||
        layerID == FWPS_LAYER_ALE_RESOURCE_ASSIGNMENT_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_AUTH_LISTEN_V4 ||
        layerID == FWPS_LAYER_ALE_AUTH_LISTEN_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_AUTH_CONNECT_V4 ||
        layerID == FWPS_LAYER_ALE_AUTH_CONNECT_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4 ||
        layerID == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4_DISCARD ||
        layerID == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 ||
        layerID == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4_DISCARD ||
#if(NTDDI_VERSION >= NTDDI_WIN7)
        layerID == FWPS_LAYER_NAME_RESOLUTION_CACHE_V4 ||
        layerID == FWPS_LAYER_ALE_RESOURCE_RELEASE_V4 ||
        layerID == FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4 ||
        layerID == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4 ||
        layerID == FWPS_LAYER_ALE_BIND_REDIRECT_V4 ||
        layerID == FWPS_LAYER_STREAM_PACKET_V4 ||
#if(NTDDI_VERSION >= NTDDI_WIN8)
        layerID == FWPS_LAYER_INGRESS_VSWITCH_TRANSPORT_V4 ||
        layerID == FWPS_LAYER_EGRESS_VSWITCH_TRANSPORT_V4 ||
#endif // (NTDDI_VERSION >= NTDDI_WIN8)
#endif // (NTDDI_VERSION >= NTDDI_WIN7)
        layerID == FWPS_LAYER_IPSEC_KM_DEMUX_V4 ||
        layerID == FWPS_LAYER_IPSEC_V4 ||
        layerID == FWPS_LAYER_IKEEXT_V4) {
        isIPv4 = TRUE;
    }

    return isIPv4;
}


NTSTATUS AleEndpointEnum()
/*
目的：演示FwpsAleEndpointEnum的用法。
注意：编译的平台和运行的平台。
说明：Ale的Endpoint，这是什么呢？
      类似TCPView.exe不停的显示和更新，
      当然这个函数每次获取的值/数量也是不同的。
      注意：这个不是本地侦听的端口信息，而是已经建立连接的连接信息。

made by correy
made at 2016.08.31.
homepage:http://correy.webs.com
*/
{
    HANDLE gEngineHandle;
    NTSTATUS Status = STATUS_SUCCESS;
    FWPM_SESSION0 session = {0};
    FWPS_ALE_ENDPOINT_ENUM_TEMPLATE0 enumTemplate;//编译为WIN 7版本，VISTA是没有这个变量的。
    HANDLE enumHandle;
    FWPS_ALE_ENDPOINT_PROPERTIES0 ** entries;
    UINT32                        numEntriesReturned;
    UINT32 calloutIndex = 0;
    UNICODE_STRING appId = {0};

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    Status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &gEngineHandle);
    ASSERT(NT_SUCCESS(Status));

    RtlZeroMemory(&enumTemplate, sizeof(FWPS_ALE_ENDPOINT_ENUM_TEMPLATE0));
    Status = FwpsAleEndpointCreateEnumHandle0(gEngineHandle, &enumTemplate, &enumHandle);//Available starting with Windows 7
    ASSERT(NT_SUCCESS(Status));

    Status = FwpsAleEndpointEnum0(gEngineHandle, enumHandle, 0xFFFFFFFF, &entries, &numEntriesReturned);//Available starting with Windows 7
    ASSERT(NT_SUCCESS(Status));

    KdPrint(("numEntriesReturned:0x%x.\n\n\n", numEntriesReturned));

    for (; calloutIndex < numEntriesReturned; calloutIndex++) {
        KdPrint(("calloutIndex:0x%x.\n", (calloutIndex + 1)));

        if (entries[calloutIndex]->ipVersion == FWP_IP_VERSION_V4) {
            UINT32 l4a = RtlUlongByteSwap((ULONG)entries[calloutIndex]->localV4Address);
            UINT32 r4a = RtlUlongByteSwap((ULONG)entries[calloutIndex]->remoteV4Address);
            wchar_t localV4Address[MAX_ADDRESS_STRING_LENGTH] = {0};
            wchar_t remoteV4Address[MAX_ADDRESS_STRING_LENGTH] = {0};

            RtlIpv4AddressToStringW((const struct in_addr *)&l4a, localV4Address);
            RtlIpv4AddressToStringW((const struct in_addr *)&r4a, remoteV4Address);

            KdPrint(("ipVersion:FWP_IP_VERSION_V4.\n"));
            KdPrint(("localV4Address:%ws.\n", localV4Address));
            KdPrint(("remoteV4Address:%ws.\n", remoteV4Address));
        } else if (entries[calloutIndex]->ipVersion == FWP_IP_VERSION_V6) {
            /*
            这个IPV6的地址的字节序需要转换不？不需要，因为它需要的是网络地址。
            最大是RtlUlonglongByteSwap，64-bit，但是IPv6 is 128 bits。
            难道要用这个函数两次，两次的也不符合，自己写个函数？自己可以验证下。
            */
            wchar_t localV6Address[MAX_ADDRESS_STRING_LENGTH] = {0};
            wchar_t remoteV6Address[MAX_ADDRESS_STRING_LENGTH] = {0};

            RtlIpv6AddressToStringW((const struct in6_addr *)&entries[calloutIndex]->localV6Address, localV6Address);
            RtlIpv6AddressToStringW((const struct in6_addr *)&entries[calloutIndex]->remoteV6Address, remoteV6Address);

            KdPrint(("ipVersion:FWP_IP_VERSION_V6.\n"));
            KdPrint(("localV6Address:%ws.\n", localV6Address));
            KdPrint(("remoteV6Address:%ws.\n", remoteV6Address));
        } else {
            KdBreakPoint();
        }

        KdPrint(("ipProtocol:%ws.\n", GetProtocolName(entries[calloutIndex]->ipProtocol)));
        KdPrint(("localPort:%d.\n", entries[calloutIndex]->localPort));
        KdPrint(("remotePort:%d.\n", entries[calloutIndex]->remotePort));
        KdPrint(("localTokenModifiedId:0x%llx.\n", entries[calloutIndex]->localTokenModifiedId));
        KdPrint(("mmSaId:0x%llx.\n", entries[calloutIndex]->mmSaId));
        KdPrint(("qmSaId:0x%llx.\n", entries[calloutIndex]->qmSaId));
        KdPrint(("ipsecStatus:0x%x.\n", entries[calloutIndex]->ipsecStatus));
        KdPrint(("flags:0x%x.\n", entries[calloutIndex]->flags));

        appId.Buffer = (PWCH)&entries[calloutIndex]->appId.data[0];
        appId.Length = (USHORT)entries[calloutIndex]->appId.size;
        appId.MaximumLength = appId.Length;
        KdPrint(("appId:%wZ.\n", &appId));//进程的完整路径（NT式的设备路径）。一个特殊是：System。

        KdPrint(("\n"));
    }

    FwpmFreeMemory((VOID **)&entries);
    Status = FwpsAleEndpointDestroyEnumHandle0(gEngineHandle, enumHandle);//Available starting with Windows 7
    ASSERT(NT_SUCCESS(Status));

    FwpmEngineClose0(gEngineHandle);

    return Status;
}


ADDRESS_FAMILY GetAddressFamilyForLayer(_In_ UINT16 layerId)
{
    ADDRESS_FAMILY addressFamily;

    switch (layerId) {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
    case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
    case FWPS_LAYER_INBOUND_IPPACKET_V4:
        addressFamily = AF_INET;
        break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
    case FWPS_LAYER_INBOUND_TRANSPORT_V6:
    case FWPS_LAYER_INBOUND_IPPACKET_V6:
    case FWPS_LAYER_OUTBOUND_IPPACKET_V6:
        addressFamily = AF_INET6;
        break;
    default:
        addressFamily = AF_UNSPEC;
        ASSERT(0);
    }

    return addressFamily;
}


FWP_DIRECTION GetPacketDirectionForLayer(_In_ UINT16 layerId)
{
    FWP_DIRECTION direction;

    switch (layerId) {
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
    case FWPS_LAYER_OUTBOUND_IPPACKET_V4:
    case FWPS_LAYER_OUTBOUND_IPPACKET_V6:
        direction = FWP_DIRECTION_OUTBOUND;
        break;
    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
    case FWPS_LAYER_INBOUND_TRANSPORT_V6:
    case FWPS_LAYER_INBOUND_IPPACKET_V4:
    case FWPS_LAYER_INBOUND_IPPACKET_V6:
        direction = FWP_DIRECTION_INBOUND;
        break;
    default:
        direction = FWP_DIRECTION_MAX;
        ASSERT(0);
    }

    return direction;
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
    PVOID  InterfaceBuffer = 0;
    ULONG  InterfaceBufferLength = 0;
    ULONG  BytesNeeded = 0;//sizeof(NDIS_ENUM_FILTERS) + sizeof(NDIS_FILTER_INTERFACE) * 9;//其实还可以设置更小点。
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
功能：此函数用于TDI过滤驱动中获取本地的IP（IPv4/6）地址。

注意：
1.此函数的运行时机。
2.此函数的运行环境（IRQL和锁等）。
3.此函数的输入参数，特别说明TDI的DeviceObject/FileObject分好几种（至少三种），要严格的区分。
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
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_UNICASTIPADDRESS_TABLE Table = NULL;

    status = GetUnicastIpAddressTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_UNICASTIPADDRESS_ROW pTable = &Table->Table[i];

        status = GetUnicastIpAddressEntry(pTable);
        //status = SetUnicastIpAddressEntry(pTable);        

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

    return status;
}


NTSTATUS EnumIpPathTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552559(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552556(v=vs.85)
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_IPPATH_TABLE Table = NULL;

    status = GetIpPathTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPPATH_ROW pTable = &Table->Table[i];

        status = GetIpPathEntry(pTable);

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

    return status;
}


NTSTATUS EnumAnycastIpAddressTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552508(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552504(v=vs.85)
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_ANYCASTIPADDRESS_TABLE Table = NULL;

    status = GetAnycastIpAddressTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_ANYCASTIPADDRESS_ROW pTable = &Table->Table[i];

        status = GetAnycastIpAddressEntry(pTable);

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

    return status;
}


NTSTATUS EnumIfTable2()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552524(v=vs.85)

Your driver can use a similar function, GetIfTable2Ex, 
to specify the level of interfaces to return. 
A call to the GetIfTable2Ex function with the Level parameter set to MibIfTableNormal retrieves the same results as calling the GetIfTable2 function.
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_IF_TABLE2 Table = NULL;

    status = GetIfTable2(&Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IF_ROW2 pTable = &Table->Table[i];

        status = GetIfEntry2(pTable);

        KdPrint(("Alias:%ls.\r\n", pTable->Alias));
        KdPrint(("Description:%ls.\r\n", pTable->Description));
    }

    FreeMibTable(Table);

    return status;
}


NTSTATUS EnumIfTable2Ex()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552528(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552517(v=vs.85)
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_IF_TABLE2 Table = NULL;

    status = GetIfTable2Ex(MibIfTableRaw, &Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IF_ROW2 pTable = &Table->Table[i];

        status = GetIfEntry2(pTable);

        KdPrint(("Alias:%ls.\r\n", pTable->Alias));
        KdPrint(("Description:%ls.\r\n", pTable->Description));
    }

    FreeMibTable(Table);

    return status;
}


NTSTATUS EnumIpInterfaceTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552543(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552540(v=vs.85)
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_IPINTERFACE_TABLE  Table = NULL;

    status = GetIpInterfaceTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPINTERFACE_ROW pTable = &Table->Table[i];

        status = GetIpInterfaceEntry(pTable);

        KdPrint(("Family:%d.\r\n", pTable->Family));
    }

    FreeMibTable(Table);

    return status;
}


NTSTATUS EnumIpForwardTable2()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552536(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552535(v=vs.85)
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_IPFORWARD_TABLE2   Table = NULL;

    status = GetIpForwardTable2(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPFORWARD_ROW2 pTable = &Table->Table[i];

        status = GetIpForwardEntry2(pTable);

        KdPrint(("Loopback:%d.\r\n", pTable->Loopback));
    }

    FreeMibTable(Table);

    return status;
}


NTSTATUS EnumIfStackTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552521(v=vs.85)
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_IFSTACK_TABLE    Table = NULL;

    status = GetIfStackTable(&Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IFSTACK_ROW pTable = &Table->Table[i];

        KdPrint(("HigherLayerInterfaceIndex:%d.\r\n", pTable->HigherLayerInterfaceIndex));
        KdPrint(("LowerLayerInterfaceIndex:%d.\r\n", pTable->LowerLayerInterfaceIndex));
    }

    FreeMibTable(Table);

    return status;
}


NTSTATUS EnumIpNetTable2()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552551(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552546(v=vs.85)
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_IPNET_TABLE2 Table = NULL;

    status = GetIpNetTable2(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_IPNET_ROW2 pTable = &Table->Table[i];

        status = GetIpNetEntry2(pTable);

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

    return status;
}


NTSTATUS EnumMulticastIpAddressTable()
/*
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552570(v=vs.85)
https://docs.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff552565(v=vs.85)
*/
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMIB_MULTICASTIPADDRESS_TABLE  Table = NULL;

    status = GetMulticastIpAddressTable(AF_UNSPEC, &Table);
    ASSERT(NT_SUCCESS(status));
    ASSERT(Table);

    for (ULONG i = 0; i < Table->NumEntries; i++) {
        PMIB_MULTICASTIPADDRESS_ROW pTable = &Table->Table[i];

        status = GetMulticastIpAddressEntry(pTable);

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

    return status;
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
