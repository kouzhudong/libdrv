/*

WFP的函数可用x fwpkclnt!*查看或搜索。
*/


#pragma once


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


BOOLEAN LayerIsIPv4(_In_ UINT32 layerID);

NTSTATUS GetUnicastIpAddressTableEx();

NTSTATUS AleEndpointEnum();

ADDRESS_FAMILY GetAddressFamilyForLayer(_In_ UINT16 layerId);

FWP_DIRECTION GetPacketDirectionForLayer(_In_ UINT16 layerId);

VOID EnumerateFilterModules(NDIS_HANDLE  NdisHandle);

NTSTATUS TdiQueryAddress(IN PDEVICE_OBJECT DeviceObject,
                         IN PFILE_OBJECT FileObject,
                         OUT PTDI_ADDRESS_INFO LocalAddress);

EXTERN_C_END
