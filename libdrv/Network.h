/*

这里不包含WFP的代码，这个见另一个工程。
*/


#pragma once


//////////////////////////////////////////////////////////////////////////////////////////////////


EXTERN_C_START


VOID EnumerateFilterModules(NDIS_HANDLE  NdisHandle);

NTSTATUS TdiQueryAddress(IN PDEVICE_OBJECT DeviceObject, IN PFILE_OBJECT FileObject, OUT PTDI_ADDRESS_INFO LocalAddress);

NTSTATUS EnumUnicastIpAddressTable();

NTSTATUS EnumIpPathTable();

NTSTATUS EnumAnycastIpAddressTable();

NTSTATUS EnumIfTable2();

NTSTATUS EnumIfTable2Ex();

NTSTATUS EnumIpInterfaceTable();

NTSTATUS EnumIpForwardTable2();

NTSTATUS EnumIfStackTable();

NTSTATUS EnumIpNetTable2();

NTSTATUS EnumMulticastIpAddressTable();

void NetioEnumTest();


EXTERN_C_END
