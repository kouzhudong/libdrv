/*
文件名字取自VS2017的控制台示例工程的头文件.

功能:预编译头,不过没有用命令强制第一个包含这个文件.

注意:
1.这个文件只包含系统的头文件和一些公共的数据.
2.这个文件只包含一些公共的数据.
3.也就是说别的头文件只准包含这个文件,不准再包含别的系统文件.

此文件主要用于解决:
1.系统文件包含导致的编译错误问题.
2.统一规划文件的包含关系.
*/


#pragma once


#if (NTDDI_VERSION >= NTDDI_VISTA)
#define NDIS60 1
#define NDIS_SUPPORT_NDIS6 1
#endif 

#define POOL_NX_OPTIN 1
#define _CRT_NON_CONFORMING_SWPRINTFS
#define INITGUID
#define NTSTRSAFE_LIB

#pragma warning(disable:4200) // 使用了非标准扩展 : 结构/联合中的零大小数组
#pragma warning(disable:4201) // unnamed struct/union
#pragma warning(disable:4214) // 使用了非标准扩展: 整形以外的位域类型
#pragma warning(disable:4127) // 条件表达式是常量
#pragma warning(disable:4057) // 在稍微不同的基类型间接寻址上不同
#pragma warning(disable:4152) // 非标准扩展，表达式中的函数/数据指针转换
#pragma warning(disable:28172) //The function 'XXX' has PAGED_CODE or PAGED_CODE_LOCKED but is not declared to be in a paged segment. 原因：1.函数内IRQL升级，2.函数内的函数的参数用局部变量，且要求这个变量是非分页内存。

#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <windef.h> //应该放在ntddk.h的后面.
#include <in6addr.h>
#include <ip2string.h>
#include <guiddef.h>
#include <ndis.h>
#include <initguid.h> //静态定义UUID用的，否则：error LNK2001。
#include <Ntstrsafe.h>
#include <ipmib.h>
#include <netpnp.h>
#include <ntintsafe.h>
#include <fltkernel.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <Bcrypt.h>

/*
WDK7600.16385.1的内核头文件没有u_short的定义,用户层的头文件有u_short的定义.
SOCKADDR结构里用到u_short.
SOCKADDR在ws2def.h中定义.
ws2def.h不建议直接包含.
netioapi.h包含ws2def.h等文件.
所以在WDK7600.16385.1中,如果不包含应用层的头文件,应该在包含netioapi.h之前,加上u_short的定义.
否者,每个包含(包括间接包含)ws2def.h的c/cpp文件都出现一大堆的错误.
*/
typedef unsigned short  u_short;
#include <netioapi.h>
//#include <ws2def.h>
#include <ws2ipdef.h>
#include <mstcpip.h>
#include <wmilib.h>
#include <wmistr.h>
#include <tdi.h>
#include <tdiinfo.h>
#include <tdikrnl.h>
#include <tdistat.h>
#include <fwpmk.h>
#include <wsk.h>
#include <ntimage.h>
#include <fwpsk.h>  //NDIS61
#include <dontuse.h>
#include <suppress.h>
#include <aux_klib.h>
#include <assert.h>
#include <Ntdddisk.h>
#include <intrin.h> //VS2012编译。
#include <immintrin.h>//VS2012编译。
//#include <mmintrin.h> //WDK 编译。
//#include <emmintrin.h>//WDK 编译。
//#include <xmmintrin.h>//WDK 编译。

#include "..\inc\lib.h"

#define TAG 'tset' //test


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
文件和注册表的路径的最大长度。

文件取这个数的原因：
1.文件路径的最大长度是：MAX_PATH，但是内核要用MAX_PATH * sizeof(wchar_t)。
  加之文件沙盒路径的前缀，最大也是这个数，所以双倍就是1024或者1040。
  沙盒前缀的路径应该动态获取，但是这样浪费效率。这是以空间换效率的做法。
2.文件/目录全路径的长度的极限是32K（字符，非字节和字），但是一般情况下是不超过MAX_PATH的。

注册表取这个数的原因：
1.参看ObQueryNameString函数的第三个参数的说明:A reasonable size for the buffer to accommodate most object names is 1024 bytes.
2.The maximum registry path length that will be copied，这是regmon的注释。
*/
#define MAXPATHLEN     1024


//https://msdn.microsoft.com/en-us/library/windows/desktop/ms738518%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
//其实：IPV4的只需This buffer should be large enough to hold at least 16 characters.
#define MAX_ADDRESS_STRING_LENGTH   64


//////////////////////////////////////////////////////////////////////////////////////////////////


#define __FILENAME__ (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#define __FILENAMEW__ (wcsrchr(_CRT_WIDE(__FILE__), L'\\') ? wcsrchr(_CRT_WIDE(__FILE__), L'\\') + 1 : _CRT_WIDE(__FILE__))

/*
既支持单字符也支持宽字符。
注意：
1.第三个参数是单字符，可以为空，但不要为NULL，更不能省略。
2.驱动在DPC上不要打印宽字符。
3.
*/

//这个支持3三个参数。
#define Print(ComponentId, Level, Format, ...) \
{DbgPrintEx(ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__);}

//这个最少4个参数。
#define PrintEx(ComponentId, Level, Format, ...) \
{KdPrintEx((ComponentId, Level, "FILE:%s, LINE:%d, "##Format".\r\n", __FILENAME__, __LINE__, __VA_ARGS__));}


//////////////////////////////////////////////////////////////////////////////////////////////////


extern UNICODE_STRING g_DosKernel32Path;
extern UNICODE_STRING g_Ntkernel32Path;
extern UNICODE_STRING g_DosKernelWow64Path;
extern UNICODE_STRING g_NtkernelWow64Path;


void GetKernel32FullPath();
PVOID GetLoadLibraryExWAddress(HANDLE UniqueProcess);
NTSTATUS GetPcrTest();

void TestUseNoExecuteMemory();
