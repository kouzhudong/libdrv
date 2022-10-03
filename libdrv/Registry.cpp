#include "pch.h"
#include "Registry.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS ZwEnumerateKeyEx(IN UNICODE_STRING * Name)
/*
显示一个注册表的键下的：子键，名字，类型，数据。
注意：没有递归显示。

用法示例：
    UNICODE_STRING test = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control");//\\Session Manager
    Status = ZwEnumerateKeyEx(&test);
    if( !NT_SUCCESS( Status ) )
    {
        DbgPrint("ZwEnumerateKeyEx fail with 0x%x\n", Status);
    }

Zw层次的注册表操作很简单。
但是做与不做还是有点区别的。

made by correy
made at 2014.07.24
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES        ObjectAttributes;
    HANDLE  KeyHandle;
    PKEY_FULL_INFORMATION pfi;
    ULONG  ResultLength;
    ULONG i = 0;

    InitializeObjectAttributes(&ObjectAttributes, Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /*
    注意ZwQueryKey的第一个参数。
    The KeyHandle passed to ZwQueryKey must have been opened with KEY_QUERY_VALUE access.
    This is accomplished by passing KEY_QUERY_VALUE, KEY_READ, 
    or KEY_ALL_ACCESS as the DesiredAccess parameter to ZwCreateKey or ZwOpenKey.
    */

    // 第一次调用是为了获取需要的长度
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, NULL, 0, &ResultLength);
    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
        {
            //在下面申请内存。
        } else {
            ZwClose(KeyHandle);
            return Status;
        }
    }

    //ResultLength += MAX_PATH ;
    //ResultLength *= 2;//多申请一半。
    pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
    if (pfi == NULL) {
        //If ExAllocatePool returns NULL, the caller should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES or should delay processing to another point in time.
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(KeyHandle);
        return Status;
    }

    // 第二次调用是为了获取数据
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, pfi, ResultLength, &ResultLength);//少了赋值。这等低级的错误。
    if (!NT_SUCCESS(Status)) {
        ExFreePool(pfi);
        ZwClose(KeyHandle);
        return Status;
    }

    //枚举子键。
    for (i = 0; i < pfi->SubKeys; i++) {
        PKEY_BASIC_INFORMATION pbi;
        UNICODE_STRING us;

        // 获取第i个子项的长度
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                //在下面申请内存。
            } else {
                break;
            }
        }

        pbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
        if (pbi == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // 获取第i个子项的数据
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, pbi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePool(pbi);
            break;
        }

        us.Buffer = pbi->Name;
        us.Length = (USHORT)pbi->NameLength;
        us.MaximumLength = us.Length;

        DbgPrint("subkey:%wZ\n", &us);

        /*
        在这里组合字符串，可以考虑递归枚举。
        */

        ExFreePool(pbi);// 释放内存
    }

    //枚举名字，类型，数据。
    for (i = 0; i < pfi->Values; i++) //可以考虑用ZwQueryValueKey获取数量。MSDN关于这个成员的解释是：The number of value entries for this key.
    {
        PKEY_VALUE_BASIC_INFORMATION pkvbi;
        UNICODE_STRING us;
        PKEY_VALUE_PARTIAL_INFORMATION pkvpi;
        UNICODE_STRING data;

        //////////////////////////////////////////////////////////////////////////////////////////

        // 获取名字及类型。
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                //在下面申请内存。
            } else {
                break;
            }
        }
        pkvbi = (PKEY_VALUE_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
        if (pkvbi == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, pkvbi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePool(pkvbi);
            break;
        }

        us.Buffer = pkvbi->Name;
        us.Length = (USHORT)pkvbi->NameLength;
        us.MaximumLength = us.Length;

        //////////////////////////////////////////////////////////////////////////////////////////
        // 获取数据
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                //在下面申请内存。
            } else {
                ExFreePool(pkvbi);
                break;
            }
        }
        pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
        if (pkvpi == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ExFreePool(pkvbi);
            break;
        }
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, pkvpi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePool(pkvpi);
            ExFreePool(pkvbi);
            break;
        }

        data.Buffer = (PWCH)pkvpi->Data;//有的数据可能无法显示。
        data.Length = (USHORT)pkvpi->DataLength;
        data.MaximumLength = data.Length;

        //////////////////////////////////////////////////////////////////////////////////////////

        DbgPrint("name:%wZ,type:%d,data:%wZ\n", &us, pkvbi->Type, &data);

        ExFreePool(pkvbi);// 释放内存
        ExFreePool(pkvpi);
    }

    ExFreePool(pfi);
    ZwClose(KeyHandle);

    return Status;
}


NTSTATUS ZwCopyKey(IN UNICODE_STRING * Name, IN UNICODE_STRING * Name2)
/*
复制一个注册表的键下的：子键，名字，类型，数据。
注意：
1.没有递归复制。
2.没有复制（安全）属性。
3.没有对参数的有效性进行检查。字符串的末尾不要带L'\\'.
4.确认使用前这两个路径是存在的。
5.更多的缺陷，请你补充纠正。更多的功能等待你的发挥。

用法：
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING test = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager");
    UNICODE_STRING test2 = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager2");
    Status = ZwCopyKey(&test, &test2);
    if( !NT_SUCCESS( Status ) )
    {
        DbgPrint("ZwEnumerateKeyEx fail with 0x%x\n", Status);
    }
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES        ObjectAttributes;
    HANDLE  KeyHandle;
    HANDLE  KeyHandle3;
    PKEY_FULL_INFORMATION pfi;
    ULONG  ResultLength;
    ULONG i = 0;

    InitializeObjectAttributes(&ObjectAttributes, Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /*
    注意ZwQueryKey的第一个参数。
    The KeyHandle passed to ZwQueryKey must have been opened with KEY_QUERY_VALUE access.
    This is accomplished by passing KEY_QUERY_VALUE, KEY_READ, 
    or KEY_ALL_ACCESS as the DesiredAccess parameter to ZwCreateKey or ZwOpenKey.
    */

    // 第一次调用是为了获取需要的长度
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, NULL, 0, &ResultLength);
    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
        {
            //在下面申请内存。
        } else {
            ZwClose(KeyHandle);
            return Status;
        }
    }

    //ResultLength += MAX_PATH ;
    //ResultLength *= 2;//多申请一半。
    pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
    if (pfi == NULL) {
        //If ExAllocatePool returns NULL, 
        //the caller should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES or should delay processing to another point in time.
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(KeyHandle);
        return Status;
    }

    // 第二次调用是为了获取数据
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, pfi, ResultLength, &ResultLength);//少了赋值。这等低级的错误。
    if (!NT_SUCCESS(Status)) {
        ExFreePool(pfi);
        ZwClose(KeyHandle);
        return Status;
    }

    //枚举子键。
    for (i = 0; i < pfi->SubKeys; i++) {
        PKEY_BASIC_INFORMATION pbi;
        UNICODE_STRING us;
        UNICODE_STRING new_key;
        OBJECT_ATTRIBUTES ob;
        HANDLE KeyHandle2 = 0;
        PUNICODE_STRING Class = NULL;
        ULONG  Disposition;

        // 获取第i个子项的长度
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                //在下面申请内存。
            } else {
                break;
            }
        }

        pbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
        if (pbi == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // 获取第i个子项的数据
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, pbi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePool(pbi);
            break;
        }

        us.Buffer = pbi->Name;
        us.Length = (USHORT)pbi->NameLength;
        us.MaximumLength = us.Length;

        DbgPrint("subkey:%wZ\n", &us);

        //开始新建。

        new_key.Buffer = (wchar_t *)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH, TAG);
        if (new_key.Buffer == NULL) {
            ExFreePool(pbi);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlZeroMemory(new_key.Buffer, MAX_PATH);
        RtlInitEmptyUnicodeString(&new_key, new_key.Buffer, MAX_PATH);

        RtlCopyUnicodeString(&new_key, Name2);

        Status = RtlAppendUnicodeToString(&new_key, L"\\");
        if (!NT_SUCCESS(Status)) {
            ExFreePool(new_key.Buffer);
            ExFreePool(pbi);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        Status = RtlAppendUnicodeStringToString(&new_key, &us);
        if (!NT_SUCCESS(Status)) {
            ExFreePool(new_key.Buffer);
            ExFreePool(pbi);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        InitializeObjectAttributes(&ob, &new_key, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
        Status = ZwCreateKey(&KeyHandle2, KEY_WRITE, &ob, 0, Class, REG_OPTION_NON_VOLATILE, &Disposition);//KEY_ALL_ACCESS KEY_READ
        if (!NT_SUCCESS(Status)) {
            //如果子键已经存在，返回正确。
            ExFreePool(new_key.Buffer);
            ExFreePool(pbi);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        } else {
            if (KeyHandle2)//断言FileHandle不等于0也不是无效的句柄。
            {
                Status = ZwClose(KeyHandle2);
                if (!NT_SUCCESS(Status)) {
                    Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
                }
            }
        }

        /*
        在这里组合字符串，可以考虑递归。
        */

        ExFreePool(pbi);// 释放内存
        ExFreePool(new_key.Buffer);
    }

    //处理上面失败的情况。主要是for 循环。
    if (!NT_SUCCESS(Status)) {
        ExFreePool(pfi);
        ZwClose(KeyHandle);
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes, Name2, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = ZwOpenKey(&KeyHandle3, KEY_ALL_ACCESS, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
        ExFreePool(pfi);
        ZwClose(KeyHandle);
        return Status;
    }

    //枚举名字，类型，数据。
    for (i = 0; i < pfi->Values; i++) //可以考虑用ZwQueryValueKey获取数量。MSDN关于这个成员的解释是：The number of value entries for this key.
    {
        PKEY_VALUE_BASIC_INFORMATION pkvbi;
        UNICODE_STRING us;
        PKEY_VALUE_PARTIAL_INFORMATION pkvpi;
        UNICODE_STRING data;

        //////////////////////////////////////////////////////////////////////////////////////////

        // 获取名字及类型。
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                //在下面申请内存。
            } else {
                break;
            }
        }
        pkvbi = (PKEY_VALUE_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
        if (pkvbi == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, pkvbi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePool(pkvbi);
            break;
        }

        us.Buffer = pkvbi->Name;
        us.Length = (USHORT)pkvbi->NameLength;
        us.MaximumLength = us.Length;

        //////////////////////////////////////////////////////////////////////////////////////////
        // 获取数据
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                //在下面申请内存。
            } else {
                ExFreePool(pkvbi);
                break;
            }
        }
        pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
        if (pkvpi == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ExFreePool(pkvbi);
            break;
        }
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, pkvpi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePool(pkvpi);
            ExFreePool(pkvbi);
            break;
        }

        data.Buffer = (PWCH)pkvpi->Data;//有的数据可能无法显示。
        data.Length = (USHORT)pkvpi->DataLength;
        data.MaximumLength = data.Length;

        //////////////////////////////////////////////////////////////////////////////////////////

        Status = ZwSetValueKey(KeyHandle3, &us, 0, pkvbi->Type, data.Buffer, data.Length);
        if (!NT_SUCCESS(Status)) //如果句柄的权限是KEY_READ这里成功，但是实际是没有成功的。
        {
            ExFreePool(pkvpi);
            ExFreePool(pkvbi);
            break;
        }

        DbgPrint("name:%wZ,type:%d,data:%wZ\n", &us, pkvbi->Type, &data);

        ExFreePool(pkvbi);// 释放内存
        ExFreePool(pkvpi);
    }

    ExFreePool(pfi);
    ZwClose(KeyHandle);
    ZwClose(KeyHandle3);

    return Status;
}


NTSTATUS ZwCreateRootKey(_In_ POBJECT_ATTRIBUTES RegisterKey, _In_ POBJECT_ATTRIBUTES HiveFile)
/*
功能：创建注册表根键，同时也是ZwLoadKey的示例用法。

参数：
RegisterKey：注册表的内核路径，以\\REGISTRY\\开头即可，但不要和现有的路径冲突。
HiveFile：形如\\DosDevices\\c:\\correy.DAT，但必须是适合本机的且合法的HIVE文件。

关于如何手动和编程制作：适合本机的且合法的HIVE文件。
这里不详，见我的另外的资料。
相信你会的。

记得：如果不用了，不要忘了调用ZwUnloadKey。
*/
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    HANDLE hRegister;
    ULONG i = 0, ulSize = 0;
    UNICODE_STRING us;

    Status = ZwLoadKey(RegisterKey, HiveFile);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("LoadKey failed Error: [%x] \n", Status);
        return Status;
    }

    //一下是列举其子键的,也就是验证下.
    Status = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, RegisterKey);
    if (NT_SUCCESS(Status)) {
        PKEY_FULL_INFORMATION pfi;

        ZwQueryKey(hRegister, KeyFullInformation, NULL, 0, &ulSize);
        pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ulSize, TAG);// 第一次调用是为了获取需要的长度

        ZwQueryKey(hRegister, KeyFullInformation, pfi, ulSize, &ulSize);// 第二次调用是为了获取数据
        for (i = 0; i < pfi->SubKeys; i++) {
            PKEY_BASIC_INFORMATION pbi;

            ZwEnumerateKey(hRegister, i, KeyBasicInformation, NULL, 0, &ulSize);// 获取第i个子项的长度
            pbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool, ulSize, TAG);
            if (pbi) {
                ZwEnumerateKey(hRegister, i, KeyBasicInformation, pbi, ulSize, &ulSize);// 获取第i个子项的数据

                us.Buffer = pbi->Name;
                us.Length = (USHORT)pbi->NameLength;
                us.MaximumLength = (USHORT)pbi->NameLength + sizeof(wchar_t);

                DbgPrint("The %d SubItem Name : %wZ\n", i, &us);

                ExFreePoolWithTag(pbi, TAG);// 释放内存
            } else {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
            }
        }

        ExFreePoolWithTag(pfi, TAG);
        ZwClose(hRegister);
    } else {
        DbgPrint("ZwOpenKey failed unknown cause. Error: [%x] \n", Status);
    }

    return Status;
}


void RegisterLoadTest()
{
    UNICODE_STRING uRegistryPath = RTL_CONSTANT_STRING(L"\\REGISTRY\\correy");

    //此文件必须是本计算机的,系统的或者自己生成的.
    UNICODE_STRING uRegDatPath = RTL_CONSTANT_STRING(L"\\DosDevices\\c:\\correy.DAT");

    OBJECT_ATTRIBUTES obj;
    OBJECT_ATTRIBUTES HiveFile;

    InitializeObjectAttributes(&obj, &uRegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    InitializeObjectAttributes(&HiveFile, &uRegDatPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    ZwCreateRootKey(&obj, &HiveFile);
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS GetKeyFullName(_In_ PREG_CREATE_KEY_INFORMATION Info, _Inout_ PUNICODE_STRING FullKeyName)
/*
功能：用于注册表回调中获取KEY的全路径。

注意：PREG_CREATE_KEY_INFORMATION == PREG_OPEN_KEY_INFORMATION

之所以有这个函数，是因为注册回调的Create和Open操作里的那个结构里的CompleteName不是全名字，名不符实。
*/
{
    ULONG Length = MAXPATHLEN;
    PUNICODE_STRING Temp;
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING  KeyPath = {0};
    PVOID Object = Info->RootObject;
    PUNICODE_STRING CompleteName = Info->CompleteName;

    //参数检查略。

    if (CompleteName->Buffer == NULL) {
        Temp = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, Length, TAG);
        if (Temp == 0) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            return Status;
        }

        Status = ObQueryNameString(Object, (POBJECT_NAME_INFORMATION)Temp, Length, &Length);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            ExFreePoolWithTag(Temp, TAG);
            return Status;
        }

        RtlInitUnicodeString(&KeyPath, Temp->Buffer);

        FullKeyName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, MAXPATHLEN, TAG);
        if (NULL == FullKeyName->Buffer) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            ExFreePoolWithTag(Temp, TAG);
            return Status;
        }

        FullKeyName->MaximumLength = MAXPATHLEN;
        RtlZeroMemory(FullKeyName->Buffer, FullKeyName->MaximumLength);
        RtlCopyUnicodeString(FullKeyName, &KeyPath);

        FullKeyName->MaximumLength = MAXPATHLEN;

        ExFreePoolWithTag(Temp, TAG);
        return Status;
    }

    if (CompleteName->Buffer[0] == L'\\') {
        FullKeyName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, CompleteName->MaximumLength, TAG);
        if (NULL == FullKeyName->Buffer) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            return Status;
        }

        FullKeyName->MaximumLength = CompleteName->MaximumLength;
        RtlZeroMemory(FullKeyName->Buffer, FullKeyName->MaximumLength);
        RtlCopyUnicodeString(FullKeyName, CompleteName);
    } else {
        Temp = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, Length, TAG);
        if (Temp == 0) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            return Status;
        }

        Status = ObQueryNameString(Object, (POBJECT_NAME_INFORMATION)Temp, Length, &Length);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            ExFreePoolWithTag(Temp, TAG);
            return Status;
        }

        RtlInitUnicodeString(&KeyPath, Temp->Buffer);

        FullKeyName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, MAXPATHLEN, TAG);
        if(NULL == FullKeyName->Buffer) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Status:%#x", Status);
            ExFreePoolWithTag(Temp, TAG);
            return Status;
        }

        FullKeyName->MaximumLength = MAXPATHLEN;
        RtlZeroMemory(FullKeyName->Buffer, FullKeyName->MaximumLength);
        RtlCopyUnicodeString(FullKeyName, &KeyPath);

        FullKeyName->MaximumLength = MAXPATHLEN;

        //判断结尾是否带斜杠。
        if (1) {
            RtlAppendUnicodeToString(FullKeyName, L"\\");
        }

        FullKeyName->MaximumLength = MAXPATHLEN;

        RtlAppendUnicodeStringToString(FullKeyName, CompleteName);

        ExFreePoolWithTag(Temp, TAG);
    }

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


//http://msdn.microsoft.com/en-us/library/ff899322(v=vs.85).aspx 
//Initializes the supplied buffer with a string representation of the SID for the current user.
//extern NTSTATUS /*WINAPI*/ RtlFormatCurrentUserKeyPath(_Out_  UNICODE_STRING CurrentUserKeyPath);  //此函数在XP就已经导出，但直接引用会出现链接错误。
typedef NTSTATUS(WINAPI * RtlFormatCurrentUserKeyPath)(_Out_  UNICODE_STRING * CurrentUserKeyPath); //那咱就动态获取吧！
//CurrentUserKeyPath [out]
//String that represents the current user's root key in the Registry. Caller must call RtlFreeUnicodeString to free the buffer when done with it.
/*
注意：微软的官方的链接里面是错误的。
开始我还以为这是我第一个发现参数传递结构，而不是指针的。
*/


PVOID ExpAllocateStringRoutine(IN SIZE_T NumberOfBytes)
{
    return ExAllocatePoolWithTag(PagedPool, NumberOfBytes, 'grtS');
}
//上下的定义摘自：\wrk\WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\ex\pool.c
#ifdef ALLOC_DATA_PRAGMA
#pragma const_seg("PAGECONST")
#endif
const PRTL_ALLOCATE_STRING_ROUTINE RtlAllocateStringRoutine = ExpAllocateStringRoutine;
const PRTL_FREE_STRING_ROUTINE RtlFreeStringRoutine = (PRTL_FREE_STRING_ROUTINE)ExFreePool;
#ifdef ALLOC_DATA_PRAGMA
#pragma const_seg()
#endif


// Maximum size of TOKEN_USER information.
#define SIZE_OF_TOKEN_INFORMATION                   \
    sizeof( TOKEN_USER )                            \
    + sizeof( SID )                                 \
    + sizeof( ULONG ) * SID_MAX_SUB_AUTHORITIES
//这个函数及上面的定义摘自WRK-v1.2/base/ntos/rtl/regutil.c，但是有修改，可以在驱动中使用或者利用。
NTSTATUS RtlFormatCurrentUserKeyPath0(OUT PUNICODE_STRING CurrentUserKeyPath)
/*++
Routine Description:
    Initialize the supplied buffer with a string representation of the current user's SID.
    这个函数还是有必要说明几点：
    1.要获取当前用户的SID，首先的不是判断SID而是当前用户，再获取SID这很容易。
      一台计算机同时登陆几个不同的用户是正常的。
      通常一个普通的用户一个会话，包括远程登录的。
      所以另一个捷径是判断会话，这有公开/导出的函数。如某个进程或者线程属于哪个会话。
    2.此函数有发掘利用的价值，看你怎么用了。
    3.此函数获取的不是当前登录用户的SID，而是当前的操作的进程的用户的SID，如系统帐户，网络帐户，服务帐户等。

Arguments:
    CurrentUserKeyPath - Returns a string that represents the current user's root key in the Registry.
    Caller must call RtlFreeUnicodeString to free the buffer when done with it.

Return Value:
    NTSTATUS - Returns STATUS_SUCCESS if the user string was succesfully initialized.
--*/
{
    HANDLE TokenHandle = 0;
    UCHAR TokenInformation[SIZE_OF_TOKEN_INFORMATION];
    ULONG ReturnLength;
    ULONG SidStringLength = 0;//添加初始化为0.
    UNICODE_STRING SidString;
    NTSTATUS Status;

    // Inside the kernel we can tell rapidly if we are impersonating.
    Status = STATUS_NO_TOKEN;
    if (PsIsThreadTerminating(PsGetCurrentThread())) {//原来是PS_IS_THREAD_IMPERSONATING。
        Status = ZwOpenThreadTokenEx(NtCurrentThread(), TOKEN_READ, TRUE, OBJ_KERNEL_HANDLE, &TokenHandle);
        if (!NT_SUCCESS(Status) && (Status != STATUS_NO_TOKEN)) {
            return Status;
        }
    }

    if (!NT_SUCCESS(Status)) {
        Status = ZwOpenProcessTokenEx(NtCurrentProcess(), TOKEN_READ, OBJ_KERNEL_HANDLE, &TokenHandle);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    Status = ZwQueryInformationToken(TokenHandle, TokenUser, TokenInformation, sizeof(TokenInformation), &ReturnLength);
    ZwClose(TokenHandle);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //Status = RtlLengthSidAsUnicodeString(((PTOKEN_USER)TokenInformation)->User.Sid, &SidStringLength);
    //if ( !NT_SUCCESS( Status ) ) {
    //    return Status ;
    //}
    //因为RtlLengthSidAsUnicodeString在XP上没有导出，所以用下面的两个函数替换。
    if (!RtlValidSid(((PTOKEN_USER)TokenInformation)->User.Sid)) {
        return Status;
    }
    SidStringLength = RtlLengthSid(((PTOKEN_USER)TokenInformation)->User.Sid);
    if (!SidStringLength) {
        return Status;
    }

    CurrentUserKeyPath->Length = 0;
    CurrentUserKeyPath->MaximumLength = (USHORT)(SidStringLength + sizeof(L"\\REGISTRY\\USER\\") + sizeof(UNICODE_NULL));
    CurrentUserKeyPath->Buffer = (PWCH)(CurrentUserKeyPath->MaximumLength);
    if (CurrentUserKeyPath->Buffer == NULL) {
        return STATUS_NO_MEMORY;
    }

    RtlAppendUnicodeToString(CurrentUserKeyPath, L"\\REGISTRY\\USER\\");// Copy "\REGISTRY\USER" to the current user string.
    SidString.MaximumLength = CurrentUserKeyPath->MaximumLength;//(USHORT)SidStringLength ;这里有修改 原数乘以2应该也可以的，不然RtlConvertSidToUnicodeString失败。
    SidString.Length = 0;
    SidString.Buffer = CurrentUserKeyPath->Buffer + (CurrentUserKeyPath->Length / sizeof(WCHAR));
    Status = RtlConvertSidToUnicodeString(&SidString, ((PTOKEN_USER)TokenInformation)->User.Sid, FALSE);
    if (!NT_SUCCESS(Status)) {//#define STATUS_BUFFER_OVERFLOW           ((NTSTATUS)0x80000005L)
        RtlFreeUnicodeString(CurrentUserKeyPath);
    } else {
        CurrentUserKeyPath->Length += SidString.Length;
    }

    return Status;
}


NTSTATUS print_current_user()
/*
功能:获取当前操作的进程的用户的SID.

打印当前操作的当前进程的用户名等.

made by correy
made at 2014.06.14
homepage:https://correy.webs.com
不足之处,敬请指出.
*/
{
    NTSTATUS Status = 0;
    UNICODE_STRING CurrentUserKeyPath = {0};
    UNICODE_STRING us_RtlFormatCurrentUserKeyPath;
    RtlFormatCurrentUserKeyPath g_p_RtlFormatCurrentUserKeyPath;

    RtlInitUnicodeString(&us_RtlFormatCurrentUserKeyPath, L"RtlFormatCurrentUserKeyPath");
    g_p_RtlFormatCurrentUserKeyPath = (RtlFormatCurrentUserKeyPath)MmGetSystemRoutineAddress(&us_RtlFormatCurrentUserKeyPath);
    ASSERT(g_p_RtlFormatCurrentUserKeyPath);
    Status = g_p_RtlFormatCurrentUserKeyPath(&CurrentUserKeyPath);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    KdPrint(("CurrentUserKeyPath:%wZ\n", &CurrentUserKeyPath));//"\REGISTRY\USER\S-1-5-18"
    RtlFreeUnicodeString(&CurrentUserKeyPath);

    Status = RtlFormatCurrentUserKeyPath0(&CurrentUserKeyPath);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    KdPrint(("CurrentUserKeyPath:%wZ\n", &CurrentUserKeyPath));//"\REGISTRY\USER\S-1-5-18"
    RtlFreeUnicodeString(&CurrentUserKeyPath);

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
有待实现的一个功能：
1.注册表的连接的设置。
2.LastWriteTime的查看和设置。
3.
*/
