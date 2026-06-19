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
    PAGED_CODE();

    OBJECT_ATTRIBUTES ObjectAttributes{};
    HANDLE KeyHandle{};
    InitializeObjectAttributes(&ObjectAttributes, Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    NTSTATUS Status = ZwOpenKey(&KeyHandle, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    /*
    注意ZwQueryKey的第一个参数。
    The KeyHandle passed to ZwQueryKey must have been opened with KEY_QUERY_VALUE access.
    This is accomplished by passing KEY_QUERY_VALUE, KEY_READ, or KEY_ALL_ACCESS as the DesiredAccess parameter to ZwCreateKey or ZwOpenKey.
    */

    // 第一次调用是为了获取需要的长度
    ULONG ResultLength{};
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, nullptr, 0, &ResultLength);
    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) // STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
        {
            // 在下面申请内存。
        } else {
            ZwClose(KeyHandle);
            return Status;
        }
    }

    // ResultLength += MAX_PATH ;
    // ResultLength *= 2;//多申请一半。
    auto pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool,ResultLength, TAG);
    if (pfi == nullptr) {
        // If ExAllocatePool returns NULL, the caller should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES or should delay processing to another point in time.
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(KeyHandle);
        return Status;
    }

    // 第二次调用是为了获取数据
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, pfi, ResultLength, &ResultLength); // 少了赋值。这等低级的错误。
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(pfi, TAG);
        ZwClose(KeyHandle);
        return Status;
    }

    // 枚举子键。
    for (ULONG i = 0; i < pfi->SubKeys; i++) {
        PKEY_BASIC_INFORMATION pbi{};
        UNICODE_STRING us{};

        // 获取第i个子项的长度
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, nullptr, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) // STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                // 在下面申请内存。
            } else {
                break;
            }
        }

        pbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool,ResultLength, TAG);
        if (pbi == nullptr) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // 获取第i个子项的数据
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, pbi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(pbi, TAG);
            break;
        }

        us.Buffer = pbi->Name;
        us.Length = (USHORT)pbi->NameLength;
        us.MaximumLength = us.Length;

        DbgPrint("subkey:%wZ\n", &us);

        /*
        在这里组合字符串，可以考虑递归枚举。
        */

        ExFreePoolWithTag(pbi, TAG); // 释放内存
    }

    // 枚举名字，类型，数据。
    for (ULONG i = 0; i < pfi->Values; i++) // 可以考虑用ZwQueryValueKey获取数量。MSDN关于这个成员的解释是：The number of value entries for this key.
    {
        //////////////////////////////////////////////////////////////////////////////////////////
        // 获取名字及类型。
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, nullptr, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) // STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                // 在下面申请内存。
            } else {
                break;
            }
        }
        auto pkvbi = (PKEY_VALUE_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool,ResultLength, TAG);
        if (pkvbi == nullptr) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, pkvbi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(pkvbi, TAG);
            break;
        }

        UNICODE_STRING us{};
        us.Buffer = pkvbi->Name;
        us.Length = (USHORT)pkvbi->NameLength;
        us.MaximumLength = us.Length;

        //////////////////////////////////////////////////////////////////////////////////////////
        // 获取数据
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, nullptr, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) // STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                // 在下面申请内存。
            } else {
                ExFreePoolWithTag(pkvbi, TAG);
                break;
            }
        }
        auto pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool,ResultLength, TAG);
        if (pkvpi == nullptr) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ExFreePoolWithTag(pkvbi, TAG);
            break;
        }
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, pkvpi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(pkvpi, TAG);
            ExFreePoolWithTag(pkvbi, TAG);
            break;
        }

        UNICODE_STRING data{};
        data.Buffer = (PWCH)pkvpi->Data; // 有的数据可能无法显示。
        data.Length = (USHORT)pkvpi->DataLength;
        data.MaximumLength = data.Length;

        //////////////////////////////////////////////////////////////////////////////////////////

        DbgPrint("name:%wZ,type:%u,data:%wZ\n", &us, pkvbi->Type, &data);

        ExFreePoolWithTag(pkvbi, TAG); // 释放内存
        ExFreePoolWithTag(pkvpi, TAG);
    }

    ExFreePoolWithTag(pfi, TAG);
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
    OBJECT_ATTRIBUTES ObjectAttributes{};
    HANDLE KeyHandle{};
    InitializeObjectAttributes(&ObjectAttributes, Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    NTSTATUS Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);
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
    ULONG ResultLength{};
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, nullptr, 0, &ResultLength);
    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) // STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
        {
            // 在下面申请内存。
        } else {
            ZwClose(KeyHandle);
            return Status;
        }
    }

    // ResultLength += MAX_PATH ;
    // ResultLength *= 2;//多申请一半。
    auto pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,ResultLength, TAG);
    if (pfi == nullptr) {
        // If ExAllocatePool returns NULL,
        // the caller should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES or should delay processing to another point in time.
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(KeyHandle);
        return Status;
    }

    // 第二次调用是为了获取数据
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, pfi, ResultLength, &ResultLength); // 少了赋值。这等低级的错误。
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(pfi, TAG);
        ZwClose(KeyHandle);
        return Status;
    }

    // 枚举子键。
    for (ULONG i = 0; i < pfi->SubKeys; i++) {
        // 获取第i个子项的长度
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, nullptr, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) // STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                // 在下面申请内存。
            } else {
                break;
            }
        }

        auto pbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,ResultLength, TAG);
        if (pbi == nullptr) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // 获取第i个子项的数据
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, pbi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(pbi, TAG);
            break;
        }

        UNICODE_STRING us{};
        us.Buffer = pbi->Name;
        us.Length = (USHORT)pbi->NameLength;
        us.MaximumLength = us.Length;

        DbgPrint("subkey:%wZ\n", &us);

        // 开始新建。按实际需要计算长度，避免固定 MAX_PATH 上限导致长路径被截断。
        UNICODE_STRING new_key{};
        USHORT new_key_max = (USHORT)(Name2->Length + sizeof(WCHAR) /* backslash */ + us.Length + sizeof(UNICODE_NULL));
        new_key.Buffer = (wchar_t *)ExAllocatePoolWithTag(NonPagedPool, new_key_max, TAG);
        if (new_key.Buffer == nullptr) {
            ExFreePoolWithTag(pbi, TAG);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlZeroMemory(new_key.Buffer, new_key_max);
        RtlInitEmptyUnicodeString(&new_key, new_key.Buffer, new_key_max);

        RtlCopyUnicodeString(&new_key, Name2);

        Status = RtlAppendUnicodeToString(&new_key, L"\\");
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(new_key.Buffer, TAG);
            ExFreePoolWithTag(pbi, TAG);
            break;
        }

        Status = RtlAppendUnicodeStringToString(&new_key, &us);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(new_key.Buffer, TAG);
            ExFreePoolWithTag(pbi, TAG);
            break;
        }

        HANDLE KeyHandle2{};
        PUNICODE_STRING Class{};
        ULONG Disposition{};
        OBJECT_ATTRIBUTES ob{};
        InitializeObjectAttributes(&ob, &new_key, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
        Status = ZwCreateKey(&KeyHandle2, KEY_WRITE, &ob, 0, Class, REG_OPTION_NON_VOLATILE, &Disposition); // KEY_ALL_ACCESS KEY_READ
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(new_key.Buffer, TAG);
            ExFreePoolWithTag(pbi, TAG);
            break;
        } else {
            if (KeyHandle2) // 断言FileHandle不等于0也不是无效的句柄。
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

        ExFreePoolWithTag(pbi, TAG); // 释放内存
        ExFreePoolWithTag(new_key.Buffer, TAG);
    }

    // 处理上面失败的情况。主要是for 循环。
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(pfi, TAG);
        ZwClose(KeyHandle);
        return Status;
    }

    InitializeObjectAttributes(&ObjectAttributes, Name2, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    HANDLE KeyHandle3{};
    Status = ZwOpenKey(&KeyHandle3, KEY_ALL_ACCESS, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(pfi, TAG);
        ZwClose(KeyHandle);
        return Status;
    }

    // 枚举名字，类型，数据。
    for (ULONG i = 0; i < pfi->Values; i++) // 可以考虑用ZwQueryValueKey获取数量。MSDN关于这个成员的解释是：The number of value entries for this key.
    {
        //////////////////////////////////////////////////////////////////////////////////////////
        // 获取名字及类型。
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, nullptr, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) // STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                // 在下面申请内存。
            } else {
                break;
            }
        }
        auto pkvbi = (PKEY_VALUE_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,ResultLength, TAG);
        if (pkvbi == nullptr) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, pkvbi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(pkvbi, TAG);
            break;
        }

        UNICODE_STRING us{};
        us.Buffer = pkvbi->Name;
        us.Length = (USHORT)pkvbi->NameLength;
        us.MaximumLength = us.Length;

        //////////////////////////////////////////////////////////////////////////////////////////
        // 获取数据
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, nullptr, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) // STATUS_BUFFER_OVERFLOW这个情况应该不会发生在这种情况下。
            {
                // 在下面申请内存。
            } else {
                ExFreePoolWithTag(pkvbi, TAG);
                break;
            }
        }
        auto pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,ResultLength, TAG);
        if (pkvpi == nullptr) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ExFreePoolWithTag(pkvbi, TAG);
            break;
        }
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, pkvpi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(pkvpi, TAG);
            ExFreePoolWithTag(pkvbi, TAG);
            break;
        }

        UNICODE_STRING data{};
        data.Buffer = (PWCH)pkvpi->Data; // 有的数据可能无法显示。
        data.Length = (USHORT)pkvpi->DataLength;
        data.MaximumLength = data.Length;

        //////////////////////////////////////////////////////////////////////////////////////////

        // 用 pkvpi->DataLength（ULONG）写入，避免被 data.Length（USHORT）截断。
        Status = ZwSetValueKey(KeyHandle3, &us, 0, pkvbi->Type, pkvpi->Data, pkvpi->DataLength);
        if (!NT_SUCCESS(Status)) // 如果句柄的权限是KEY_READ这里成功，但是实际是没有成功的。
        {
            ExFreePoolWithTag(pkvpi, TAG);
            ExFreePoolWithTag(pkvbi, TAG);
            break;
        }

        DbgPrint("name:%wZ,type:%u,data:%wZ\n", &us, pkvbi->Type, &data);

        ExFreePoolWithTag(pkvbi, TAG); // 释放内存
        ExFreePoolWithTag(pkvpi, TAG);
    }

    ExFreePoolWithTag(pfi, TAG);
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
    NTSTATUS Status = ZwLoadKey(RegisterKey, HiveFile);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("LoadKey failed Error: [%x] \n", Status);
        return Status;
    }

    // 一下是列举其子键的,也就是验证下.
    HANDLE hRegister{};
    Status = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, RegisterKey);
    if (NT_SUCCESS(Status)) {
        ULONG ulSize = 0;
        ZwQueryKey(hRegister, KeyFullInformation, nullptr, 0, &ulSize);
        if (ulSize == 0) {
            ZwClose(hRegister);
            return STATUS_UNSUCCESSFUL;
        }
        auto pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ulSize, TAG);
        if (!pfi) {
            ZwClose(hRegister);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = ZwQueryKey(hRegister, KeyFullInformation, pfi, ulSize, &ulSize); // 第二次调用是为了获取数据
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(pfi, TAG);
            ZwClose(hRegister);
            return Status;
        }

        for (ULONG i = 0; i < pfi->SubKeys; i++) {
            Status = ZwEnumerateKey(hRegister, i, KeyBasicInformation, nullptr, 0, &ulSize); // 获取第i个子项的长度
            if (Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_BUFFER_OVERFLOW && !NT_SUCCESS(Status)) {
                break;
            }

            auto pbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool, ulSize, TAG);
            if (pbi == nullptr) {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "申请内存失败");
                continue;
            }

            Status = ZwEnumerateKey(hRegister, i, KeyBasicInformation, pbi, ulSize, &ulSize); // 获取第i个子项的数据
            if (NT_SUCCESS(Status)) {
                UNICODE_STRING us{};
                us.Buffer = pbi->Name;
                us.Length = (USHORT)pbi->NameLength;
                us.MaximumLength = (USHORT)pbi->NameLength;

                DbgPrint("The %u SubItem Name : %wZ\n", i, &us);
            }

            ExFreePoolWithTag(pbi, TAG); // 释放内存
        }

        ExFreePoolWithTag(pfi, TAG);
        ZwClose(hRegister);
    } else {
        DbgPrint("ZwOpenKey failed unknown cause. Error: [%x] \n", Status);
    }

    return Status;
}


NTSTATUS SetValueKeyDword(_In_ PUNICODE_STRING KeyPath, _In_ PUNICODE_STRING ValueName, _In_ ULONG Value)
{
    OBJECT_ATTRIBUTES ObjectAttributes{};
    HANDLE KeyHandle = nullptr;
    InitializeObjectAttributes(&ObjectAttributes, KeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    NTSTATUS Status = ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &ObjectAttributes);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
        return Status;
    }

    ULONG Data = Value;
    Status = ZwSetValueKey(KeyHandle, ValueName, 0, REG_DWORD, &Data, sizeof(ULONG));
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
    }

    ZwClose(KeyHandle);

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS GetKeyFullName(__in PVOID RootObject, __in PUNICODE_STRING CompleteName, _Inout_ PUNICODE_STRING KeyFullName)
/*
功能：用于注册表回调中获取KEY的全路径。

调用时机：Open/Create的前操作。后操作建议用CmCallbackGetKeyObjectID。

注释：
1.参数KeyFullName由调用者（用FreeUnicodeString）释放。
2.CompleteName，这个参数名不副实，有不少的相对路径。
3.
*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    POBJECT_NAME_INFORMATION ObjectNameInfo = nullptr;

    // 出参先清零：本函数负责申请 KeyFullName->Buffer，绝不读取调用者传入的旧值。
    // 原代码在申请前就对未初始化的 Buffer 调用 RtlZeroMemory，可能崩溃或越界。
    KeyFullName->Buffer = nullptr;
    KeyFullName->Length = 0;
    KeyFullName->MaximumLength = 0;

    do {
        // 情形一：CompleteName 是以反斜杠开头的绝对路径，直接拷贝。
        if (CompleteName->Buffer != nullptr && CompleteName->Length >= sizeof(WCHAR) && CompleteName->Buffer[0] == L'\\') {
            USHORT MaximumLength = (USHORT)(CompleteName->Length + sizeof(UNICODE_NULL));
            KeyFullName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, MaximumLength, TAG);
            if (nullptr == KeyFullName->Buffer) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: %s", "ExAllocatePoolWithTag Fail");
                break;
            }
            RtlZeroMemory(KeyFullName->Buffer, MaximumLength);
            KeyFullName->MaximumLength = MaximumLength;
            RtlCopyUnicodeString(KeyFullName, CompleteName);
            break;
        }

        // 情形二、三都需要 RootObject 的对象名，先取所需长度。
        ULONG Length = 0;
        Status = ObQueryNameString(RootObject, nullptr, 0, &Length);
        if (0 == Length) {
            if (NT_SUCCESS(Status)) {
                Status = STATUS_UNSUCCESSFUL;
            }
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        ObjectNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePoolWithTag(PagedPool, Length, TAG);
        if (nullptr == ObjectNameInfo) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: %s", "ExAllocatePoolWithTag Fail");
            break;
        }
        RtlZeroMemory(ObjectNameInfo, Length);

        Status = ObQueryNameString(RootObject, ObjectNameInfo, Length, &Length);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }

        // 情形二：CompleteName 为空，结果就是 RootObject 的对象名。
        if (CompleteName->Buffer == nullptr || CompleteName->Length == 0) {
            USHORT MaximumLength = (USHORT)(ObjectNameInfo->Name.Length + sizeof(UNICODE_NULL));
            KeyFullName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, MaximumLength, TAG);
            if (nullptr == KeyFullName->Buffer) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: %s", "ExAllocatePoolWithTag Fail");
                break;
            }
            RtlZeroMemory(KeyFullName->Buffer, MaximumLength);
            KeyFullName->MaximumLength = MaximumLength;
            RtlCopyUnicodeString(KeyFullName, &ObjectNameInfo->Name);
            break;
        }

        // 情形三：相对路径，组合 RootObject对象名 + L"\\" + CompleteName。
        ULONG Required = (ULONG)ObjectNameInfo->Name.Length + sizeof(WCHAR) /* backslash */ + (ULONG)CompleteName->Length + sizeof(UNICODE_NULL);
        if (Required > MAXUSHORT) {
            Status = STATUS_NAME_TOO_LONG;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }
        USHORT MaximumLength = (USHORT)Required;
        KeyFullName->Buffer = (PWCH)ExAllocatePoolWithTag(PagedPool, MaximumLength, TAG);
        if (nullptr == KeyFullName->Buffer) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: %s", "ExAllocatePoolWithTag Fail");
            break;
        }
        RtlZeroMemory(KeyFullName->Buffer, MaximumLength);
        KeyFullName->MaximumLength = MaximumLength;
        RtlCopyUnicodeString(KeyFullName, &ObjectNameInfo->Name);

        if (KeyFullName->Length >= sizeof(WCHAR) &&
            L'\\' != KeyFullName->Buffer[KeyFullName->Length / sizeof(WCHAR) - 1]) { // 判断结尾是否带斜杠。
            Status = RtlAppendUnicodeToString(KeyFullName, L"\\");
            if (!NT_SUCCESS(Status)) {
                PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
                break;
            }
        }

        Status = RtlAppendUnicodeStringToString(KeyFullName, CompleteName);
        if (!NT_SUCCESS(Status)) {
            PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
            break;
        }
    } while (FALSE);

    if (ObjectNameInfo) {
        ExFreePoolWithTag(ObjectNameInfo, TAG);
    }

    // 失败时不把半成品缓冲区返回给调用者。
    if (!NT_SUCCESS(Status) && KeyFullName->Buffer) {
        ExFreePoolWithTag(KeyFullName->Buffer, TAG);
        KeyFullName->Buffer = nullptr;
        KeyFullName->Length = 0;
        KeyFullName->MaximumLength = 0;
    }

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


// http://msdn.microsoft.com/en-us/library/ff899322(v=vs.85).aspx
// Initializes the supplied buffer with a string representation of the SID for the current user.
// extern NTSTATUS /*WINAPI*/ RtlFormatCurrentUserKeyPath(_Out_  UNICODE_STRING CurrentUserKeyPath);  //此函数在XP就已经导出，但直接引用会出现链接错误。
typedef NTSTATUS(WINAPI * RtlFormatCurrentUserKeyPath)(_Out_ UNICODE_STRING * CurrentUserKeyPath); // 那咱就动态获取吧！
// CurrentUserKeyPath [out]
// String that represents the current user's root key in the Registry. Caller must call RtlFreeUnicodeString to free the buffer when done with it.
/*
注意：微软的官方的链接里面是错误的。
开始我还以为这是我第一个发现参数传递结构，而不是指针的。
*/


PVOID ExpAllocateStringRoutine(IN SIZE_T NumberOfBytes)
{
    return ExAllocatePoolWithTag(PagedPool,NumberOfBytes, 'grtS');
}


// 上下的定义摘自：\wrk\WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\ex\pool.c
// #ifdef ALLOC_DATA_PRAGMA
// #pragma const_seg("PAGECONST")
// #endif


// warning LNK4210: 存在 .CRT 节；可能有未处理的静态初始值设定项或结束符
// const PRTL_ALLOCATE_STRING_ROUTINE RtlAllocateStringRoutine = ExpAllocateStringRoutine;
// const PRTL_FREE_STRING_ROUTINE RtlFreeStringRoutine = (PRTL_FREE_STRING_ROUTINE)ExFreePool;


// #ifdef ALLOC_DATA_PRAGMA
// #pragma const_seg()
// #endif


// Maximum size of TOKEN_USER information.
#define SIZE_OF_TOKEN_INFORMATION \
    sizeof(TOKEN_USER) + sizeof(SID) + sizeof(ULONG) * SID_MAX_SUB_AUTHORITIES


// 这个函数及上面的定义摘自WRK-v1.2/base/ntos/rtl/regutil.c，但是有修改，可以在驱动中使用或者利用。
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
    // Try thread token first (impersonation); fall back to process token on STATUS_NO_TOKEN.
    HANDLE TokenHandle{};
    NTSTATUS Status = ZwOpenThreadTokenEx(NtCurrentThread(), TOKEN_READ, TRUE, OBJ_KERNEL_HANDLE, &TokenHandle);
    if (!NT_SUCCESS(Status)) {
        if (Status != STATUS_NO_TOKEN) {
            return Status;
        }
        Status = ZwOpenProcessTokenEx(NtCurrentProcess(), TOKEN_READ, OBJ_KERNEL_HANDLE, &TokenHandle);
        if (!NT_SUCCESS(Status)) {
            return Status;
        }
    }

    ULONG ReturnLength{};
    // 按指针对齐，TOKEN_USER 内含 PSID 指针，UCHAR 数组不保证对齐。
    __declspec(align(MEMORY_ALLOCATION_ALIGNMENT)) UCHAR TokenInformation[SIZE_OF_TOKEN_INFORMATION];
    Status = ZwQueryInformationToken(TokenHandle, TokenUser, TokenInformation, sizeof(TokenInformation), &ReturnLength);
    ZwClose(TokenHandle);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    PSID Sid = ((PTOKEN_USER)TokenInformation)->User.Sid;
    if (!RtlValidSid(Sid)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "RtlValidSid Fail");
        return STATUS_INVALID_SID; // 原代码这里返回 Status(=STATUS_SUCCESS)，调用者会拿到未初始化的串并误释放。
    }

    // 让 RtlConvertSidToUnicodeString 自行申请缓冲区得到 SID 字符串，长度由它保证正确。
    // 原代码用 RtlLengthSid（SID 二进制字节数）估算字符串长度，对真实用户 SID 偏小，会导致转换失败。
    UNICODE_STRING SidString{};
    Status = RtlConvertSidToUnicodeString(&SidString, Sid, TRUE);
    if (!NT_SUCCESS(Status)) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "Error: Status:%#x", Status);
        return Status;
    }

    UNICODE_STRING Prefix = RTL_CONSTANT_STRING(L"\\REGISTRY\\USER\\");
    CurrentUserKeyPath->Length = 0;
    CurrentUserKeyPath->MaximumLength = (USHORT)(Prefix.Length + SidString.Length + sizeof(UNICODE_NULL));
    CurrentUserKeyPath->Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(PagedPool, CurrentUserKeyPath->MaximumLength, TAG));
    if (CurrentUserKeyPath->Buffer == nullptr) {
        RtlFreeUnicodeString(&SidString);
        CurrentUserKeyPath->MaximumLength = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(CurrentUserKeyPath->Buffer, CurrentUserKeyPath->MaximumLength);

    RtlAppendUnicodeStringToString(CurrentUserKeyPath, &Prefix); // "\REGISTRY\USER\"
    RtlAppendUnicodeStringToString(CurrentUserKeyPath, &SidString);
    RtlFreeUnicodeString(&SidString);

    return STATUS_SUCCESS;
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
    UNICODE_STRING CurrentUserKeyPath{};
    UNICODE_STRING us_RtlFormatCurrentUserKeyPath{};
    RtlFormatCurrentUserKeyPath g_p_RtlFormatCurrentUserKeyPath{};

    RtlInitUnicodeString(&us_RtlFormatCurrentUserKeyPath, L"RtlFormatCurrentUserKeyPath");
    g_p_RtlFormatCurrentUserKeyPath = static_cast<RtlFormatCurrentUserKeyPath>(MmGetSystemRoutineAddress(&us_RtlFormatCurrentUserKeyPath));
    if (!g_p_RtlFormatCurrentUserKeyPath) {
        PrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "%s", "MmGetSystemRoutineAddress(RtlFormatCurrentUserKeyPath) failed");
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    NTSTATUS Status = g_p_RtlFormatCurrentUserKeyPath(&CurrentUserKeyPath);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    KdPrint(("CurrentUserKeyPath:%wZ\n", &CurrentUserKeyPath)); //"\REGISTRY\USER\S-1-5-18"
    RtlFreeUnicodeString(&CurrentUserKeyPath);

    Status = RtlFormatCurrentUserKeyPath0(&CurrentUserKeyPath);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }
    KdPrint(("CurrentUserKeyPath:%wZ\n", &CurrentUserKeyPath)); //"\REGISTRY\USER\S-1-5-18"
    if (CurrentUserKeyPath.Buffer) {
        ExFreePoolWithTag(CurrentUserKeyPath.Buffer, TAG);
        CurrentUserKeyPath.Buffer = nullptr;
    }

    return Status;
}


//////////////////////////////////////////////////////////////////////////////////////////////////


/*
有待实现的一个功能：
1.注册表的连接的设置。
2.LastWriteTime的查看和设置。
3.
*/
