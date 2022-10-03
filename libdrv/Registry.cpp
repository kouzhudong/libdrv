#include "pch.h"
#include "Registry.h"


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS ZwEnumerateKeyEx(IN UNICODE_STRING * Name)
/*
��ʾһ��ע���ļ��µģ��Ӽ������֣����ͣ����ݡ�
ע�⣺û�еݹ���ʾ��

�÷�ʾ����
    UNICODE_STRING test = RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control");//\\Session Manager
    Status = ZwEnumerateKeyEx(&test);
    if( !NT_SUCCESS( Status ) )
    {
        DbgPrint("ZwEnumerateKeyEx fail with 0x%x\n", Status);
    }

Zw��ε�ע�������ܼ򵥡�
�������벻�������е�����ġ�

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
    ע��ZwQueryKey�ĵ�һ��������
    The KeyHandle passed to ZwQueryKey must have been opened with KEY_QUERY_VALUE access.
    This is accomplished by passing KEY_QUERY_VALUE, KEY_READ, 
    or KEY_ALL_ACCESS as the DesiredAccess parameter to ZwCreateKey or ZwOpenKey.
    */

    // ��һ�ε�����Ϊ�˻�ȡ��Ҫ�ĳ���
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, NULL, 0, &ResultLength);
    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW������Ӧ�ò��ᷢ������������¡�
        {
            //�����������ڴ档
        } else {
            ZwClose(KeyHandle);
            return Status;
        }
    }

    //ResultLength += MAX_PATH ;
    //ResultLength *= 2;//������һ�롣
    pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
    if (pfi == NULL) {
        //If ExAllocatePool returns NULL, the caller should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES or should delay processing to another point in time.
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(KeyHandle);
        return Status;
    }

    // �ڶ��ε�����Ϊ�˻�ȡ����
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, pfi, ResultLength, &ResultLength);//���˸�ֵ����ȵͼ��Ĵ���
    if (!NT_SUCCESS(Status)) {
        ExFreePool(pfi);
        ZwClose(KeyHandle);
        return Status;
    }

    //ö���Ӽ���
    for (i = 0; i < pfi->SubKeys; i++) {
        PKEY_BASIC_INFORMATION pbi;
        UNICODE_STRING us;

        // ��ȡ��i������ĳ���
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW������Ӧ�ò��ᷢ������������¡�
            {
                //�����������ڴ档
            } else {
                break;
            }
        }

        pbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
        if (pbi == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // ��ȡ��i�����������
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
        ����������ַ��������Կ��ǵݹ�ö�١�
        */

        ExFreePool(pbi);// �ͷ��ڴ�
    }

    //ö�����֣����ͣ����ݡ�
    for (i = 0; i < pfi->Values; i++) //���Կ�����ZwQueryValueKey��ȡ������MSDN���������Ա�Ľ����ǣ�The number of value entries for this key.
    {
        PKEY_VALUE_BASIC_INFORMATION pkvbi;
        UNICODE_STRING us;
        PKEY_VALUE_PARTIAL_INFORMATION pkvpi;
        UNICODE_STRING data;

        //////////////////////////////////////////////////////////////////////////////////////////

        // ��ȡ���ּ����͡�
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW������Ӧ�ò��ᷢ������������¡�
            {
                //�����������ڴ档
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
        // ��ȡ����
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW������Ӧ�ò��ᷢ������������¡�
            {
                //�����������ڴ档
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

        data.Buffer = (PWCH)pkvpi->Data;//�е����ݿ����޷���ʾ��
        data.Length = (USHORT)pkvpi->DataLength;
        data.MaximumLength = data.Length;

        //////////////////////////////////////////////////////////////////////////////////////////

        DbgPrint("name:%wZ,type:%d,data:%wZ\n", &us, pkvbi->Type, &data);

        ExFreePool(pkvbi);// �ͷ��ڴ�
        ExFreePool(pkvpi);
    }

    ExFreePool(pfi);
    ZwClose(KeyHandle);

    return Status;
}


NTSTATUS ZwCopyKey(IN UNICODE_STRING * Name, IN UNICODE_STRING * Name2)
/*
����һ��ע���ļ��µģ��Ӽ������֣����ͣ����ݡ�
ע�⣺
1.û�еݹ鸴�ơ�
2.û�и��ƣ���ȫ�����ԡ�
3.û�жԲ�������Ч�Խ��м�顣�ַ�����ĩβ��Ҫ��L'\\'.
4.ȷ��ʹ��ǰ������·���Ǵ��ڵġ�
5.�����ȱ�ݣ����㲹�����������Ĺ��ܵȴ���ķ��ӡ�

�÷���
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
    ע��ZwQueryKey�ĵ�һ��������
    The KeyHandle passed to ZwQueryKey must have been opened with KEY_QUERY_VALUE access.
    This is accomplished by passing KEY_QUERY_VALUE, KEY_READ, 
    or KEY_ALL_ACCESS as the DesiredAccess parameter to ZwCreateKey or ZwOpenKey.
    */

    // ��һ�ε�����Ϊ�˻�ȡ��Ҫ�ĳ���
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, NULL, 0, &ResultLength);
    if (!NT_SUCCESS(Status)) {
        if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW������Ӧ�ò��ᷢ������������¡�
        {
            //�����������ڴ档
        } else {
            ZwClose(KeyHandle);
            return Status;
        }
    }

    //ResultLength += MAX_PATH ;
    //ResultLength *= 2;//������һ�롣
    pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
    if (pfi == NULL) {
        //If ExAllocatePool returns NULL, 
        //the caller should return the NTSTATUS value STATUS_INSUFFICIENT_RESOURCES or should delay processing to another point in time.
        Status = STATUS_INSUFFICIENT_RESOURCES;
        ZwClose(KeyHandle);
        return Status;
    }

    // �ڶ��ε�����Ϊ�˻�ȡ����
    Status = ZwQueryKey(KeyHandle, KeyFullInformation, pfi, ResultLength, &ResultLength);//���˸�ֵ����ȵͼ��Ĵ���
    if (!NT_SUCCESS(Status)) {
        ExFreePool(pfi);
        ZwClose(KeyHandle);
        return Status;
    }

    //ö���Ӽ���
    for (i = 0; i < pfi->SubKeys; i++) {
        PKEY_BASIC_INFORMATION pbi;
        UNICODE_STRING us;
        UNICODE_STRING new_key;
        OBJECT_ATTRIBUTES ob;
        HANDLE KeyHandle2 = 0;
        PUNICODE_STRING Class = NULL;
        ULONG  Disposition;

        // ��ȡ��i������ĳ���
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW������Ӧ�ò��ᷢ������������¡�
            {
                //�����������ڴ档
            } else {
                break;
            }
        }

        pbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, TAG);
        if (pbi == NULL) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // ��ȡ��i�����������
        Status = ZwEnumerateKey(KeyHandle, i, KeyBasicInformation, pbi, ResultLength, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            ExFreePool(pbi);
            break;
        }

        us.Buffer = pbi->Name;
        us.Length = (USHORT)pbi->NameLength;
        us.MaximumLength = us.Length;

        DbgPrint("subkey:%wZ\n", &us);

        //��ʼ�½���

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
            //����Ӽ��Ѿ����ڣ�������ȷ��
            ExFreePool(new_key.Buffer);
            ExFreePool(pbi);
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        } else {
            if (KeyHandle2)//����FileHandle������0Ҳ������Ч�ľ����
            {
                Status = ZwClose(KeyHandle2);
                if (!NT_SUCCESS(Status)) {
                    Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "0x%#x", Status);
                }
            }
        }

        /*
        ����������ַ��������Կ��ǵݹ顣
        */

        ExFreePool(pbi);// �ͷ��ڴ�
        ExFreePool(new_key.Buffer);
    }

    //��������ʧ�ܵ��������Ҫ��for ѭ����
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

    //ö�����֣����ͣ����ݡ�
    for (i = 0; i < pfi->Values; i++) //���Կ�����ZwQueryValueKey��ȡ������MSDN���������Ա�Ľ����ǣ�The number of value entries for this key.
    {
        PKEY_VALUE_BASIC_INFORMATION pkvbi;
        UNICODE_STRING us;
        PKEY_VALUE_PARTIAL_INFORMATION pkvpi;
        UNICODE_STRING data;

        //////////////////////////////////////////////////////////////////////////////////////////

        // ��ȡ���ּ����͡�
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValueBasicInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW������Ӧ�ò��ᷢ������������¡�
            {
                //�����������ڴ档
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
        // ��ȡ����
        Status = ZwEnumerateValueKey(KeyHandle, i, KeyValuePartialInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(Status)) {
            if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) //STATUS_BUFFER_OVERFLOW������Ӧ�ò��ᷢ������������¡�
            {
                //�����������ڴ档
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

        data.Buffer = (PWCH)pkvpi->Data;//�е����ݿ����޷���ʾ��
        data.Length = (USHORT)pkvpi->DataLength;
        data.MaximumLength = data.Length;

        //////////////////////////////////////////////////////////////////////////////////////////

        Status = ZwSetValueKey(KeyHandle3, &us, 0, pkvbi->Type, data.Buffer, data.Length);
        if (!NT_SUCCESS(Status)) //��������Ȩ����KEY_READ����ɹ�������ʵ����û�гɹ��ġ�
        {
            ExFreePool(pkvpi);
            ExFreePool(pkvbi);
            break;
        }

        DbgPrint("name:%wZ,type:%d,data:%wZ\n", &us, pkvbi->Type, &data);

        ExFreePool(pkvbi);// �ͷ��ڴ�
        ExFreePool(pkvpi);
    }

    ExFreePool(pfi);
    ZwClose(KeyHandle);
    ZwClose(KeyHandle3);

    return Status;
}


NTSTATUS ZwCreateRootKey(_In_ POBJECT_ATTRIBUTES RegisterKey, _In_ POBJECT_ATTRIBUTES HiveFile)
/*
���ܣ�����ע��������ͬʱҲ��ZwLoadKey��ʾ���÷���

������
RegisterKey��ע�����ں�·������\\REGISTRY\\��ͷ���ɣ�����Ҫ�����е�·����ͻ��
HiveFile������\\DosDevices\\c:\\correy.DAT�����������ʺϱ������ҺϷ���HIVE�ļ���

��������ֶ��ͱ���������ʺϱ������ҺϷ���HIVE�ļ���
���ﲻ�꣬���ҵ���������ϡ�
�������ġ�

�ǵã���������ˣ���Ҫ���˵���ZwUnloadKey��
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

    //һ�����о����Ӽ���,Ҳ������֤��.
    Status = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, RegisterKey);
    if (NT_SUCCESS(Status)) {
        PKEY_FULL_INFORMATION pfi;

        ZwQueryKey(hRegister, KeyFullInformation, NULL, 0, &ulSize);
        pfi = (PKEY_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ulSize, TAG);// ��һ�ε�����Ϊ�˻�ȡ��Ҫ�ĳ���

        ZwQueryKey(hRegister, KeyFullInformation, pfi, ulSize, &ulSize);// �ڶ��ε�����Ϊ�˻�ȡ����
        for (i = 0; i < pfi->SubKeys; i++) {
            PKEY_BASIC_INFORMATION pbi;

            ZwEnumerateKey(hRegister, i, KeyBasicInformation, NULL, 0, &ulSize);// ��ȡ��i������ĳ���
            pbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool, ulSize, TAG);
            if (pbi) {
                ZwEnumerateKey(hRegister, i, KeyBasicInformation, pbi, ulSize, &ulSize);// ��ȡ��i�����������

                us.Buffer = pbi->Name;
                us.Length = (USHORT)pbi->NameLength;
                us.MaximumLength = (USHORT)pbi->NameLength + sizeof(wchar_t);

                DbgPrint("The %d SubItem Name : %wZ\n", i, &us);

                ExFreePoolWithTag(pbi, TAG);// �ͷ��ڴ�
            } else {
                Print(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "�����ڴ�ʧ��");
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

    //���ļ������Ǳ��������,ϵͳ�Ļ����Լ����ɵ�.
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
���ܣ�����ע���ص��л�ȡKEY��ȫ·����

ע�⣺PREG_CREATE_KEY_INFORMATION == PREG_OPEN_KEY_INFORMATION

֮�������������������Ϊע��ص���Create��Open��������Ǹ��ṹ���CompleteName����ȫ���֣�������ʵ��
*/
{
    ULONG Length = MAXPATHLEN;
    PUNICODE_STRING Temp;
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING  KeyPath = {0};
    PVOID Object = Info->RootObject;
    PUNICODE_STRING CompleteName = Info->CompleteName;

    //��������ԡ�

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

        //�жϽ�β�Ƿ��б�ܡ�
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
//extern NTSTATUS /*WINAPI*/ RtlFormatCurrentUserKeyPath(_Out_  UNICODE_STRING CurrentUserKeyPath);  //�˺�����XP���Ѿ���������ֱ�����û�������Ӵ���
typedef NTSTATUS(WINAPI * RtlFormatCurrentUserKeyPath)(_Out_  UNICODE_STRING * CurrentUserKeyPath); //���۾Ͷ�̬��ȡ�ɣ�
//CurrentUserKeyPath [out]
//String that represents the current user's root key in the Registry. Caller must call RtlFreeUnicodeString to free the buffer when done with it.
/*
ע�⣺΢��Ĺٷ������������Ǵ���ġ�
��ʼ�һ���Ϊ�����ҵ�һ�����ֲ������ݽṹ��������ָ��ġ�
*/


PVOID ExpAllocateStringRoutine(IN SIZE_T NumberOfBytes)
{
    return ExAllocatePoolWithTag(PagedPool, NumberOfBytes, 'grtS');
}
//���µĶ���ժ�ԣ�\wrk\WindowsResearchKernel-WRK\WRK-v1.2\base\ntos\ex\pool.c
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
//�������������Ķ���ժ��WRK-v1.2/base/ntos/rtl/regutil.c���������޸ģ�������������ʹ�û������á�
NTSTATUS RtlFormatCurrentUserKeyPath0(OUT PUNICODE_STRING CurrentUserKeyPath)
/*++
Routine Description:
    Initialize the supplied buffer with a string representation of the current user's SID.
    ������������б�Ҫ˵�����㣺
    1.Ҫ��ȡ��ǰ�û���SID�����ȵĲ����ж�SID���ǵ�ǰ�û����ٻ�ȡSID������ס�
      һ̨�����ͬʱ��½������ͬ���û��������ġ�
      ͨ��һ����ͨ���û�һ���Ự������Զ�̵�¼�ġ�
      ������һ���ݾ����жϻỰ�����й���/�����ĺ�������ĳ�����̻����߳������ĸ��Ự��
    2.�˺����з������õļ�ֵ��������ô���ˡ�
    3.�˺�����ȡ�Ĳ��ǵ�ǰ��¼�û���SID�����ǵ�ǰ�Ĳ����Ľ��̵��û���SID����ϵͳ�ʻ��������ʻ��������ʻ��ȡ�

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
    ULONG SidStringLength = 0;//��ӳ�ʼ��Ϊ0.
    UNICODE_STRING SidString;
    NTSTATUS Status;

    // Inside the kernel we can tell rapidly if we are impersonating.
    Status = STATUS_NO_TOKEN;
    if (PsIsThreadTerminating(PsGetCurrentThread())) {//ԭ����PS_IS_THREAD_IMPERSONATING��
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
    //��ΪRtlLengthSidAsUnicodeString��XP��û�е�������������������������滻��
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
    SidString.MaximumLength = CurrentUserKeyPath->MaximumLength;//(USHORT)SidStringLength ;�������޸� ԭ������2Ӧ��Ҳ���Եģ���ȻRtlConvertSidToUnicodeStringʧ�ܡ�
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
����:��ȡ��ǰ�����Ľ��̵��û���SID.

��ӡ��ǰ�����ĵ�ǰ���̵��û�����.

made by correy
made at 2014.06.14
homepage:https://correy.webs.com
����֮��,����ָ��.
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
�д�ʵ�ֵ�һ�����ܣ�
1.ע�������ӵ����á�
2.LastWriteTime�Ĳ鿴�����á�
3.
*/
