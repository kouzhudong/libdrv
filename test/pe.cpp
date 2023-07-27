#include "pch.h"
#include "pe.h"


void TestGetRoutineAddress()
{
    PVOID GetSecurityUserInfoAddress = GetRoutineAddress("ksecdd.sys", "GetSecurityUserInfo");
    Print(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "GetSecurityUserInfoAddress:0x%p", GetSecurityUserInfoAddress);
}
