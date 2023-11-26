/*
本文包括：Process, Thread, Image等的测试。
*/

#pragma once


//////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS EnumProcessTest(VOID);
NTSTATUS PrintAllKernelModule();

void CreateSystemThreadInIdleProcess();
void StopSystemThreadInIdleProcess();
void TestGetTokenOffsetInProcess();
void TestGetProtectionOffsetInProcess();


//////////////////////////////////////////////////////////////////////////////////////////////////
