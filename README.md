# libdrv
Static Library For Drivers

创建本工程的目的。

有一些代码是几乎每个工程都用到的，很常见的代码。

把这些代码提炼出来，精简下，且适用于各个工程，且有通用性和稳定性。

这是创建本工程的目的。

为何不用DLL，因为在驱动里DLL还得注册。


--------------------------------------------------------------------------------------------------


弄成静态库使用很方便，只需一个h和lib即可。

注意本lib用到不少的系统的lib，所以你使用的工程（如果用到了相应的功能）也应该包含他们，如：    
* $(DDK_LIB_PATH)ntoskrnl.lib  
* $(DDK_LIB_PATH)hal.lib  
* $(DDK_LIB_PATH)wmilib.lib  
* $(DDK_LIB_PATH)\fltMgr.lib  
* $(DDK_LIB_PATH)\Ksecdd.lib  
* $(DDK_LIB_PATH)\ndis.lib  
* $(DDK_LIB_PATH)\wdmsec.lib  
* $(DDK_LIB_PATH)\fwpkclnt.lib  
* $(SDK_LIB_PATH)\uuid.lib  
* $(DDK_LIB_PATH)\Netio.lib  
* $(DDK_LIB_PATH)\Ntstrsafe.lib  
* $(DDK_LIB_PATH)\Aux_klib.lib  


--------------------------------------------------------------------------------------------------


本库的设计的几个规则：  
1. 尽量不调用日志函数。刚开始的时候还考虑是否使用日志，以及何种日志。  
2. 因为上一条，所以代码失败要返回详细的信息，也就是失败的原因。  
3. 因为上两条的原因，所以使用者要检查返回值，并记录日志。  
4. 代码不会主动抛异常。代码尽量屏蔽异常。但是不代表代码中没有异常。代码尽量捕捉异常并返回信息。  
5. 导出（对外公开的）的函数都是NTAPI调用格式。  
6. 代码尽量使用SAL（source-code annotation language:源代码批注语言）。  
7. 代码格式类似go和python.  
8. 代码尽量不使用硬编码。  
9. 代码开启静态的语法检查（启用Microsoft Code Analysis, 关闭Clang-Tidy）。  
10. 警告的等级是4级，且将警告视为错误。  
11. 代码的运行要过：驱动程序校验器/应用程序校验器/gflags.exe.  
12. 禁止使用断言（估计现在代码中还有不少断言）。  
13. 接口的参数只有基本类型和指针（没有类，模板和引用）。  
14. 只依赖操作系统的库，不再依赖第三方的库，包括CRT。  
15. 所有接口皆为C接口，即EXTERN_C。  
16. C语言标准选择：ISO C17 (2018)标准 (/std:c17)。  
17. C++语言标准选择：ISO C++17 标准 (/std:c++17) 或者：预览 - 最新 C++ 工作草案中的功能 (/std:c++latest)。  
18. 与代码的精简相比，首选效率和速度。


特别说明：  
本库只提供c/c++调用接口文档，  
其他的，如：ASM，C#，GO，PYTHON，JAVA，PHP等自行定义。  


注意：
接口或者回调的调用方式。__stdcall or __cdecl or __fastcall。


--------------------------------------------------------------------------------------------------


所有接口皆为C接口  
要实现这句话，需要把函数的声明加上EXTERN_C  
本工程是在头文件中实施的。 

关于这个（是不是导出的C函数）检查办法是：  
1. 用7z打开lib，  
2. 然后解压，  
3. 然后用notepad++所有的txt文件  
4. 最后搜索哪个函数名  
5. 看函数名即知  


--------------------------------------------------------------------------------------------------
