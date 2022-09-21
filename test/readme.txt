/*
要使KdPrintEx((DPFLTR_IHVNETWORK_ID,...生效的两种种办法:
1.先加nt的载符号文件，
  然后运行windbg命令：ed nt!Kd_IHVNETWORK_Mask f，相应的类似命令有：ed nt!Kd_DEFAULT_Mask f;ed nt!Kd_FLTMGR_Mask f。
  这个办法立即生效，
  同时也是关闭的办法, 只需再次设置这个值为0即可。
2.另一种办法使修改注册表.
  如果用reg文件，内容如下：
  Windows Registry Editor Version 5.00

  [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter]
  "IHVNETWORK"=dword:0000000f
  但是需要重启.
*/
