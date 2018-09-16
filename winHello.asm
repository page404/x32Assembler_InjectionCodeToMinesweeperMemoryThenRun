.386    ;表示指令集,再往前就是 16位指令集了.
.model flat , stdcall ;model flat :表示内存模型为 flat    stdcall:默认的调用约定,如果不在这里写,那么,每个函数我们都要自己写调用约定.
option casemap:none   ;区分大小写,如果不写这一行,不区分大小写.

;-------这里的路径必须是 RadASM 32位 软件的安装目录下的 include 跟 lib,要不然生成不了 exe 文件
;--inc相关
include C:\RadASM\masm32\include\windows.inc
include C:\RadASM\masm32\include\kernel32.inc
include C:\RadASM\masm32\include\user32.inc
include myres.inc

;--lib相关
includelib C:\RadASM\masm32\lib\kernel32.lib
includelib C:\RadASM\masm32\lib\user32.lib

.const   ;常量段,该段的内容是只读的.
  g_szHello db '鼠标左键 注入代码 到 扫雷内存 并执行(每5秒弹出一个MessageBox)!', 0
  g_szTitle db 'Page404', 0

  g_szUsername db 'Backer', 0
  g_szPassword db 'Cracker', 0

  ;根据类名,查找对应的窗口句柄
  ;g_szClassName db '扫雷', 0
  g_szClassName db 'Minesweeper', 0
  ;g_szClassName db 'Hello world!', 0

  g_szKernel32 db 'Kernel32', 0
  g_szUser32 db 'User32', 0

  g_szSleep db 'Sleep', 0
  g_szMsgBox db 'MessageBoxA', 0

.data?
  g_hInst dd ?

.code

INJECTCODE_BEGIN:  ;---------------要注入到扫雷内存中代码的开始位置
g_szInjectText db 'Hello world!', 0
g_szInjectTitle db 'Inject', 0
;--该位置的变量是在 .code 代码段,但是不在 proc 函数范围内,所以是不能修改值的
;如果要修改值,必须修改它们所在内存的属性为 可读可写可执行 才可以.
;VirtualProtect 在这里做了这件事情,将要写入目标内存中的代码属性改成了 可读可写可执行 也包含了这里定义的变量.
g_lpMsgBox dd 0
g_lpSleep dd 0

InjectCode proc

;-----动态重定位(运行时(call NEXT)的地址 减去 编译时(offset)的地址),即相对偏移
;INJECTCODE_BEGIN 到 INJECTCODE_END 这段代码是注入到扫雷的内存当中去的,所以偏移地址跟我们自己的hello.exe肯定不一样,所以要用动态重定位的方式来计算偏移量
;并在下面调用系统的 LoadLibrary->GetProcAddress 得到 MessageBoxA 及 Sleep 等系统 api 的固定地址
;最后,将 相对偏移地址+固定地址,即是我们程序运行时,调用的系统api地址.
;这样处理,不管注入任何的exe中,都是计算要注入exe运行时所调用的系统api地址.
  call NEXT
NEXT:
  pop ebx
  sub ebx, offset NEXT

  .while TRUE
  
    ;调用 MessageBox api函数
    push MB_OKCANCEL
    lea eax, [ebx + offset g_szInjectTitle]
    push eax
    lea eax, [ebx + offset g_szInjectText]
    push eax
    push NULL
    call [ebx + offset g_lpMsgBox]
	;如果点击了 取消 按钮,退出 while 循环
    .break .if eax == IDCANCEL

	;调用 Sleep api函数
    push 5000
    call [ebx + offset g_lpSleep]
	
  .endw
  ret

InjectCode endp
INJECTCODE_END:  ;---------------要注入到扫雷内存中代码的结束位置

Inject proc
  ;查找到的窗口句柄
  local @hWnd:HWND
  ;进程的标识符
  local @dwPID:DWORD
  ;打开进程的句柄
  local @hProcess:HANDLE
  ;所分配内存的基地址
  local @lpMem:LPVOID
  ;创建线程的句柄
  local @hThread:HANDLE
  local @nInjectCodeSize:UINT
  local @dwOld:DWORD

  ;初始化初值为0(即错误值),这样,在退出程序时,检查函数EXIT_PROC:块就不会因为是随机值而判断错误
  xor eax, eax
  mov @hWnd, eax
  mov @hProcess, eax
  mov @lpMem, eax
  mov @hThread, eax
  mov @nInjectCodeSize, eax

  ;调用 FindWindow api函数
  invoke FindWindow, offset g_szClassName, NULL
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  mov @hWnd, eax

  ;调用 GetWindowThreadProcessId api函数
  invoke GetWindowThreadProcessId, @hWnd, addr @dwPID
  ;调用 OpenProcess api函数,建立两个进程之间的联系
  invoke OpenProcess, PROCESS_ALL_ACCESS, FALSE, @dwPID
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  ;这里的 eax 为 OpenProcess 的函数返回值
  mov @hProcess, eax

  ;计算要注入到扫雷内存中的代码的长度
  mov @nInjectCodeSize, offset INJECTCODE_END - offset INJECTCODE_BEGIN
  ;调用 VirtualAllocEx api函数,开辟内存空间
  ;这里的 @hProcess 为查找到的窗口(即扫雷)的进程句柄,所以是在扫雷里面分配的内存空间
  invoke VirtualAllocEx, @hProcess, NULL, @nInjectCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  mov @lpMem, eax

  ;调用 VirtualProtect api函数,修改我们在扫雷中所分配内存的属性为 可读可写可执行
  ;下面的 mov g_lpSleep, eax 及 mov g_lpMsgBox, eax 都修改了这一块内存中的数据,所以,这行代码要在他们之前执行.
  invoke VirtualProtect, INJECTCODE_BEGIN, @nInjectCodeSize, PAGE_EXECUTE_READWRITE, addr @dwOld
  ; check it

  ;------得到 Kernel32 中的 Sleep 函数的 地址
  ;调用 LoadLibrary api函数
  invoke LoadLibrary, offset g_szKernel32
  ; check it
  ;调用 GetProcAddress api函数
  invoke GetProcAddress, eax, offset g_szSleep
  ; check it
  mov g_lpSleep, eax

  ;------得到 User32 中的 MessageBoxA 函数的 地址
  ;调用 LoadLibrary api函数
  invoke LoadLibrary, offset g_szUser32
  ; check it
  ;调用 GetProcAddress api函数
  invoke GetProcAddress, eax, offset g_szMsgBox
  ; check it
  mov g_lpMsgBox, eax

  ;调用 WriteProcessMemory api函数,写入代码到扫雷的内存,代码的起始地址为 offset INJECTCODE_BEGIN,写入长度为 @nInjectCodeSize
  invoke WriteProcessMemory, @hProcess, @lpMem, offset INJECTCODE_BEGIN, @nInjectCodeSize, NULL
  ;返回值在 eax 中,这里直接用 eax 来进行判断,是否写入成功.
  .if eax == FALSE
    jmp EXIT_PROC
  .endif
  
  mov eax, @lpMem
  add eax, offset InjectCode - offset INJECTCODE_BEGIN
  ;调用 CreateRemoteThread api函数,在扫雷的进程里面开一个线程.
  ;参数四: 因为 @lpMem 的前面部分是字符串,代码部分是从 InjectCode: 开始的,所以要将 @lpMem 地址再加上 offset InjectCode - offset INJECTCODE_BEGIN ,即是代码真正开始的位置
  ;如果参数四直接使用 @lpMem,那么,前面的字符串部分会被解释成代码,运行肯定出错.
  invoke CreateRemoteThread, @hProcess, NULL, 0, eax, 0, 0, NULL
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  mov @hThread, eax

  ;调用 WaitForSingleObject api函数,等待刚刚我们所创建的线程@hThread执行结束,才会继续往下执行
  ;因为弹出对话框是在一个while循环里的,所以,只要while循环不结束,@hThread线程也就不会结束(即不会往下执行EXIT_PROC:)
  ;如果没有这一句,执行完一次弹出框后,就会直接往下执行 EXIT_PROC ,释放我们所注入的那块内存区域
  invoke WaitForSingleObject, @hThread, INFINITE

EXIT_PROC:
  .if @hThread
    ;调用 CloseHandle api函数,关闭线程句柄
    invoke CloseHandle, @hThread
    mov @hThread, NULL
  .endif

  .if @lpMem
    ;调用 VirtualFreeEx api函数,释放内存空间
    invoke VirtualFreeEx, @hProcess, @lpMem, @nInjectCodeSize, MEM_RELEASE
    mov @lpMem, NULL
  .endif

  .if @hProcess
    ;调用 CloseHandle api函数,关闭进程句柄 
    invoke CloseHandle, @hProcess
    mov @hProcess, NULL
  .endif
  ret
Inject endp

DialogProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM

  invoke MessageBox, NULL, offset g_szHello, offset g_szTitle, MB_OK
  
  ret
DialogProc endp

WndProc proc hWnd:HWND, uMsg:UINT, wParam:WPARAM, lParam:LPARAM
  local @ps:PAINTSTRUCT
	local @hdc:HDC
  local @rt:RECT

  .if uMsg == WM_LBUTTONDOWN
    invoke Inject             ;鼠标左键,调用我们写的注入函数

  .elseif uMsg == WM_COMMAND
    mov eax, wParam
    .if ax == IDM_FILE_EXIT
      invoke SendMessage, hWnd, WM_DESTROY, 0, 0

    .elseif ax == IDM_FILE_OPEN
      invoke MessageBox, NULL, offset g_szHello, 
        offset g_szTitle, MB_OK

    .elseif ax == IDM_HELP_ABOUT
      invoke DialogBoxParam, g_hInst, DLG_ABOUT, 
        hWnd, offset DialogProc, NULL

    .endif

  .elseif uMsg == WM_PAINT
    invoke BeginPaint, hWnd, addr @ps
    mov @hdc, eax
    invoke GetClientRect, hWnd, addr @rt
    invoke DrawText, @hdc, offset g_szHello, sizeof g_szHello - 1,
      addr @rt, DT_CENTER or DT_VCENTER or DT_SINGLELINE
    invoke EndPaint, hWnd, addr @ps

  .elseif uMsg == WM_DESTROY
    invoke PostQuitMessage, 0

  .else
    invoke DefWindowProc, hWnd, uMsg, wParam, lParam
    ret
  .endif

  xor eax, eax
  ret
WndProc endp

InitInstance proc hInst:HANDLE
  local @hWnd:HWND
  invoke CreateWindowEx, NULL, offset g_szHello, offset g_szTitle, 
    WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, 
    NULL, NULL, hInst, NULL
  mov @hWnd, eax

  .if !@hWnd
    mov eax, FALSE
    ret
  .endif

  invoke ShowWindow, @hWnd, SW_SHOW
  invoke UpdateWindow, @hWnd

  mov eax, TRUE
  ret
InitInstance endp

MyRegisterClass proc hInst:HANDLE
  local @wcex:WNDCLASSEX

  invoke RtlZeroMemory, addr @wcex, sizeof @wcex
	mov @wcex.cbSize, sizeof WNDCLASSEX
	mov @wcex.style, CS_HREDRAW or CS_VREDRAW;
	mov @wcex.lpfnWndProc, offset WndProc
  push hInst
	pop @wcex.hInstance
	mov @wcex.hbrBackground, COLOR_WINDOW+1
	mov @wcex.lpszClassName, offset g_szHello;

  invoke LoadIcon, hInst, IDI_HELLO
  mov @wcex.hIcon, eax
	mov @wcex.lpszMenuName, IDM_TESTSDK
  invoke LoadIcon, hInst, IDI_HELLO
  mov @wcex.hIconSm, eax

  invoke RegisterClassEx, addr @wcex
  ret
MyRegisterClass endp

WinMain proc hInst:HANDLE
  local @msg:MSG

  invoke MyRegisterClass, hInst

  invoke InitInstance, hInst
  .if !eax
    mov eax, FALSE
    ret
  .endif

  invoke GetMessage, addr @msg, NULL, 0, 0
  .while eax
    invoke DispatchMessage, addr @msg
    invoke GetMessage, addr @msg, NULL, 0, 0
  .endw

  mov eax, @msg.wParam
  ret
WinMain endp

START:
  invoke GetModuleHandle, NULL
  mov g_hInst, eax
  invoke WinMain, eax
  invoke ExitProcess, 0

end START
