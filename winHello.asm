.386    ;��ʾָ�,����ǰ���� 16λָ���.
.model flat , stdcall ;model flat :��ʾ�ڴ�ģ��Ϊ flat    stdcall:Ĭ�ϵĵ���Լ��,�����������д,��ô,ÿ���������Ƕ�Ҫ�Լ�д����Լ��.
option casemap:none   ;���ִ�Сд,�����д��һ��,�����ִ�Сд.

;-------�����·�������� RadASM 32λ ����İ�װĿ¼�µ� include �� lib,Ҫ��Ȼ���ɲ��� exe �ļ�
;--inc���
include C:\RadASM\masm32\include\windows.inc
include C:\RadASM\masm32\include\kernel32.inc
include C:\RadASM\masm32\include\user32.inc
include myres.inc

;--lib���
includelib C:\RadASM\masm32\lib\kernel32.lib
includelib C:\RadASM\masm32\lib\user32.lib

.const   ;������,�öε�������ֻ����.
  g_szHello db '������ ע����� �� ɨ���ڴ� ��ִ��(ÿ5�뵯��һ��MessageBox)!', 0
  g_szTitle db 'Page404', 0

  g_szUsername db 'Backer', 0
  g_szPassword db 'Cracker', 0

  ;��������,���Ҷ�Ӧ�Ĵ��ھ��
  ;g_szClassName db 'ɨ��', 0
  g_szClassName db 'Minesweeper', 0
  ;g_szClassName db 'Hello world!', 0

  g_szKernel32 db 'Kernel32', 0
  g_szUser32 db 'User32', 0

  g_szSleep db 'Sleep', 0
  g_szMsgBox db 'MessageBoxA', 0

.data?
  g_hInst dd ?

.code

INJECTCODE_BEGIN:  ;---------------Ҫע�뵽ɨ���ڴ��д���Ŀ�ʼλ��
g_szInjectText db 'Hello world!', 0
g_szInjectTitle db 'Inject', 0
;--��λ�õı������� .code �����,���ǲ��� proc ������Χ��,�����ǲ����޸�ֵ��
;���Ҫ�޸�ֵ,�����޸����������ڴ������Ϊ �ɶ���д��ִ�� �ſ���.
;VirtualProtect �����������������,��Ҫд��Ŀ���ڴ��еĴ������Ըĳ��� �ɶ���д��ִ�� Ҳ���������ﶨ��ı���.
g_lpMsgBox dd 0
g_lpSleep dd 0

InjectCode proc

;-----��̬�ض�λ(����ʱ(call NEXT)�ĵ�ַ ��ȥ ����ʱ(offset)�ĵ�ַ),�����ƫ��
;INJECTCODE_BEGIN �� INJECTCODE_END ��δ�����ע�뵽ɨ�׵��ڴ浱��ȥ��,����ƫ�Ƶ�ַ�������Լ���hello.exe�϶���һ��,����Ҫ�ö�̬�ض�λ�ķ�ʽ������ƫ����
;�����������ϵͳ�� LoadLibrary->GetProcAddress �õ� MessageBoxA �� Sleep ��ϵͳ api �Ĺ̶���ַ
;���,�� ���ƫ�Ƶ�ַ+�̶���ַ,�������ǳ�������ʱ,���õ�ϵͳapi��ַ.
;��������,����ע���κε�exe��,���Ǽ���Ҫע��exe����ʱ�����õ�ϵͳapi��ַ.
  call NEXT
NEXT:
  pop ebx
  sub ebx, offset NEXT

  .while TRUE
  
    ;���� MessageBox api����
    push MB_OKCANCEL
    lea eax, [ebx + offset g_szInjectTitle]
    push eax
    lea eax, [ebx + offset g_szInjectText]
    push eax
    push NULL
    call [ebx + offset g_lpMsgBox]
	;�������� ȡ�� ��ť,�˳� while ѭ��
    .break .if eax == IDCANCEL

	;���� Sleep api����
    push 5000
    call [ebx + offset g_lpSleep]
	
  .endw
  ret

InjectCode endp
INJECTCODE_END:  ;---------------Ҫע�뵽ɨ���ڴ��д���Ľ���λ��

Inject proc
  ;���ҵ��Ĵ��ھ��
  local @hWnd:HWND
  ;���̵ı�ʶ��
  local @dwPID:DWORD
  ;�򿪽��̵ľ��
  local @hProcess:HANDLE
  ;�������ڴ�Ļ���ַ
  local @lpMem:LPVOID
  ;�����̵߳ľ��
  local @hThread:HANDLE
  local @nInjectCodeSize:UINT
  local @dwOld:DWORD

  ;��ʼ����ֵΪ0(������ֵ),����,���˳�����ʱ,��麯��EXIT_PROC:��Ͳ�����Ϊ�����ֵ���жϴ���
  xor eax, eax
  mov @hWnd, eax
  mov @hProcess, eax
  mov @lpMem, eax
  mov @hThread, eax
  mov @nInjectCodeSize, eax

  ;���� FindWindow api����
  invoke FindWindow, offset g_szClassName, NULL
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  mov @hWnd, eax

  ;���� GetWindowThreadProcessId api����
  invoke GetWindowThreadProcessId, @hWnd, addr @dwPID
  ;���� OpenProcess api����,������������֮�����ϵ
  invoke OpenProcess, PROCESS_ALL_ACCESS, FALSE, @dwPID
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  ;����� eax Ϊ OpenProcess �ĺ�������ֵ
  mov @hProcess, eax

  ;����Ҫע�뵽ɨ���ڴ��еĴ���ĳ���
  mov @nInjectCodeSize, offset INJECTCODE_END - offset INJECTCODE_BEGIN
  ;���� VirtualAllocEx api����,�����ڴ�ռ�
  ;����� @hProcess Ϊ���ҵ��Ĵ���(��ɨ��)�Ľ��̾��,��������ɨ�����������ڴ�ռ�
  invoke VirtualAllocEx, @hProcess, NULL, @nInjectCodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  mov @lpMem, eax

  ;���� VirtualProtect api����,�޸�������ɨ�����������ڴ������Ϊ �ɶ���д��ִ��
  ;����� mov g_lpSleep, eax �� mov g_lpMsgBox, eax ���޸�����һ���ڴ��е�����,����,���д���Ҫ������֮ǰִ��.
  invoke VirtualProtect, INJECTCODE_BEGIN, @nInjectCodeSize, PAGE_EXECUTE_READWRITE, addr @dwOld
  ; check it

  ;------�õ� Kernel32 �е� Sleep ������ ��ַ
  ;���� LoadLibrary api����
  invoke LoadLibrary, offset g_szKernel32
  ; check it
  ;���� GetProcAddress api����
  invoke GetProcAddress, eax, offset g_szSleep
  ; check it
  mov g_lpSleep, eax

  ;------�õ� User32 �е� MessageBoxA ������ ��ַ
  ;���� LoadLibrary api����
  invoke LoadLibrary, offset g_szUser32
  ; check it
  ;���� GetProcAddress api����
  invoke GetProcAddress, eax, offset g_szMsgBox
  ; check it
  mov g_lpMsgBox, eax

  ;���� WriteProcessMemory api����,д����뵽ɨ�׵��ڴ�,�������ʼ��ַΪ offset INJECTCODE_BEGIN,д�볤��Ϊ @nInjectCodeSize
  invoke WriteProcessMemory, @hProcess, @lpMem, offset INJECTCODE_BEGIN, @nInjectCodeSize, NULL
  ;����ֵ�� eax ��,����ֱ���� eax �������ж�,�Ƿ�д��ɹ�.
  .if eax == FALSE
    jmp EXIT_PROC
  .endif
  
  mov eax, @lpMem
  add eax, offset InjectCode - offset INJECTCODE_BEGIN
  ;���� CreateRemoteThread api����,��ɨ�׵Ľ������濪һ���߳�.
  ;������: ��Ϊ @lpMem ��ǰ�沿�����ַ���,���벿���Ǵ� InjectCode: ��ʼ��,����Ҫ�� @lpMem ��ַ�ټ��� offset InjectCode - offset INJECTCODE_BEGIN ,���Ǵ���������ʼ��λ��
  ;���������ֱ��ʹ�� @lpMem,��ô,ǰ����ַ������ֻᱻ���ͳɴ���,���п϶�����.
  invoke CreateRemoteThread, @hProcess, NULL, 0, eax, 0, 0, NULL
  .if eax == NULL
    jmp EXIT_PROC
  .endif
  mov @hThread, eax

  ;���� WaitForSingleObject api����,�ȴ��ո��������������߳�@hThreadִ�н���,�Ż��������ִ��
  ;��Ϊ�����Ի�������һ��whileѭ�����,����,ֻҪwhileѭ��������,@hThread�߳�Ҳ�Ͳ������(����������ִ��EXIT_PROC:)
  ;���û����һ��,ִ����һ�ε������,�ͻ�ֱ������ִ�� EXIT_PROC ,�ͷ�������ע����ǿ��ڴ�����
  invoke WaitForSingleObject, @hThread, INFINITE

EXIT_PROC:
  .if @hThread
    ;���� CloseHandle api����,�ر��߳̾��
    invoke CloseHandle, @hThread
    mov @hThread, NULL
  .endif

  .if @lpMem
    ;���� VirtualFreeEx api����,�ͷ��ڴ�ռ�
    invoke VirtualFreeEx, @hProcess, @lpMem, @nInjectCodeSize, MEM_RELEASE
    mov @lpMem, NULL
  .endif

  .if @hProcess
    ;���� CloseHandle api����,�رս��̾�� 
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
    invoke Inject             ;������,��������д��ע�뺯��

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
