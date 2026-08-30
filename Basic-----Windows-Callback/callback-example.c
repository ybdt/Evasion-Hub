#include <windows.h>

// 声明窗口过程回调函数，用于处理窗口消息
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // 注册窗口类
    // 定义并初始化一个常量、宽字符数组
    const wchar_t CLASS_NAME[] = L"Sample Window Class";

    // 向操作系统注册一种名为CLASS_NAME的新窗口类型，这种类型的窗口属于当前应用程序实例hInstance，并且所有发送给这类窗口的消息都由WindowProc函数来处理
    WNDCLASS wc = { };
    wc.lpfnWndProc = WindowProc;  // 设置回调函数
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    RegisterClass(&wc);
    
    // 创建窗口
    HWND hwnd = CreateWindowEx(
        0,                                        // 扩展窗口样式
        CLASS_NAME,                               // 窗口类
        L"回调函数示例",                            // 窗口标题
        WS_OVERLAPPEDWINDOW,                      // 窗口样式
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,   // 位置和大小
        NULL,                                     // 父窗口
        NULL,                                     // 菜单
        hInstance,                                // 实例句柄
        NULL                                      // 附加数据
    );
    if (hwnd == NULL) {
        return 0;
    }
    
    // 显示窗口
    ShowWindow(hwnd, nCmdShow);
    
    // 消息循环
    MSG msg = { };
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}

// 窗口过程回调函数实现
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg)
    {
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // 在窗口上绘制文本
            TextOut(hdc, 50, 50, L"这是一个回调函数示例", 9);
            
            EndPaint(hwnd, &ps);

            return 0;
        }

        case WM_LBUTTONDOWN:
            MessageBox(hwnd, L"您点击了鼠标左键!", L"提示", MB_OK);   // 鼠标左键点击时显示消息框
            return 0;
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}