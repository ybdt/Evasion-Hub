import winreg
from elevate import elevate
import time

elevate()
while True:
    key = winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\Policies\Microsoft\Windows Defender", 0, winreg.KEY_ALL_ACCESS)
    try:
        value, type = winreg.QueryValueEx(key, "DisableAntiSpyware")
    except:
        print("注册表项 HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender 不包含值 DisableAntiSpyware，正在添加...")
        winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, 1)
        print("成功添加值 DisableAntiSpyware")
    else:
        print("注册表项 HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender 包含值 DisableAntiSpyware，且值数据为{}，值类型为{}".format(value, str(type)))
    time.sleep(3)