
// spo0lsv_killDlg.cpp : 实现文件
// 产权归该博客，在此只用来学习之，该项目来自于：https://blog.csdn.net/ioio_jy/article/details/40961557

#include "stdafx.h"
#include "spo0lsv_kill.h"
#include "spo0lsv_killDlg.h"
#include "afxdialogex.h"
#include <tchar.h>
#include <TlHelp32.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CString csTxt;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// Cspo0lsv_killDlg 对话框



Cspo0lsv_killDlg::Cspo0lsv_killDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_SPO0LSV_KILL_DIALOG, pParent)
	, m_edit(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void Cspo0lsv_killDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_SHOW, m_edit);
}

BEGIN_MESSAGE_MAP(Cspo0lsv_killDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_KILL, &Cspo0lsv_killDlg::OnBnClickedButtonKill)
END_MESSAGE_MAP()


// Cspo0lsv_killDlg 消息处理程序

BOOL Cspo0lsv_killDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void Cspo0lsv_killDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void Cspo0lsv_killDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR Cspo0lsv_killDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}




bool Cspo0lsv_killDlg::is_exist_mem(char* pszProcName, DWORD* dwpid)
{
	// 进程名
	TCHAR szPro[] = _T("spo0lsv.exe");

	// 创建快照，遍历进程
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	if (Process32First(hsnap, &pe))
	{
		do 
		{
			// 找寻病毒的进程
			if (lstrcmpi(szPro, pe.szExeFile) == 0)
			{
				*dwpid = pe.th32ProcessID;
				return TRUE;
			}

		} while (Process32Next(hsnap, &pe));
	}
	CloseHandle(hsnap);

	return FALSE;
}

// 提升为调试权限
// BOOL EnableDebugPrivilege(BOOL fEnable)
// {
// 	BOOL fOk = FALSE;
// 	HANDLE hToken;
// 	// 以修改权限的方式，打开进程的令牌
// 	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
// 	{
// 		// 令牌权限结构体
// 		TOKEN_PRIVILEGES tp;
// 		tp.PrivilegeCount = 1;
// 		// 获得LUID
// 		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
// 		tp.Privileges[0].Attributes == fEnable ? SE_PRIVILEGE_ENABLED : 0;
// 		// 修改权限
// 		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
// 		fOk = (GetLastError() == ERROR_SUCCESS);
// 		CloseHandle(hToken);
// 	}
// 	return(fOk);
// }

bool Cspo0lsv_killDlg::elevate_permissions(char* pszPrivilege)
{

	HANDLE hToken = INVALID_HANDLE_VALUE;
	LUID luid;
	TOKEN_PRIVILEGES tp;

	BOOL bRet = LookupPrivilegeValue(NULL, (LPCWSTR)pszPrivilege, &luid);
	if (bRet == FALSE) return bRet;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
	return bRet; 
}

// 计算病毒程序的散列值
// 在查杀病毒的技术中有一种方法类似于特征码查杀法，这种方法并不从病毒内提取特征码，
// 而是计算病毒的散列值。利用这个散列值，就可以在查杀的过程中计算每个文件的散列，
// 然后进行比较。这种方法简单易于实现，一般在病毒刚被发现时，在逆向分析前使用。
// 常见的计算散列的算法有MD5、Sha - 1以及CRC32等。
DWORD CRC32(BYTE* ptr, DWORD size)
{
	DWORD crcTable[256], crcTmp;
	// 动态生成CRC-32表
	for (int i = 0; i < 256; ++i)
	{
		crcTmp = i;
		for (int j = 8; j > 0; --j)
		{
			if (crcTmp & 1)
				crcTmp = (crcTmp >> 1) ^ 0xEDB88320L;
			else
				crcTmp >>= 1;
		}
		crcTable[i] = crcTmp;
	}
	// 计算CRC32的值
	DWORD crcTmp2 = 0xFFFFFFFF;
	while (size--)
	{
		crcTmp2 = ((crcTmp2 >> 8) & 0x00FFFFFF) ^ crcTable[(crcTmp2 ^ (*ptr)) & 0xFF];
	}
	return (crcTmp2 ^ 0xFFFFFFFF);
}

// 查找并删除Desktop_.ini文件
// 病毒会在所有盘符下面的非系统目录中创建名为Desktop_.ini的文件，
// 虽说这个文件看似并不会对系统产生什么危害，但是为了实现对“熊猫烧香”的彻底查杀，
// 还是应当将其删除的。这里主要涉及两方面的知识，一个是遍历整个磁盘的文件，
// 这需要使用FindFirstFile()与FindNextFile()这两个API函数，并采用递归调用的方法；
// 另一个是修改文件属性，因为病毒创建出来的文件会带有系统、只读和隐藏这三个属性，
// 若不对其进行更改，是无法删除病毒文件的。
DWORD WINAPI FindFiles(LPVOID lpszPath)
{
	WIN32_FIND_DATA stFindFile;
	HANDLE hFindFile;
	// 扫描路径
	char szPath[MAX_PATH];
	char szFindFile[MAX_PATH];
	char szSearch[MAX_PATH];
	char *szFilter;
	int len;
	int ret = 0;

	szFilter = "*.*";
	lstrcpyA(szPath, (char*)lpszPath);

	len = lstrlenA(szPath);
	if (szPath[len - 1] != '\\')
	{
		szPath[len] = '\\';
		szPath[len + 1] = '\0';
	}

	lstrcpyA(szSearch, szPath);
	lstrcatA(szSearch, szFilter);

	hFindFile = FindFirstFile((LPCWSTR)szSearch, &stFindFile);
	if (hFindFile != INVALID_HANDLE_VALUE)
	{
		do 
		{
			lstrcpyA(szFindFile, szPath);
			lstrcatA(szFindFile, (LPCSTR)stFindFile.cFileName);

			if (stFindFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (stFindFile.cFileName[0] != '.')
				{
					FindFiles(szFindFile);
				}
			}
			else
			{
				if (!lstrcmpA((LPCSTR)stFindFile.cFileName, "Desktop_.ini"))
				{
					// 去除文件的隐藏、系统以及只读属性
					DWORD dwFileAttributes = GetFileAttributesA(szFindFile);
					dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
					dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
					dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
					SetFileAttributesA(szFindFile, dwFileAttributes);
					// 删除Desktop_.ini
					BOOL bRet = DeleteFileA(szFindFile);
					csTxt += szFindFile;
					if (bRet)
					{
						csTxt += _T("被删除！\r\n");
					}
					else
					{
						csTxt += _T("无法删除！\r\n");
					}
				}
			}
			ret = FindNextFile(hFindFile, &stFindFile);
		} while (ret != 0);
	}
	FindClose(hFindFile);
	return 0;
}

void Cspo0lsv_killDlg::OnBnClickedButtonKill()
{
	// TODO: 在此添加控件通知处理程序代码
	csTxt = "";
	UpdateData(TRUE); 
	BOOL bRet = FALSE;
	DWORD dwPid = 0;

	// 1. 结束spo0lsv.exe进程，并删除病毒程序本身
	bRet = is_exist_mem("spo0lsv.exe", &dwPid);
	if (bRet == TRUE)
	{
		csTxt = _T("检查系统内存 \r\n");
		csTxt += _T("系统中存在病毒进程：spo0lsv.exe\r\n");
		csTxt += _T("准备进行查杀\r\n");
		SetDlgItemText(IDC_EDIT_SHOW, csTxt); // 将内容显示
		// 提升权限
		bRet = elevate_permissions((char*)SE_DEBUG_NAME);
		if (bRet == FALSE)
		{
			csTxt += _T("提升权限失败\r\n");
		}
		else
		{
			csTxt += _T("提升权限成功\r\n");
		}
		SetDlgItemText(IDC_EDIT_SHOW, csTxt);
		// 打开并尝试结束病毒进程
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (hProcess == INVALID_HANDLE_VALUE)
		{
			csTxt += _T("无法结束病毒进程\r\n");
			return;
		}
		bRet = TerminateProcess(hProcess, 0); // 结束进程
		if (bRet == FALSE)
		{
			csTxt += _T("无法结束病毒进程\r\n");
			return;
		}
		csTxt += _T("病毒进程已经结束\r\n");
		SetDlgItemText(IDC_EDIT_SHOW, csTxt);
		CloseHandle(hProcess);
	}
	else
	{
		csTxt += _T("系统中不存在 spo0lsv.exe病毒进程\r\n");
	}
	Sleep(10);
	// 查杀磁盘中是否存在名为spo0lsv.exe的病毒文件
	char szSysPath[MAX_PATH] = { 0 };
	GetSystemDirectoryA(szSysPath, MAX_PATH);
	lstrcatA(szSysPath, "\\drivers\\spo0lsv.exe");
	csTxt += _T("检查磁盘中是否存在 spo0lsv.exe 文件\r\n");

	if (GetFileAttributesA(szSysPath) == 0xFFFFFFFF)
	{
		csTxt += _T("spo0lsv.exe 病毒文件不存在\r\n");
	}
	else
	{
		csTxt += _T("spo0lsv.exe 病毒文件存在，正在计算散列值\r\n");
		csTxt += _T("是否与病毒库收录散列值(E334747C)相等\r\n");

		HANDLE hFile = CreateFileA(szSysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			MessageBox(L"创建失败");
			return;
		}
		DWORD dwSize = GetFileSize(hFile, NULL);
		if (dwSize == 0xFFFFFFFF)
		{
			MessageBox(L"获取文件大小失败");
			return;
		}
		BYTE* pFile = (BYTE*)malloc(dwSize);
		if (pFile == NULL)
		{
			MessageBox(L"分配空间失败");
			return;
		}

		DWORD dwNum = 0;
		ReadFile(hFile, pFile, dwSize, &dwNum, NULL);
		// 计算 spo0lsv.exe 的散列值
		DWORD dwCrc32 = CRC32(pFile, dwSize);

		if (pFile != NULL)
		{
			free(pFile);
			pFile = NULL;
		}

		CloseHandle(hFile);
		// 0xE334747C 熊猫烧香病毒散列值
		if (dwCrc32 != 0xE334747C)
		{
			csTxt += _T("spo0lsv.exe校验失败\r\n");
		}
		else
		{
			csTxt += _T("spo0lsv.exe 校验成功，正在删除 ... \r\n");
			// 去除文件的隐藏、系统以及只读属性
			DWORD dwFileAttributes = GetFileAttributesA(szSysPath);
			dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
			dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
			dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
			SetFileAttributesA(szSysPath, dwFileAttributes);
			// 删除spo0lsv.exe
			bRet = DeleteFileA(szSysPath);
			if (bRet)
			{
				csTxt += _T("spo0lsv.exe 病毒被删除!\r\n");
			}
			else
			{
				csTxt += _T("spo0lsv.exe 病毒无法删除!\r\n");
			}
		}
	}
	SetDlgItemText(IDC_EDIT_SHOW, csTxt);
	Sleep(10);
	
	// 2. 删除每个盘符下的 setup.exe 与 autorun.inf 以及 Desktop_.ini
	char szDriverString[MAXBYTE] = { 0 };
	char *pTmp = NULL;
	// 获取字符串类型的驱动器列表
	GetLogicalDriveStringsA(MAXBYTE, szDriverString);
	pTmp = szDriverString;
	
	while (*pTmp)
	{
		char szAutorunPath[MAX_PATH] = { 0 };
		char szSetupPath[MAX_PATH] = { 0 };
		lstrcatA(szAutorunPath, pTmp);
		lstrcatA(szAutorunPath, "autorun.inf");
		lstrcatA(szSetupPath, pTmp);
		lstrcatA(szSetupPath, "setup.exe");

		if (GetFileAttributesA(szSetupPath) == 0xFFFFFFFF)
		{
			csTxt += pTmp;
			csTxt += _T("setup.exe 病毒文件不存在\r\n");
		}
		else
		{
			csTxt += pTmp;
			csTxt += _T("setup.exe病毒文件存在，正在进行计算校验和\r\n");
			csTxt += _T("是否与病毒库收录散列值相等\r\n");
			HANDLE hFile = CreateFileA(szSetupPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				MessageBox(L"创建失败");
				return;
			}
			DWORD dwSize = GetFileSize(hFile, NULL);
			if (dwSize == 0xFFFFFFFF)
			{
				MessageBox(L"获取文件大小失败");
				return;
			}
			BYTE *pFile = (BYTE*)malloc(dwSize);
			if (pFile == NULL)
			{
				MessageBox(L"分配空间失败");
				return;
			}

			DWORD dwNum = 0;
			ReadFile(hFile, pFile, dwSize, &dwNum, NULL);

			DWORD dwCrc32 = CRC32(pFile, dwSize);
			if (pFile != NULL)
			{
				free(pFile);
				pFile = NULL;
			}
			CloseHandle(hFile);
			if (dwCrc32 != 0xE334747C)
			{
				csTxt += _T("校验和验证失败\r\n");
			}
			else
			{
				csTxt += _T("校验和验证成功，正在删除\r\n");
				// 去除文件的隐藏、系统以及只读属性
				DWORD dwFileAttributes = GetFileAttributesA(szSetupPath);
				dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
				dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
				dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
				SetFileAttributesA(szSetupPath, dwFileAttributes);
				// 删除setup.exe
				bRet = DeleteFileA(szSetupPath);
				if (bRet)
				{
					csTxt += pTmp;
					csTxt += _T("setup.exe被删除\r\n");
				}
				else
				{
					csTxt += pTmp;
					csTxt += _T("setup.exe无法删除\r\n");
				}
			}
		}
		// 去除文件的隐藏、系统以及只读属性
		DWORD dwFileAttributes = GetFileAttributesA(szSetupPath);
		dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
		dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
		dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
		SetFileAttributesA(szSetupPath, dwFileAttributes);
		// 删除autorun.inf
		bRet = DeleteFileA(szAutorunPath);
		csTxt += pTmp;
		if (bRet)
		{
			csTxt += _T("autorun.inf被删除\r\n");
		}
		else
		{
			csTxt += _T("autorun.inf不存在或无法删除\r\n");
		}
		// 删除Desktop_.ini
		FindFiles(pTmp);
		// 检查下一个盘符
		pTmp += 4;
	}
	Sleep(10);

	// 3. 修复注册表内容，删除病毒启动项并修复文件的隐藏显示
	csTxt += _T("正在检查注册表...\r\n");
	SetDlgItemText(IDC_EDIT_SHOW, csTxt);
	// 首先检查启动项
	char RegRun[] = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	HKEY hKeyHKCU = NULL;
	LONG lSize = MAXBYTE;
	char cData[MAXBYTE] = { 0 };

	long lRet = RegOpenKeyA(HKEY_CURRENT_USER, RegRun, &hKeyHKCU);
	if (lRet == ERROR_SUCCESS)
	{
		lRet = RegQueryValueExA(hKeyHKCU, "svcshare", NULL, NULL, (unsigned char*)cData, (unsigned long*)&lSize);
		if (lRet == ERROR_SUCCESS)
		{
			if (lstrcmpA(cData, "C:\\WINDOWS\\system32\\drivers\\spo0lsv.exe") == 0)
			{
				csTxt += _T("注册表启动项中存在病毒信息\r\n");
			}

			lRet = RegDeleteValueA(hKeyHKCU, "svcshare");
			if (lRet == ERROR_SUCCESS)
			{
				csTxt += _T("注册表启动项中的病毒信息已删除\r\n");
			}
			else
			{
				csTxt += _T("注册表启动项中的病毒信息无法删除\r\n");
			}
		}
		else
		{
			csTxt += _T("注册表启动项中不存在病毒信息\r\n");
		}
		RegCloseKey(hKeyHKCU);
	}
	else
	{
		csTxt += _T("注册表启动项信息读取失败\r\n");
	}
	// 接下来修复文件的隐藏显示，需要将CheckedValue的值设置为1
	char RegHide[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL";
	HKEY hKeyHKLM = NULL;
	DWORD dwFlag = 1;

	long lRetHide = RegOpenKeyA(HKEY_LOCAL_MACHINE, RegHide, &hKeyHKLM);
	if (lRetHide == ERROR_SUCCESS)
	{
		csTxt += _T("检测注册表的文件隐藏选项\r\n");
		if (ERROR_SUCCESS == RegSetValueExA(hKeyHKLM, "CheckedValue", 0, REG_DWORD, (CONST BYTE*)&dwFlag, 4))
		{
			csTxt += _T("注册表修复完毕!\r\n");
		}
		else
		{
			csTxt += _T("无法修复注册表的文件隐藏选项\r\n");
		}
	}

	// 4. 病毒查杀完成
	csTxt += _T("病毒查杀完成， 请使用专业杀毒软件进行全面扫描!\r\n");
	SetDlgItemText(IDC_EDIT_SHOW, csTxt);
	
}