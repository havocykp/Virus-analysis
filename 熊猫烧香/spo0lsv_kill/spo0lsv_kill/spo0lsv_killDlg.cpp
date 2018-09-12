
// spo0lsv_killDlg.cpp : ʵ���ļ�
// ��Ȩ��ò��ͣ��ڴ�ֻ����ѧϰ֮������Ŀ�����ڣ�https://blog.csdn.net/ioio_jy/article/details/40961557

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
// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// Cspo0lsv_killDlg �Ի���



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


// Cspo0lsv_killDlg ��Ϣ�������

BOOL Cspo0lsv_killDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void Cspo0lsv_killDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR Cspo0lsv_killDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}




bool Cspo0lsv_killDlg::is_exist_mem(char* pszProcName, DWORD* dwpid)
{
	// ������
	TCHAR szPro[] = _T("spo0lsv.exe");

	// �������գ���������
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
			// ��Ѱ�����Ľ���
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

// ����Ϊ����Ȩ��
// BOOL EnableDebugPrivilege(BOOL fEnable)
// {
// 	BOOL fOk = FALSE;
// 	HANDLE hToken;
// 	// ���޸�Ȩ�޵ķ�ʽ���򿪽��̵�����
// 	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
// 	{
// 		// ����Ȩ�޽ṹ��
// 		TOKEN_PRIVILEGES tp;
// 		tp.PrivilegeCount = 1;
// 		// ���LUID
// 		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
// 		tp.Privileges[0].Attributes == fEnable ? SE_PRIVILEGE_ENABLED : 0;
// 		// �޸�Ȩ��
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

// ���㲡�������ɢ��ֵ
// �ڲ�ɱ�����ļ�������һ�ַ����������������ɱ�������ַ��������Ӳ�������ȡ�����룬
// ���Ǽ��㲡����ɢ��ֵ���������ɢ��ֵ���Ϳ����ڲ�ɱ�Ĺ����м���ÿ���ļ���ɢ�У�
// Ȼ����бȽϡ����ַ���������ʵ�֣�һ���ڲ����ձ�����ʱ�����������ǰʹ�á�
// �����ļ���ɢ�е��㷨��MD5��Sha - 1�Լ�CRC32�ȡ�
DWORD CRC32(BYTE* ptr, DWORD size)
{
	DWORD crcTable[256], crcTmp;
	// ��̬����CRC-32��
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
	// ����CRC32��ֵ
	DWORD crcTmp2 = 0xFFFFFFFF;
	while (size--)
	{
		crcTmp2 = ((crcTmp2 >> 8) & 0x00FFFFFF) ^ crcTable[(crcTmp2 ^ (*ptr)) & 0xFF];
	}
	return (crcTmp2 ^ 0xFFFFFFFF);
}

// ���Ҳ�ɾ��Desktop_.ini�ļ�
// �������������̷�����ķ�ϵͳĿ¼�д�����ΪDesktop_.ini���ļ���
// ��˵����ļ����Ʋ������ϵͳ����ʲôΣ��������Ϊ��ʵ�ֶԡ���è���㡱�ĳ��ײ�ɱ��
// ����Ӧ������ɾ���ġ�������Ҫ�漰�������֪ʶ��һ���Ǳ����������̵��ļ���
// ����Ҫʹ��FindFirstFile()��FindNextFile()������API�����������õݹ���õķ�����
// ��һ�����޸��ļ����ԣ���Ϊ���������������ļ������ϵͳ��ֻ�����������������ԣ�
// ����������и��ģ����޷�ɾ�������ļ��ġ�
DWORD WINAPI FindFiles(LPVOID lpszPath)
{
	WIN32_FIND_DATA stFindFile;
	HANDLE hFindFile;
	// ɨ��·��
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
					// ȥ���ļ������ء�ϵͳ�Լ�ֻ������
					DWORD dwFileAttributes = GetFileAttributesA(szFindFile);
					dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
					dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
					dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
					SetFileAttributesA(szFindFile, dwFileAttributes);
					// ɾ��Desktop_.ini
					BOOL bRet = DeleteFileA(szFindFile);
					csTxt += szFindFile;
					if (bRet)
					{
						csTxt += _T("��ɾ����\r\n");
					}
					else
					{
						csTxt += _T("�޷�ɾ����\r\n");
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
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	csTxt = "";
	UpdateData(TRUE); 
	BOOL bRet = FALSE;
	DWORD dwPid = 0;

	// 1. ����spo0lsv.exe���̣���ɾ������������
	bRet = is_exist_mem("spo0lsv.exe", &dwPid);
	if (bRet == TRUE)
	{
		csTxt = _T("���ϵͳ�ڴ� \r\n");
		csTxt += _T("ϵͳ�д��ڲ������̣�spo0lsv.exe\r\n");
		csTxt += _T("׼�����в�ɱ\r\n");
		SetDlgItemText(IDC_EDIT_SHOW, csTxt); // ��������ʾ
		// ����Ȩ��
		bRet = elevate_permissions((char*)SE_DEBUG_NAME);
		if (bRet == FALSE)
		{
			csTxt += _T("����Ȩ��ʧ��\r\n");
		}
		else
		{
			csTxt += _T("����Ȩ�޳ɹ�\r\n");
		}
		SetDlgItemText(IDC_EDIT_SHOW, csTxt);
		// �򿪲����Խ�����������
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (hProcess == INVALID_HANDLE_VALUE)
		{
			csTxt += _T("�޷�������������\r\n");
			return;
		}
		bRet = TerminateProcess(hProcess, 0); // ��������
		if (bRet == FALSE)
		{
			csTxt += _T("�޷�������������\r\n");
			return;
		}
		csTxt += _T("���������Ѿ�����\r\n");
		SetDlgItemText(IDC_EDIT_SHOW, csTxt);
		CloseHandle(hProcess);
	}
	else
	{
		csTxt += _T("ϵͳ�в����� spo0lsv.exe��������\r\n");
	}
	Sleep(10);
	// ��ɱ�������Ƿ������Ϊspo0lsv.exe�Ĳ����ļ�
	char szSysPath[MAX_PATH] = { 0 };
	GetSystemDirectoryA(szSysPath, MAX_PATH);
	lstrcatA(szSysPath, "\\drivers\\spo0lsv.exe");
	csTxt += _T("���������Ƿ���� spo0lsv.exe �ļ�\r\n");

	if (GetFileAttributesA(szSysPath) == 0xFFFFFFFF)
	{
		csTxt += _T("spo0lsv.exe �����ļ�������\r\n");
	}
	else
	{
		csTxt += _T("spo0lsv.exe �����ļ����ڣ����ڼ���ɢ��ֵ\r\n");
		csTxt += _T("�Ƿ��벡������¼ɢ��ֵ(E334747C)���\r\n");

		HANDLE hFile = CreateFileA(szSysPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			MessageBox(L"����ʧ��");
			return;
		}
		DWORD dwSize = GetFileSize(hFile, NULL);
		if (dwSize == 0xFFFFFFFF)
		{
			MessageBox(L"��ȡ�ļ���Сʧ��");
			return;
		}
		BYTE* pFile = (BYTE*)malloc(dwSize);
		if (pFile == NULL)
		{
			MessageBox(L"����ռ�ʧ��");
			return;
		}

		DWORD dwNum = 0;
		ReadFile(hFile, pFile, dwSize, &dwNum, NULL);
		// ���� spo0lsv.exe ��ɢ��ֵ
		DWORD dwCrc32 = CRC32(pFile, dwSize);

		if (pFile != NULL)
		{
			free(pFile);
			pFile = NULL;
		}

		CloseHandle(hFile);
		// 0xE334747C ��è���㲡��ɢ��ֵ
		if (dwCrc32 != 0xE334747C)
		{
			csTxt += _T("spo0lsv.exeУ��ʧ��\r\n");
		}
		else
		{
			csTxt += _T("spo0lsv.exe У��ɹ�������ɾ�� ... \r\n");
			// ȥ���ļ������ء�ϵͳ�Լ�ֻ������
			DWORD dwFileAttributes = GetFileAttributesA(szSysPath);
			dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
			dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
			dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
			SetFileAttributesA(szSysPath, dwFileAttributes);
			// ɾ��spo0lsv.exe
			bRet = DeleteFileA(szSysPath);
			if (bRet)
			{
				csTxt += _T("spo0lsv.exe ������ɾ��!\r\n");
			}
			else
			{
				csTxt += _T("spo0lsv.exe �����޷�ɾ��!\r\n");
			}
		}
	}
	SetDlgItemText(IDC_EDIT_SHOW, csTxt);
	Sleep(10);
	
	// 2. ɾ��ÿ���̷��µ� setup.exe �� autorun.inf �Լ� Desktop_.ini
	char szDriverString[MAXBYTE] = { 0 };
	char *pTmp = NULL;
	// ��ȡ�ַ������͵��������б�
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
			csTxt += _T("setup.exe �����ļ�������\r\n");
		}
		else
		{
			csTxt += pTmp;
			csTxt += _T("setup.exe�����ļ����ڣ����ڽ��м���У���\r\n");
			csTxt += _T("�Ƿ��벡������¼ɢ��ֵ���\r\n");
			HANDLE hFile = CreateFileA(szSetupPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				MessageBox(L"����ʧ��");
				return;
			}
			DWORD dwSize = GetFileSize(hFile, NULL);
			if (dwSize == 0xFFFFFFFF)
			{
				MessageBox(L"��ȡ�ļ���Сʧ��");
				return;
			}
			BYTE *pFile = (BYTE*)malloc(dwSize);
			if (pFile == NULL)
			{
				MessageBox(L"����ռ�ʧ��");
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
				csTxt += _T("У�����֤ʧ��\r\n");
			}
			else
			{
				csTxt += _T("У�����֤�ɹ�������ɾ��\r\n");
				// ȥ���ļ������ء�ϵͳ�Լ�ֻ������
				DWORD dwFileAttributes = GetFileAttributesA(szSetupPath);
				dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
				dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
				dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
				SetFileAttributesA(szSetupPath, dwFileAttributes);
				// ɾ��setup.exe
				bRet = DeleteFileA(szSetupPath);
				if (bRet)
				{
					csTxt += pTmp;
					csTxt += _T("setup.exe��ɾ��\r\n");
				}
				else
				{
					csTxt += pTmp;
					csTxt += _T("setup.exe�޷�ɾ��\r\n");
				}
			}
		}
		// ȥ���ļ������ء�ϵͳ�Լ�ֻ������
		DWORD dwFileAttributes = GetFileAttributesA(szSetupPath);
		dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
		dwFileAttributes &= ~FILE_ATTRIBUTE_SYSTEM;
		dwFileAttributes &= ~FILE_ATTRIBUTE_READONLY;
		SetFileAttributesA(szSetupPath, dwFileAttributes);
		// ɾ��autorun.inf
		bRet = DeleteFileA(szAutorunPath);
		csTxt += pTmp;
		if (bRet)
		{
			csTxt += _T("autorun.inf��ɾ��\r\n");
		}
		else
		{
			csTxt += _T("autorun.inf�����ڻ��޷�ɾ��\r\n");
		}
		// ɾ��Desktop_.ini
		FindFiles(pTmp);
		// �����һ���̷�
		pTmp += 4;
	}
	Sleep(10);

	// 3. �޸�ע������ݣ�ɾ������������޸��ļ���������ʾ
	csTxt += _T("���ڼ��ע���...\r\n");
	SetDlgItemText(IDC_EDIT_SHOW, csTxt);
	// ���ȼ��������
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
				csTxt += _T("ע����������д��ڲ�����Ϣ\r\n");
			}

			lRet = RegDeleteValueA(hKeyHKCU, "svcshare");
			if (lRet == ERROR_SUCCESS)
			{
				csTxt += _T("ע����������еĲ�����Ϣ��ɾ��\r\n");
			}
			else
			{
				csTxt += _T("ע����������еĲ�����Ϣ�޷�ɾ��\r\n");
			}
		}
		else
		{
			csTxt += _T("ע����������в����ڲ�����Ϣ\r\n");
		}
		RegCloseKey(hKeyHKCU);
	}
	else
	{
		csTxt += _T("ע�����������Ϣ��ȡʧ��\r\n");
	}
	// �������޸��ļ���������ʾ����Ҫ��CheckedValue��ֵ����Ϊ1
	char RegHide[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL";
	HKEY hKeyHKLM = NULL;
	DWORD dwFlag = 1;

	long lRetHide = RegOpenKeyA(HKEY_LOCAL_MACHINE, RegHide, &hKeyHKLM);
	if (lRetHide == ERROR_SUCCESS)
	{
		csTxt += _T("���ע�����ļ�����ѡ��\r\n");
		if (ERROR_SUCCESS == RegSetValueExA(hKeyHKLM, "CheckedValue", 0, REG_DWORD, (CONST BYTE*)&dwFlag, 4))
		{
			csTxt += _T("ע����޸����!\r\n");
		}
		else
		{
			csTxt += _T("�޷��޸�ע�����ļ�����ѡ��\r\n");
		}
	}

	// 4. ������ɱ���
	csTxt += _T("������ɱ��ɣ� ��ʹ��רҵɱ���������ȫ��ɨ��!\r\n");
	SetDlgItemText(IDC_EDIT_SHOW, csTxt);
	
}