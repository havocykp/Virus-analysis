
// spo0lsv_killDlg.h : 头文件
//

#pragma once


// Cspo0lsv_killDlg 对话框
class Cspo0lsv_killDlg : public CDialogEx
{
// 构造
public:
	Cspo0lsv_killDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SPO0LSV_KILL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CString m_edit;
	
	afx_msg void OnBnClickedButtonKill();

	// 在内存中查找病毒是否存在
	bool is_exist_mem(char* pszProcName, DWORD* dwpid);
	// 提升权限，访问受限制系统资源
	bool elevate_permissions(char* pszPrivilege);
};
