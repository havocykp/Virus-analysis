
// spo0lsv_killDlg.h : ͷ�ļ�
//

#pragma once


// Cspo0lsv_killDlg �Ի���
class Cspo0lsv_killDlg : public CDialogEx
{
// ����
public:
	Cspo0lsv_killDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SPO0LSV_KILL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CString m_edit;
	
	afx_msg void OnBnClickedButtonKill();

	// ���ڴ��в��Ҳ����Ƿ����
	bool is_exist_mem(char* pszProcName, DWORD* dwpid);
	// ����Ȩ�ޣ�����������ϵͳ��Դ
	bool elevate_permissions(char* pszPrivilege);
};
