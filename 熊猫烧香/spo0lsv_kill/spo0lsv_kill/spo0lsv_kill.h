
// spo0lsv_kill.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// Cspo0lsv_killApp: 
// �йش����ʵ�֣������ spo0lsv_kill.cpp
//

class Cspo0lsv_killApp : public CWinApp
{
public:
	Cspo0lsv_killApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern Cspo0lsv_killApp theApp;