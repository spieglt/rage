
// AgeDlg.h : header file
//

#pragma once


// CAgeDlg dialog
class CAgeDlg : public CDialogEx
{
// Construction
public:
	CAgeDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_AGE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
};

struct AgeOptions {
	char *input; // should be option
	BOOL help;
	BOOL version;
	BOOL encrypt;
	BOOL decrypt;
	BOOL passphrase;
	char max_work_factor; // should be option
	BOOL armor;
	char **recipient;
	char **recipients_file;
	char **identity;
	char *output; // should be option
};
