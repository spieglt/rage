
// AgeDlg.cpp : implementation file
//

#include "stdafx.h"
#include "Age.h"
#include "AgeDlg.h"
#include "afxdialogex.h"
#include "winuser.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
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


// CAgeDlg dialog



CAgeDlg::CAgeDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_AGE_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAgeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAgeDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ENCRYPT_BUTTON, &CAgeDlg::OnBnClickedButton)
	ON_EN_CHANGE(PASSWORD_BOX, &CAgeDlg::OnEnChangeBox)
	ON_BN_CLICKED(RADIO_PASSPHRASE, &CAgeDlg::OnBnClickedPassphrase)
	ON_BN_CLICKED(RADIO_NATIVE, &CAgeDlg::OnBnClickedNative)
	ON_BN_CLICKED(RADIO_SSH, &CAgeDlg::OnBnClickedSsh)
END_MESSAGE_MAP()


// CAgeDlg message handlers

BOOL CAgeDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
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

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	this->CheckDlgButton(RADIO_PASSPHRASE, BST_CHECKED);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CAgeDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CAgeDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CAgeDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CAgeDlg::OnBnClickedButton()
{
	// TODO: Add your control notification handler code here
	struct COptions *cOptions = (struct COptions*)malloc(sizeof(struct COptions));
	cOptions->input = "myfile";
	cOptions->help = false;
	cOptions->version = false;
	cOptions->encrypt = true;
	cOptions->decrypt = false;
	cOptions->passphrase = "password";
	cOptions->max_work_factor = 22;
	cOptions->armor = false;
	cOptions->recipient;
	cOptions->recipients_file;
	cOptions->identity;
	cOptions->output;

	char *res = wrapper(cOptions);
	MessageBoxA(NULL, res, "Message", MB_OK);
	//printf("%s\n", res);
}


void CAgeDlg::OnEnChangeBox()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialogEx::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}


void CAgeDlg::OnBnClickedPassphrase()
{
	this->GetDlgItem(PASSWORD_BOX)->ShowWindow(SW_SHOW);
	this->GetDlgItem(PASSWORD_LABEL)->ShowWindow(SW_SHOW);
	this->GetDlgItem(NATIVE_LABEL)->ShowWindow(SW_HIDE);
	this->GetDlgItem(SSH_LABEL)->ShowWindow(SW_HIDE);
	this->GetDlgItem(KEY_FILE_SELECTOR)->ShowWindow(SW_HIDE);
}


void CAgeDlg::OnBnClickedNative()
{
	this->GetDlgItem(PASSWORD_BOX)->ShowWindow(SW_HIDE);
	this->GetDlgItem(PASSWORD_LABEL)->ShowWindow(SW_HIDE);
	this->GetDlgItem(NATIVE_LABEL)->ShowWindow(SW_SHOW);
	this->GetDlgItem(SSH_LABEL)->ShowWindow(SW_HIDE);
	this->GetDlgItem(KEY_FILE_SELECTOR)->ShowWindow(SW_SHOW);
}


void CAgeDlg::OnBnClickedSsh()
{
	this->GetDlgItem(PASSWORD_BOX)->ShowWindow(SW_HIDE);
	this->GetDlgItem(PASSWORD_LABEL)->ShowWindow(SW_HIDE);
	this->GetDlgItem(NATIVE_LABEL)->ShowWindow(SW_HIDE);
	this->GetDlgItem(SSH_LABEL)->ShowWindow(SW_SHOW);
	this->GetDlgItem(KEY_FILE_SELECTOR)->ShowWindow(SW_SHOW);
}
