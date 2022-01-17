#pragma warning(disable:4996)
#pragma comment(lib,"ws2_32.lib")   //라이브러리 종속성 추가
#pragma comment(lib,"Iphlpapi.lib")
#include <windows.h>
#include <tchar.h>
#include <iphlpapi.h>
#include <iostream>
//#include <Winsock2.h>//소켓 프로그래밍을 위한 헤더 = arpa/inet.h 대신 윈도우에서 사용
#include "resource.h"
using namespace std;

BOOL CALLBACK WinProc(HWND, UINT, WPARAM, LPARAM);

#define MAX_SEND_IMAGE 9

//전역변수
HDC hdc;
PAINTSTRUCT ps;
DWORD ThreadID;
HANDLE hthread[100];
HWND dig;
HINSTANCE g_inst;
LRESULT timeoutout;

LPCTSTR lpszClass = _T("ARP Simulation");

char ip[18];
char mac[34];

char arr_ip[5][16] = { 0 };
char arr_mac[5][17] = { 0 };

char LocalIp[16] = { 0 };  // My IP 를 저장 , ARP_Packet에서 Sender or Target으로 사용
char LocalMac[16] = { 0 }; // My Mac을 저장 , ARP_Packet에서 Sender or Target으로 사용

typedef struct arp_hdr {
    char HardwareType[30];
    char ProtocolType[30];
    char HardwareLength[2];
    char ProtocolLength[2];
    char Operation[2];
    char SenderMAC[34];
    char SenderIP[18];
    char TargetMAC[34];
    char TargetIP[18];
}arp;

typedef struct arp_table {
    int nAttempt = 0, nQueue, nSignal, nTimeout = 900;
    char chQueue[5], chAttempt[5], chTimeout[7];
    char chState[30] = { "FREE" }; // 상태 변수
    bool empty = TRUE;
    char ip_addr[18];
    char mac_addr[34];
}table;

typedef struct address {
    char ip_addr[18];
    char mac_addr[34];
}Addr;

arp request;
arp reply;
table cache;

Addr getLocal() {
    char mac_addr[34];
    Addr adr;
    PIP_ADAPTER_INFO info;
    DWORD size = sizeof(PIP_ADAPTER_INFO);
    int result;
    HWND INIT_IP;
    HWND INIT_MAC;

    INIT_IP = GetDlgItem(dig, IDC_MYIPADDRESS);
    INIT_MAC = GetDlgItem(dig, IDC_MYMACADDRESS);
    ZeroMemory(&info, sizeof(PIP_ADAPTER_INFO));

    result = GetAdaptersInfo(info, &size);

    if (result == ERROR_BUFFER_OVERFLOW) {
        info = new IP_ADAPTER_INFO[size];

        GetAdaptersInfo(info, &size);
    }
    sprintf(adr.mac_addr, "%02X-%02X-%02X-%02X-%02X-%02X", info->Address[0], info->Address[1], info->Address[2], info->Address[3], info->Address[4], info->Address[5]);
    sprintf(adr.ip_addr, "%s", info->IpAddressList.IpAddress.String);
    SendMessage(INIT_MAC, LB_DELETESTRING, 0, 0);
    SendMessage(INIT_IP, LB_DELETESTRING, 0, 0);

    SendMessage(INIT_MAC, LB_ADDSTRING, 0, (LPARAM)adr.mac_addr);
    SendMessage(INIT_IP, LB_ADDSTRING, 0, (LPARAM)adr.ip_addr);

    return adr;
}
bool cache_table(int sig) {
    HWND TABLE_STATE, TABLE_QUEUE, TABLE_ATTEMPT, TABLE_TIMEOUT, TABLE_IP, TABLE_MAC;
    TABLE_STATE = GetDlgItem(dig, IDC_LIST10);
    TABLE_QUEUE = GetDlgItem(dig, IDC_LIST15);
    TABLE_ATTEMPT = GetDlgItem(dig, IDC_LIST20);
    TABLE_TIMEOUT = GetDlgItem(dig, IDC_LIST25);
    TABLE_IP = GetDlgItem(dig, IDC_LIST30);
    TABLE_MAC = GetDlgItem(dig, IDC_LIST35);
    if (cache.empty)
        return true;
    switch (sig) {
    case 0:
        strcpy(cache.chState, "FREE");
        cache.nAttempt = 0;
        cache.nQueue = 0;
        cache.nSignal = 0;
        cache.nTimeout = 900;
        cache.empty = TRUE;
        strcpy(cache.chQueue, "");
        strcpy(cache.chAttempt, "");
        strcpy(cache.chTimeout, "");
        strcpy(cache.ip_addr, "");
        strcpy(cache.mac_addr, "");
        break;
    case 1:
        strcpy(cache.chState, "PENDING");
        strcpy(cache.ip_addr, request.TargetIP);
        srand(time(NULL));
        cache.nAttempt++;
        cache.nQueue = rand() % 50 + 1;
        _itoa(cache.nQueue, cache.chQueue, 10);
        _itoa(cache.nAttempt, cache.chAttempt, 10);
        break;
    case 3:
        cache.nAttempt++;
        _itoa(cache.nAttempt, cache.chAttempt, 10);
        break;
    case 2:
        strcpy(cache.mac_addr, reply.SenderMAC);
        _itoa(cache.nQueue, cache.chQueue, 10);
        _itoa(cache.nAttempt, cache.chAttempt, 10);
        _itoa(cache.nTimeout, cache.chTimeout, 10);
        strcpy(cache.chState, "RESOLVED");
        break;
    case 4:
        _itoa(cache.nTimeout, cache.chTimeout, 10);
        if (cache.nTimeout <= 0)
            cache_table(0);
        else
            cache.nTimeout -= 60;
        break;
    }
    SendMessage(TABLE_STATE, LB_DELETESTRING, 0, 0);
    SendMessage(TABLE_IP, LB_DELETESTRING, 0, 0);
    SendMessage(TABLE_QUEUE, LB_DELETESTRING, 0, 0);
    SendMessage(TABLE_ATTEMPT, LB_DELETESTRING, 0, 0);
    SendMessage(TABLE_MAC, LB_DELETESTRING, 0, 0);
    SendMessage(TABLE_TIMEOUT, LB_DELETESTRING, 0, 0);

    SendMessage(TABLE_STATE, LB_ADDSTRING, 0, (LPARAM)cache.chState);
    SendMessage(TABLE_IP, LB_ADDSTRING, 0, (LPARAM)cache.ip_addr);
    SendMessage(TABLE_QUEUE, LB_ADDSTRING, 0, (LPARAM)cache.chQueue);
    SendMessage(TABLE_ATTEMPT, LB_ADDSTRING, 0, (LPARAM)cache.chAttempt);
    SendMessage(TABLE_MAC, LB_ADDSTRING, 0, (LPARAM)cache.mac_addr);
    SendMessage(TABLE_TIMEOUT, LB_ADDSTRING, 0, (LPARAM)cache.chTimeout);
    return true;
}

BOOL ARP_Send() {
    IPAddr ip_addr;
    DWORD result;
    ULONG pMacAddr[2];
    ULONG phyAddrLen;
    Addr local = getLocal();
    phyAddrLen = 6;
    char mac_addr[6 * 3];
    int i, j;
    int k = 0, l, m;
    ip_addr = inet_addr(ip);
    HWND PACKET_HardwareType, PACKET_ProtocolType, PACKET_HardwareLength, PACKET_ProtocolLength, PACKET_Operation,
        PACKET_SenderHardwareAddress, PACKET_SenderProtocolAddress, PACKET_TargetHardwareAddress, PACKET_TargetProtocolAddress;

    cache.empty = FALSE;
    memset(pMacAddr, 0xff, sizeof(pMacAddr));
    PBYTE pbHexMac = (PBYTE)pMacAddr;

    strcpy(request.HardwareLength, "6");
    strcpy(request.HardwareType, "Ethernet(1)");
    strcpy(request.Operation, "1");
    strcpy(request.ProtocolLength, "4");
    strcpy(request.ProtocolType, "0x0800");
    strcpy(request.SenderIP, local.ip_addr);
    strcpy(request.SenderMAC, local.mac_addr);
    strcpy(request.TargetIP, ip);
    strcpy(request.TargetMAC, "0");

    cache_table(1);

    result = SendARP(ip_addr, 0, pMacAddr, &phyAddrLen);

    PACKET_HardwareType = GetDlgItem(dig, IDC_LIST1);  //SendMessage에서 핸들값으로 쓰기 위해 GetDlgItem을 사용하여 LISTBOX의 핸들값을 받아온다.
    PACKET_ProtocolType = GetDlgItem(dig, IDC_LIST2);
    PACKET_HardwareLength = GetDlgItem(dig, IDC_LIST3);
    PACKET_ProtocolLength = GetDlgItem(dig, IDC_LIST4);
    PACKET_Operation = GetDlgItem(dig, IDC_LIST5);
    PACKET_SenderHardwareAddress = GetDlgItem(dig, IDC_LIST6);
    PACKET_SenderProtocolAddress = GetDlgItem(dig, IDC_LIST7);
    PACKET_TargetHardwareAddress = GetDlgItem(dig, IDC_LIST8);
    PACKET_TargetProtocolAddress = GetDlgItem(dig, IDC_LIST9);

    SendMessage(PACKET_HardwareType, LB_DELETESTRING, 0, 0); //위에서 GetDlgItem을 통해 받아온 핸들값을 처음에 적용
    SendMessage(PACKET_ProtocolType, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_HardwareLength, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_ProtocolLength, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_Operation, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_SenderHardwareAddress, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_SenderProtocolAddress, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_TargetHardwareAddress, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_TargetProtocolAddress, LB_DELETESTRING, 0, 0);

    //메시지
    SendMessage(PACKET_HardwareType, LB_ADDSTRING, 0, (LPARAM)request.HardwareType);
    SendMessage(PACKET_ProtocolType, LB_ADDSTRING, 0, (LPARAM)request.ProtocolType);
    SendMessage(PACKET_HardwareLength, LB_ADDSTRING, 0, (LPARAM)request.HardwareLength);
    SendMessage(PACKET_ProtocolLength, LB_ADDSTRING, 0, (LPARAM)request.ProtocolLength);
    SendMessage(PACKET_Operation, LB_ADDSTRING, 0, (LPARAM)request.Operation);
    // 위의 부분은 고정 궁금하면 ARP_PACKET 구조검색
    SendMessage(PACKET_SenderHardwareAddress, LB_ADDSTRING, 0, (LPARAM)request.SenderMAC);   //GetMACAddress 에서 받아온 Mac 주소를 출력
    SendMessage(PACKET_SenderProtocolAddress, LB_ADDSTRING, 0, (LPARAM)request.SenderIP);   //GetMyIP에서 받아온 IP주소를 출력
    SendMessage(PACKET_TargetHardwareAddress, LB_ADDSTRING, 0, (LPARAM)request.TargetMAC);      //ARP_REQUEST에서는 Target의 물리주소를 모르기 때문에 0으로 처리
    SendMessage(PACKET_TargetProtocolAddress, LB_ADDSTRING, 0, (LPARAM)request.TargetIP);   //입력한 Target의 IP 주소를 저장


    while (result != NO_ERROR && k < 5) {
        MessageBox(NULL, "ERROR", NULL, MB_OK);
        k++;
        cache_table(3);
        result = SendARP(ip_addr, 0, pMacAddr, &phyAddrLen);
    }

    for (i = 0, j = 0; i < (int)phyAddrLen - 1; ++i) {
        j += sprintf(mac_addr + j, "%02X:", pbHexMac[i]);
    }
    sprintf(mac_addr + j, "%02X", pbHexMac[i]);
    strcpy(mac, mac_addr);

    strcpy(reply.HardwareLength, "6");
    strcpy(reply.HardwareType, "Ethernet(1)");
    strcpy(reply.Operation, "2");
    strcpy(reply.ProtocolLength, "4");
    strcpy(reply.ProtocolType, "0x0800");
    strcpy(reply.SenderIP, ip);
    strcpy(reply.SenderMAC, mac);
    strcpy(reply.TargetIP, local.ip_addr);
    strcpy(reply.TargetMAC, local.mac_addr);
    //메시지
    SendMessage(PACKET_Operation, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_SenderHardwareAddress, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_SenderProtocolAddress, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_TargetHardwareAddress, LB_DELETESTRING, 0, 0);
    SendMessage(PACKET_TargetProtocolAddress, LB_DELETESTRING, 0, 0);

    SendMessage(PACKET_Operation, LB_INSERTSTRING, 0, (LPARAM)reply.Operation);
    // 위의 부분은 고정 궁금하면 ARP_PACKET 구조검색

    SendMessage(PACKET_SenderHardwareAddress, LB_INSERTSTRING, 0, (LPARAM)reply.SenderMAC);   //GetMACAddress 에서 받아온 Mac 주소를 출력
    SendMessage(PACKET_SenderProtocolAddress, LB_INSERTSTRING, 0, (LPARAM)reply.SenderIP);   //GetMyIP에서 받아온 IP주소를 출력
    SendMessage(PACKET_TargetHardwareAddress, LB_INSERTSTRING, 0, (LPARAM)reply.TargetMAC);      //ARP_REQUEST에서는 Target의 물리주소를 모르기 때문에 0으로 처리
    SendMessage(PACKET_TargetProtocolAddress, LB_INSERTSTRING, 0, (LPARAM)reply.TargetIP);   //입력한 Target의 IP 주소를 저장

    cache_table(2);
    return true;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_inst = hInstance;
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, WinProc);
    return TRUE;
}

BOOL CALLBACK WinProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    dig = hDlg;
    int index = 0;
    int thread_num = 0;

    HDC hDC;
    PAINTSTRUCT ps;

    switch (uMsg) {
    case WM_INITDIALOG:
        getLocal();
        SetTimer(dig, 1, 1000, NULL);
        SendMessage(GetDlgItem(dig, IDC_LIST10), LB_ADDSTRING, 0, (LPARAM)"FREE");
        SendMessage(GetDlgItem(dig, IDC_LIST11), LB_ADDSTRING, 0, (LPARAM)"FREE");
        SendMessage(GetDlgItem(dig, IDC_LIST12), LB_ADDSTRING, 0, (LPARAM)"FREE");
        SendMessage(GetDlgItem(dig, IDC_LIST13), LB_ADDSTRING, 0, (LPARAM)"FREE");
        SendMessage(GetDlgItem(dig, IDC_LIST14), LB_ADDSTRING, 0, (LPARAM)"FREE");
        return TRUE;
    case WM_TIMER:
        cache_table(4);
        return 0;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDSEND:
            GetDlgItemTextA(dig, IDC_INPUTIP, ip, 18);
            ARP_Send();
            return TRUE;
        case IDCANCEL:
            EndDialog(dig, 0);
            return TRUE;
        }
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return FALSE;
}