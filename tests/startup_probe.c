// Run the actual GUI entry point with a test-only WFP object that cannot open
// the filtering engine or toggle Windows Firewall. Never ship this executable.
#include "../src/global.h"
#include <dbghelp.h>
#include <evntrace.h>
#include <stdio.h>
#pragma comment(lib,"dbghelp.lib")
INT APIENTRY wWinMain (HINSTANCE,HINSTANCE,LPWSTR,INT);
PITEM_NETWORK_CONTEXT _app_network_getcontext (void);
VOID _app_displayinfonetwork_callback (PITEM_NETWORK,LPNMLVDISPINFOW);
static volatile LONG failures;
static volatile LONG checked;
#define CHECK(value) do { if(!(value)) { printf("FAIL line %d: %s\n",__LINE__,#value); InterlockedIncrement(&failures); } } while(0)

static void frame_symbol (DWORD64 address)
{
    BYTE storage[sizeof(SYMBOL_INFO)+MAX_SYM_NAME] = {0};
    SYMBOL_INFO *symbol=(SYMBOL_INFO *)storage;
    DWORD64 displacement=0;
    symbol->SizeOfStruct=sizeof(*symbol); symbol->MaxNameLen=MAX_SYM_NAME;
    if(SymFromAddr(GetCurrentProcess(),address,&displacement,symbol))
        printf("  %s+0x%llx\n",symbol->Name,displacement);
    else printf("  address=0x%llx\n",address);
}

static LONG CALLBACK fault (EXCEPTION_POINTERS *exception)
{
    static volatile LONG reporting;
    if(exception->ExceptionRecord->ExceptionCode!=EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    // DbgHelp is single-threaded; let the first fault finish its report.
    if(InterlockedCompareExchange(&reporting,1,0))
    {
        Sleep(30000);
        ExitProcess(1);
    }
    printf("ACCESS_VIOLATION operation=%llu target=0x%llx\n",exception->ExceptionRecord->ExceptionInformation[0],exception->ExceptionRecord->ExceptionInformation[1]);
    SymSetOptions(SYMOPT_UNDNAME|SYMOPT_LOAD_LINES|SYMOPT_DEFERRED_LOADS);
    SymInitialize(GetCurrentProcess(),NULL,TRUE);
    CONTEXT context=*exception->ContextRecord;
    frame_symbol(context.Rip);
    STACKFRAME64 frame={0};
    frame.AddrPC.Offset=context.Rip; frame.AddrPC.Mode=AddrModeFlat;
    frame.AddrStack.Offset=context.Rsp; frame.AddrStack.Mode=AddrModeFlat;
    frame.AddrFrame.Offset=context.Rbp; frame.AddrFrame.Mode=AddrModeFlat;
    for(unsigned i=0;i<30;i++)
    {
        if(!StackWalk64(IMAGE_FILE_MACHINE_AMD64,GetCurrentProcess(),GetCurrentThread(),&frame,&context,NULL,SymFunctionTableAccess64,SymGetModuleBase64,NULL)) break;
        if(!frame.AddrPC.Offset) break;
        frame_symbol(frame.AddrPC.Offset);
    }
    fflush(stdout);
    ExitProcess(1);
}

static BOOL owner_endpoint(USHORT port,UDP_ENDPOINT *key)
{
    ULONG required=0;
    GetExtendedUdpTable(NULL,&required,FALSE,AF_INET,UDP_TABLE_OWNER_MODULE,0);
    if(!required) return FALSE;
    PMIB_UDPTABLE_OWNER_MODULE table=(PMIB_UDPTABLE_OWNER_MODULE)_r_mem_allocate(required);
    BOOL found=FALSE;
    if(GetExtendedUdpTable(table,&required,FALSE,AF_INET,UDP_TABLE_OWNER_MODULE,0)==NO_ERROR)
    {
        for(ULONG i=0;i<table->dwNumEntries;i++)
        {
            if(table->table[i].dwOwningPid!=GetCurrentProcessId() || _r_byteswap_ushort((USHORT)table->table[i].dwLocalPort)!=port) continue;
            ZeroMemory(key,sizeof(*key));
            key->pid=GetCurrentProcessId(); key->af=AF_INET; key->port=port;
            memcpy(key->address,&table->table[i].dwLocalAddr,4);
            key->created=table->table[i].liCreateTimestamp.QuadPart;
            found=TRUE; break;
        }
    }
    _r_mem_free(table);
    return found;
}

static void live_udp(HWND window)
{
    WSADATA wsa;
    CHECK(!WSAStartup(MAKEWORD(2,2),&wsa));
    SOCKET endpoint=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    CHECK(endpoint!=INVALID_SOCKET);
    if(endpoint==INVALID_SOCKET) return;
    SOCKADDR_IN address={0}; INT length=sizeof(address);
    address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    DWORD timeout=2000;
    CHECK(!setsockopt(endpoint,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(timeout)));
    CHECK(!bind(endpoint,(SOCKADDR *)&address,sizeof(address)));
    CHECK(!getsockname(endpoint,(SOCKADDR *)&address,&length));
    UDP_ENDPOINT key; UDP_SNAPSHOT snapshot={0}; BOOL found=FALSE;
    PITEM_NETWORK_CONTEXT network=_app_network_getcontext();
    // Establish the same owner-table baseline that the production refresh uses.
    // Only traffic after that baseline belongs in the displayed total.
    for(unsigned attempt=0;attempt<20 && !found;attempt++)
    {
        found=owner_endpoint(ntohs(address.sin_port),&key);
        if(!found) Sleep(100);
    }
    CHECK(found);
    udp_stats_read(network->udp_stats,&key,&snapshot);
    CHECK(snapshot.error==ERROR_NOT_READY && !snapshot.sent && !snapshot.received);
    char payload[1200]={0},received[1200];
    for(unsigned i=0;i<100;i++)
    {
        INT sent=sendto(endpoint,payload,sizeof(payload),0,(SOCKADDR *)&address,sizeof(address));
        CHECK(sent==sizeof(payload));
        if(sent!=sizeof(payload)) break;
        INT count=recv(endpoint,received,sizeof(received),0);
        CHECK(count==sizeof(payload));
        if(count!=sizeof(payload)) break;
    }
    HWND list=GetDlgItem(window,IDC_NETWORK);
    CHECK(list && IsWindowVisible(list));
    found=FALSE;
    for(unsigned attempt=0;attempt<30 && !found;attempt++)
    {
        INT rows=(INT)SendMessageW(list,LVM_GETITEMCOUNT,0,0);
        if(attempt==0) printf("NETWORK_ROWS=%d backend=%zu\n",rows,_r_obj_gethashtablesize(_app_network_getcontext()->network_ptr));
        CHECK(rows>0);
        udp_stats_poll(network->udp_stats);
        udp_stats_read(network->udp_stats,&key,&snapshot);
        found=!snapshot.error && snapshot.sent==120000 && snapshot.received==120000;
        if(!found) Sleep(500);
    }
    CHECK(found);
    printf("GUI_UDP port=%u sent=%llu received=%llu matched=%d\n",ntohs(address.sin_port),snapshot.sent,snapshot.received,found);
    closesocket(endpoint); WSACleanup();
}

static DWORD WINAPI finish_probe (void *unused)
{
    UNREFERENCED_PARAMETER(unused);
    Sleep(12000);
    HWND window=_r_app_gethwnd(); DWORD_PTR result=0;
    BOOL responsive=window && SendMessageTimeoutW(window,WM_NULL,0,0,SMTO_ABORTIFHUNG,2000,&result);
    PITEM_NETWORK_CONTEXT context=_app_network_getcontext();
    printf("GUI hwnd=%p responsive=%d network_context=%p\n",window,responsive,context);
    CHECK(responsive && context);
    if(responsive && context)
    {
        // The launcher hides the initial console; the real UI must be visible
        // for Simplewall's normal list refresh to run.
        ShowWindow(window,SW_SHOWNOACTIVATE);
        PITEM_TAB_CONTEXT tab=_app_listview_getcontext(window,INT_ERROR);
        printf("GUI_VISIBLE=%d selected_list=%d\n",IsWindowVisible(window),tab?tab->listview_id:0);
        BOOLEAN enabled=_r_config_getboolean(L"IsUdpTrafficEnabled",FALSE,NULL);
        BOOL menu_checked=!!(GetMenuState(GetMenu(window),IDM_UDPTRAFFIC_CHK,MF_BYCOMMAND)&MF_CHECKED);
        CHECK(menu_checked==enabled);
        CHECK(!!context->udp_stats==enabled);
        printf("UDP_OPTION enabled=%u checked=%d collector=%d\n",enabled,menu_checked,!!context->udp_stats);
        if(enabled && context->udp_stats)
        {
            CHECK(udp_stats_poll(context->udp_stats)==ERROR_SUCCESS);
            live_udp(window);
        }
    }
    InterlockedExchange(&checked,1);
    if(responsive) PostMessageW(window,WM_CLOSE,0,0);
    Sleep(4000);
    printf("TIMEOUT closing probe\n");
    ExitProcess(2);
}

static DWORD WINAPI hard_timeout(void *unused)
{
    UNREFERENCED_PARAMETER(unused);
    Sleep(55000);
    printf("TIMEOUT during startup probe\n");
    ExitProcess(2);
}

int main (void)
{
    FILE *report;
    if(freopen_s(&report,"startup-report.txt","w",stdout)) return 3;
    setvbuf(stdout,NULL,_IONBF,0);
    printf("STARTUP_PROBE: WFP engine and firewall toggle disabled in test object\n");
    AddVectoredExceptionHandler(1,fault);
    HANDLE watchdog=CreateThread(NULL,0,hard_timeout,NULL,0,NULL);
    CHECK(watchdog!=NULL);
    if(watchdog) CloseHandle(watchdog);
    watchdog=CreateThread(NULL,0,finish_probe,NULL,0,NULL);
    CHECK(watchdog!=NULL);
    if(watchdog) CloseHandle(watchdog);
    INT result=wWinMain(GetModuleHandleW(NULL),NULL,L"",SW_SHOWNORMAL);
    printf("GUI_EXIT=%d\n",result);
    CHECK(result==0 && checked);
    struct { EVENT_TRACE_PROPERTIES properties; WCHAR name[128]; } trace={0};
    trace.properties.Wnode.BufferSize=sizeof(trace);
    trace.properties.LoggerNameOffset=FIELD_OFFSET(typeof(trace),name);
    ULONG status=ControlTraceW(0,L"simplewall-UDP",&trace.properties,EVENT_TRACE_CONTROL_QUERY);
    CHECK(status==ERROR_WMI_INSTANCE_NOT_FOUND);
    printf("SESSION_CLEANUP=%lu\nSTARTUP_RESULT: %ld failures\n",status,failures);
    return failures?1:0;
}
