// Exercise the public SDK adapter without running Simplewall or touching WFP.
#include "../tools/public-sdk/routine-compat.h"

static unsigned failures;
#define CHECK(value) do { if (!(value)) { printf("FAIL line %d: %s\n",__LINE__,#value); failures++; } } while (0)

static VOID NTAPI signal_test_thread(PVOID argument) { SetEvent((HANDLE)argument); }

static void version_resource(void)
{
    WCHAR path[MAX_PATH];
    CHECK(GetSystemDirectoryW(path,RTL_NUMBER_OF(path))>0);
    CHECK(wcscat_s(path,RTL_NUMBER_OF(path),L"\\kernel32.dll")==0);
    R_STRINGREF name;
    _r_obj_initializestringref(&name,path);
    HINSTANCE module=NULL;
    CHECK(NT_SUCCESS(_r_sys_loadlibraryasresource(&module,&name)));
    if(!module) return;
    R_STORAGE resource={0};
    NTSTATUS status=_r_res_loadresource(&resource,module,RT_VERSION,MAKEINTRESOURCE(VS_VERSION_INFO),0);
    CHECK(NT_SUCCESS(status));
    if(NT_SUCCESS(status))
    {
        // Match the application's startup path, including a read-only mapped
        // resource. Reversing these void-pointer arguments used to write here.
        VS_FIXEDFILEINFO *version=NULL;
        CHECK(_r_res_queryversion((PVOID_PTR)&version,resource.buffer));
        CHECK(version && version->dwSignature==VS_FFI_SIGNATURE);
        CHECK(version && HIWORD(version->dwFileVersionMS)>0);
        LCID language=_r_res_querytranslation(resource.buffer);
        PR_STRING description=_r_res_querystring(resource.buffer,L"FileDescription",language);
        CHECK(description && description->length>0);
        if(description) _r_obj_dereference(description);
    }
    _r_sys_freelibrary(module);
}

static void strings_and_table(void)
{
    WCHAR bounded[] = {L'A',L'b',L'C',L'X'};
    R_STRINGREF ref = {0};
    ref.buffer=bounded; ref.length=3*sizeof(WCHAR);
    // No terminator exists in this allocation: max_length must be honored.
    CHECK(_r_str_getlength_ex(bounded,3)==3);
    CHECK(_r_str_gethash(&ref,TRUE)==_r_str_gethash2(L"abc",TRUE));
    CHECK(_r_str_gethash(&ref,FALSE)!=_r_str_gethash2(L"abc",FALSE));
    CHECK(wcscmp(_r_path_getbasename2(L"C:\\folder\\app.exe"),L"app.exe")==0);
    R_STRINGREF drive=PR_STRINGREF_INIT(L"c:\\test");
    CHECK(_r_path_getdrivenumber(&drive)==2);
    R_STRINGREF unc=PR_STRINGREF_INIT(L"\\\\server\\share");
    CHECK(_r_path_isnetwork(&unc));
    PR_HASHTABLE table=_r_obj_createhashtable(sizeof(ULONG),4,NULL);
    ULONG expected=321;
    _r_obj_addhashtableitem(table,0xf1234567U,&expected);
    struct { ULONG hash; ULONG sentinel; } result={0,0xdeadbeef};
    ULONG_PTR cursor=0;
    PVOID value=NULL;
    CHECK(_r_obj_enumhashtable(table,&value,&result.hash,&cursor));
    CHECK(result.hash==0xf1234567U && result.sentinel==0xdeadbeef);
    CHECK(value && *(ULONG *)value==expected);
    CHECK(!_r_obj_enumhashtable(table,&value,NULL,&cursor));
    _r_obj_dereference(table);

    R_STRINGREF image={0};
    WCHAR module[MAX_PATH];
    GetModuleFileNameW(NULL,module,RTL_NUMBER_OF(module));
    _r_obj_initializestringref(&image,module);
    CHECK(_r_str_gethash(_r_sys_getimagepath(),TRUE)==_r_str_gethash(&image,TRUE));
    FILETIME time; LARGE_INTEGER timestamp;
    _r_unixtime_to_filetime(&time,0);
    _r_calc_filetime2largeinteger(&timestamp,&time);
    CHECK(timestamp.QuadPart==116444736000000000LL);
}

static void configuration(void)
{
    PR_STRING directory=_r_app_getdirectory();
    PR_STRING path=_r_app_getconfigpath();
    BOOL inside=path && directory && wcsncmp(path->buffer,directory->buffer,directory->length/sizeof(WCHAR))==0 && path->buffer[directory->length/sizeof(WCHAR)]==L'\\';
    CHECK(inside);
    if (!inside) return;
    _r_config_initialize();
    _r_config_setboolean(L"IsEnabled",TRUE,L"compat-section-a");
    _r_config_setboolean(L"IsEnabled",FALSE,L"compat-section-b");
    CHECK(_r_config_getboolean(L"IsEnabled",FALSE,L"compat-section-a"));
    CHECK(!_r_config_getboolean(L"IsEnabled",TRUE,L"compat-section-b"));
    CHECK(!_r_config_invertboolean(L"IsEnabled",FALSE,L"compat-section-a"));
    _r_config_setlong64(L"Total",1234567890123LL,L"compat-test");
    CHECK(_r_config_getlong64(L"Total",0,L"compat-test")==1234567890123LL);
}

static void files_and_compression(void)
{
    PR_STRING directory=_r_app_getdirectory();
    PR_STRING path=_r_format_string(L"%s\\fixture-%lu-%llu.dat",directory->buffer,GetCurrentProcessId(),GetTickCount64());
    PR_STRING link=_r_format_string(L"%s.link",path->buffer);
    HANDLE file=NULL, linked=NULL;
    NTSTATUS status=_r_fs_createfile(&file,&path->sr,FILE_CREATE,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,FILE_ATTRIBUTE_NORMAL,0,FALSE,NULL);
    CHECK(NT_SUCCESS(status));
    if (NT_SUCCESS(status))
    {
        DWORD written=0;
        CHECK(WriteFile(file,"abc",3,&written,NULL) && written==3);
        CHECK(NT_SUCCESS(_r_fs_setpos(file,0)));
        LONG64 size=0;
        CHECK(NT_SUCCESS(_r_fs_getsize(NULL,file,&size)) && size==3);
        PR_STRING hash=NULL;
        CHECK(NT_SUCCESS(_r_crypt_getfilehash(&hash,BCRYPT_SHA256_ALGORITHM,NULL,file)));
        CHECK(hash && _wcsicmp(hash->buffer,L"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")==0);
        if (hash) _r_obj_dereference(hash);
        CHECK(_r_fs_isexists(&path->sr));
        CHECK(NT_SUCCESS(_r_fs_createhardlink(&path->sr,&link->sr)));
        CHECK(NT_SUCCESS(_r_fs_openfile(&linked,&link->sr,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,0,FALSE)));
        if (linked)
        {
            BY_HANDLE_FILE_INFORMATION first,second;
            CHECK(GetFileInformationByHandle(file,&first));
            CHECK(GetFileInformationByHandle(linked,&second));
            CHECK(first.nFileIndexLow==second.nFileIndexLow && first.nFileIndexHigh==second.nFileIndexHigh);
            NtClose(linked);
        }
        NtClose(file);
        CHECK(DeleteFileW(link->buffer));
        CHECK(DeleteFileW(path->buffer));
    }
    PR_STRING missing=_r_format_string(L"%s.missing",path->buffer);
    PR_STRING hash=(PR_STRING)(ULONG_PTR)1;
    CHECK(!NT_SUCCESS(_r_crypt_getfilehash(&hash,BCRYPT_SHA256_ALGORITHM,&missing->sr,NULL)));
    CHECK(hash==NULL);
    _r_obj_dereference(missing); _r_obj_dereference(path); _r_obj_dereference(link);

    BYTE payload[8192]; memset(payload,0x5a,sizeof(payload));
    R_BYTEREF input={0}; input.buffer=(LPSTR)payload; input.length=sizeof(payload);
    PR_BYTE compressed=NULL,restored=NULL;
    CHECK(NT_SUCCESS(_r_sys_compressbuffer(&compressed,COMPRESSION_FORMAT_LZNT1,&input)));
    if (compressed)
    {
        CHECK(NT_SUCCESS(_r_sys_decompressbuffer(&restored,COMPRESSION_FORMAT_LZNT1,&compressed->sr)));
        CHECK(restored && restored->length==sizeof(payload) && memcmp(restored->buffer,payload,sizeof(payload))==0);
        _r_obj_dereference(compressed);
    }
    if (restored) _r_obj_dereference(restored);
    input.length=(ULONG_PTR)PR_SIZE_BUFFER_OVERFLOW+1;
    restored=(PR_BYTE)(ULONG_PTR)1;
    CHECK(_r_sys_decompressbuffer(&restored,COMPRESSION_FORMAT_LZNT1,&input)==STATUS_BUFFER_OVERFLOW);
    CHECK(restored==NULL);
}

static void handles_and_ui(void)
{
    BYTE sid[SECURITY_MAX_SID_SIZE],unchanged[SECURITY_MAX_SID_SIZE];
    DWORD sid_size=sizeof(sid);
    CHECK(CreateWellKnownSid(WinLocalSystemSid,NULL,sid,&sid_size));
    memcpy(unchanged,sid,sid_size);
    PR_STRING sid_text=NULL;
    CHECK(NT_SUCCESS(_r_str_fromsid(&sid_text,sid)));
    CHECK(sid_text && wcscmp(sid_text->buffer,L"S-1-5-18")==0);
    CHECK(memcmp(unchanged,sid,sid_size)==0);
    if(sid_text) _r_obj_dereference(sid_text);
    HANDLE process=NULL,token=NULL,key=NULL;
    CHECK(NT_SUCCESS(_r_sys_openprocess(&process,GetCurrentProcessId(),PROCESS_QUERY_LIMITED_INFORMATION)));
    if (process)
    {
        PR_STRING name=NULL;
        CHECK(NT_SUCCESS(_r_sys_queryprocessstring(&name,process,ProcessImageFileNameWin32)));
        CHECK(name && _r_str_gethash(&name->sr,TRUE)==_r_str_gethash(_r_sys_getimagepath(),TRUE));
        if(name) _r_obj_dereference(name);
        CHECK(OpenProcessToken(process,TOKEN_QUERY,&token));
        if(token)
        {
            PVOID user=NULL;
            CHECK(NT_SUCCESS(_r_sys_querytokeninformation(&user,token,TokenUser)));
            CHECK(user && IsValidSid(((TOKEN_USER *)user)->User.Sid));
            if(user) _r_mem_free(user);
            NtClose(token);
        }
        NtClose(process);
    }
    CHECK(NT_SUCCESS(_r_reg_openkey(&key,HKEY_LOCAL_MACHINE,L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",0,KEY_READ)));
    if(key) NtClose(key);
    PR_BYTE service=NULL;
    CHECK(NT_SUCCESS(_r_sys_getservicesid(&service,L"RpcSs")));
    CHECK(service && IsValidSid(service->buffer));
    if(service)
    {
        BYTE expected[SECURITY_MAX_SID_SIZE]; DWORD size=sizeof(expected),domain_size=64; WCHAR domain[64]; SID_NAME_USE use;
        CHECK(LookupAccountNameW(NULL,L"NT SERVICE\\RpcSs",expected,&size,domain,&domain_size,&use));
        CHECK(EqualSid(service->buffer,expected));
        _r_obj_dereference(service);
    }
    HANDLE event=CreateEventW(NULL,TRUE,FALSE,NULL),thread=NULL;
    CHECK(NT_SUCCESS(_r_sys_createthread(&thread,NtCurrentProcess(),signal_test_thread,event,NULL,L"CompatTest")));
    if(thread)
    {
        CHECK(WaitForSingleObject(event,0)==WAIT_TIMEOUT);
        CHECK(NT_SUCCESS(NtResumeThread(thread,NULL)));
        CHECK(WaitForSingleObject(event,5000)==WAIT_OBJECT_0);
        CHECK(WaitForSingleObject(thread,5000)==WAIT_OBJECT_0);
        NtClose(thread);
    }
    if(event) CloseHandle(event);
    INITCOMMONCONTROLSEX controls={sizeof(controls),ICC_WIN95_CLASSES};
    CHECK(InitCommonControlsEx(&controls));
    HWND window=CreateWindowExW(0,L"STATIC",L"Compatibility test",WS_OVERLAPPED,0,0,320,200,NULL,NULL,GetModuleHandleW(NULL),NULL);
    CHECK(window!=NULL);
    if(window)
    {
        HWND list=CreateWindowExW(0,WC_LISTVIEWW,L"",WS_CHILD|LVS_REPORT,0,50,200,100,window,(HMENU)12,GetModuleHandleW(NULL),NULL);
        CHECK(list!=NULL);
        CHECK(_r_listview_additem(window,12,INT_ERROR,L"first",I_DEFAULT,I_DEFAULT,71)==0);
        CHECK(_r_listview_additem(window,12,INT_ERROR,L"second",I_DEFAULT,I_DEFAULT,72)==1);
        CHECK(_r_listview_getitemcount(window,12)==2);
        CHECK(_r_wnd_setcontext(window,51,(PVOID)(ULONG_PTR)123));
        CHECK(_r_wnd_getcontext(window,51)==(PVOID)(ULONG_PTR)123);
        CHECK(_r_wnd_removecontext(window,51));
        CHECK(_r_wnd_getcontext(window,51)==NULL);
        HWND edit=CreateWindowExW(0,L"EDIT",L"hello",WS_CHILD,0,0,100,20,window,(HMENU)10,GetModuleHandleW(NULL),NULL);
        CHECK(edit!=NULL);
        if(edit)
        {
            DWORD start=99,end=99;
            _r_edit_setselection(window,10,0,-1);
            SendMessageW(edit,EM_GETSEL,(WPARAM)&start,(LPARAM)&end);
            CHECK(start==0 && end==5);
            CHECK(_r_edit_setreadonly(window,10,TRUE));
            CHECK(GetWindowLongW(edit,GWL_STYLE)&ES_READONLY);
            _r_edit_setmargin(window,10,3,7);
            CHECK(SendMessageW(edit,EM_GETMARGINS,0,0)==MAKELPARAM(3,7));
        }
        HWND button=CreateWindowExW(0,L"BUTTON",L"check",WS_CHILD|BS_AUTOCHECKBOX,0,25,100,20,window,(HMENU)11,GetModuleHandleW(NULL),NULL);
        CHECK(button!=NULL);
        _r_button_setcheck(window,11,TRUE); CHECK(_r_button_ischecked(window,11));
        _r_button_setcheck(window,11,FALSE); CHECK(!_r_button_ischecked(window,11));
        DestroyWindow(window);
    }
}

int main(void)
{
    setvbuf(stdout,NULL,_IONBF,0);
    strings_and_table(); configuration(); files_and_compression(); handles_and_ui(); version_resource();
    printf("PUBLIC SDK CONTRACT TESTS: %u failures\n",failures);
    return failures?1:0;
}
