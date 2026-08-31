// Exercise the production network update and UI callback without WinMain,
// DlgProc, filter installation, application startup, or the network worker.
#include "../src/network.c"
VOID _app_displayinfonetwork_callback (PITEM_NETWORK, LPNMLVDISPINFOW);
VOID _app_config_apply (HWND, HWND, INT);
static void verify_endpoint (SW_UDP_STATS *, const UDP_ENDPOINT *, const UDP_SNAPSHOT *);
static void integration_tests (void);
static void tcp_live_tests (void);
#define UDP_TEST_VERIFY_ENDPOINT verify_endpoint
#define UDP_TEST_EXTRA integration_tests
#define UDP_TEST_LIVE_EXTRA tcp_live_tests
#include "udpstats_test.c"

static void display (PITEM_NETWORK row, INT column, WCHAR *text, INT capacity)
{
	NMLVDISPINFOW notification = {0};
	notification.item.mask = LVIF_TEXT;
	notification.item.iSubItem = column;
	notification.item.pszText = text;
	notification.item.cchTextMax = capacity;
	text[0] = 0;
	_app_displayinfonetwork_callback (row, &notification);
}

static void verify_endpoint (SW_UDP_STATS *stats, const UDP_ENDPOINT *endpoint, const UDP_SNAPSHOT *snapshot)
{
	ITEM_NETWORK row = {0}; ITEM_NETWORK_CONTEXT context = {0};
	WCHAR text[128], expected[64];
	context.udp_stats = stats;
	row.af = endpoint->af; row.protocol = IPPROTO_UDP; row.local_port = endpoint->port;
	memcpy (&row.local_addr, endpoint->address, endpoint->af == AF_INET ? 4 : 16);
	_app_network_update_udp_stats (&row, &context, endpoint->pid, endpoint->created, endpoint->scope_id);
	CHECK (!row.traffic_error && row.is_stats_initialized);
	CHECK (row.download_total == snapshot->received && row.upload_total == snapshot->sent);
	display (&row, 11, text, RTL_NUMBER_OF (text));
	_r_format_bytesize64 (expected, RTL_NUMBER_OF (expected), snapshot->received + snapshot->sent);
	CHECK (wcscmp (text, expected) == 0);
	printf ("UI_UDP port=%u total=%ls\n", endpoint->port, text);
}

static void integration_tests (void)
{
	ITEM_NETWORK row = {0}; WCHAR text[128];
	// A hidden ordinary window exercises the actual option handler. No DlgProc.
	PR_STRING config_path = _r_app_getconfigpath ();
	CHECK (wcsstr (config_path->buffer, L"\\temp\\") != NULL);
	if (!wcsstr (config_path->buffer, L"\\temp\\")) return;
	_r_config_initialize ();
	HWND window = CreateWindowExW (0, L"STATIC", L"test", WS_OVERLAPPED, 0, 0, 200, 100, NULL, NULL, GetModuleHandleW (NULL), NULL);
	HMENU menu = CreateMenu ();
	CHECK (window && menu && AppendMenuW (menu, MF_STRING, IDM_UDPTRAFFIC_CHK, L"UDP/QUIC"));
	SetMenu (window, menu);
	_r_config_setboolean (L"IsUdpTrafficEnabled", FALSE, NULL);
	_app_config_apply (window, NULL, IDM_UDPTRAFFIC_CHK);
	CHECK (_r_config_getboolean (L"IsUdpTrafficEnabled", FALSE, NULL));
	CHECK (GetMenuState (menu, IDM_UDPTRAFFIC_CHK, MF_BYCOMMAND) & MF_CHECKED);
	_app_config_apply (window, NULL, IDM_UDPTRAFFIC_CHK);
	CHECK (!_r_config_getboolean (L"IsUdpTrafficEnabled", TRUE, NULL));
	CHECK (!(GetMenuState (menu, IDM_UDPTRAFFIC_CHK, MF_BYCOMMAND) & MF_CHECKED));
	DestroyWindow (window);
	row.protocol = IPPROTO_UDP; row.traffic_error = ERROR_NOT_READY;
	for (INT column = 9; column <= 11; column++)
	{
		display (&row, column, text, RTL_NUMBER_OF (text)); CHECK (wcscmp (text, L"\x2014") == 0);
	}
	row.traffic_error = ERROR_DATA_NOT_ACCEPTED;
	row.is_stats_initialized = TRUE; // errors take precedence even during an update
	display (&row, 11, text, RTL_NUMBER_OF (text)); CHECK (wcscmp (text, L"\x2014") == 0);
	// The existing TCP baseline / delta behavior is preserved by the shared helper.
	ZeroMemory (&row, sizeof (row)); row.protocol = IPPROTO_TCP;
	_app_network_update_stats_values (&row, 10000, 20000);
	CHECK (row.is_stats_initialized && !row.download_total && !row.upload_total);
	row.last_stats_tick -= 1000;
	_app_network_update_stats_values (&row, 11200, 20800);
	CHECK (row.download_total == 1200 && row.upload_total == 800);
	CHECK (row.download_speed > 0 && row.upload_speed > 0);
	display (&row, 9, text, RTL_NUMBER_OF (text)); CHECK (wcsstr (text, L"/s") != NULL);
	row.last_stats_tick -= 1000;
	_app_network_update_stats_values (&row, 0, 0); // reset cannot wrap to a huge delta
	CHECK (row.download_total == 1200 && row.upload_total == 800 && !row.download_speed);
	printf ("NETWORK_UI_INTEGRATION: %s\n", failures ? "FAIL" : "PASS");
}

static void tcp_live_tests (void)
{
	for (unsigned family = 0; family < 2; family++)
	{
		ADDRESS_FAMILY af = family ? AF_INET6 : AF_INET;
		SOCKADDR_STORAGE address = {0}, local = {0};
		int length = family ? sizeof (SOCKADDR_IN6) : sizeof (SOCKADDR_IN);
		SOCKET listener = socket (af, SOCK_STREAM, IPPROTO_TCP), client = INVALID_SOCKET, accepted = INVALID_SOCKET;
		ITEM_NETWORK row = {0};
		MIB_TCPROW_OWNER_MODULE row4 = {0}; MIB_TCP6ROW_OWNER_MODULE row6 = {0};
		char bytes[1200] = {0}, response[1200];
		DWORD timeout = 2000;
		address.ss_family = af;
		if (family) ((SOCKADDR_IN6 *)&address)->sin6_addr.u.Byte[15] = 1;
		else ((SOCKADDR_IN *)&address)->sin_addr.S_un.S_addr = htonl (INADDR_LOOPBACK);
		CHECK (listener != INVALID_SOCKET && !bind (listener, (SOCKADDR *)&address, length));
		CHECK (!listen (listener, 1) && !getsockname (listener, (SOCKADDR *)&address, &length));
		client = socket (af, SOCK_STREAM, IPPROTO_TCP);
		CHECK (client != INVALID_SOCKET && !connect (client, (SOCKADDR *)&address, length));
		accepted = accept (listener, NULL, NULL);
		CHECK (accepted != INVALID_SOCKET && !getsockname (client, (SOCKADDR *)&local, &length));
		setsockopt (accepted, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof (timeout));
		if (family)
		{
			memcpy (row6.ucLocalAddr, &((SOCKADDR_IN6 *)&local)->sin6_addr, 16);
			memcpy (row6.ucRemoteAddr, &((SOCKADDR_IN6 *)&address)->sin6_addr, 16);
			row6.dwLocalPort = ((SOCKADDR_IN6 *)&local)->sin6_port; row6.dwRemotePort = ((SOCKADDR_IN6 *)&address)->sin6_port;
			row6.dwState = MIB_TCP_STATE_ESTAB;
			_app_network_update_tcp6_stats (&row, &row6);
		}
		else
		{
			row4.dwLocalAddr = ((SOCKADDR_IN *)&local)->sin_addr.S_un.S_addr; row4.dwRemoteAddr = ((SOCKADDR_IN *)&address)->sin_addr.S_un.S_addr;
			row4.dwLocalPort = ((SOCKADDR_IN *)&local)->sin_port; row4.dwRemotePort = ((SOCKADDR_IN *)&address)->sin_port;
			row4.dwState = MIB_TCP_STATE_ESTAB;
			_app_network_update_tcp4_stats (&row, &row4);
		}
		CHECK (row.is_stats_initialized && row.is_stats_enabled);
		for (unsigned i = 0; i < 100; i++)
		{
			CHECK (send (client, bytes, sizeof (bytes), 0) == sizeof (bytes));
			CHECK (recv (accepted, response, sizeof (response), MSG_WAITALL) == sizeof (response));
		}
		Sleep (50);
		if (family) _app_network_update_tcp6_stats (&row, &row6); else _app_network_update_tcp4_stats (&row, &row4);
		CHECK (row.upload_total == 120000 && row.download_total == 0);
		printf ("TCP%d_REGRESSION sent=%llu received=%llu initialized=%d\n", family ? 6 : 4, row.upload_total, row.download_total, row.is_stats_initialized);
		closesocket (accepted); closesocket (client); closesocket (listener);
	}
}
