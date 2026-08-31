// Compile the production implementation directly so event parsing and failure
// paths can be exercised without administrator rights or a running ETW session.
#include <winsock2.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <stdio.h>
static unsigned events_seen, own_seen;
static void diagnostic (EVENT_RECORD *event)
{
    events_seen++;
    if (event->EventHeader.ProviderId.Data1 == 0xe53c6823 && event->EventHeader.ProcessId == GetCurrentProcessId ()) own_seen++;
}
#define UDP_STATS_DIAGNOSTIC diagnostic

#include "../src/udpstats.c"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static unsigned failures;
#define CHECK(test) do { if (!(test)) { printf ("FAIL line %d: %s\n", __LINE__, #test); failures++; } } while (0)

// Hand-built AFD metadata fixtures cover both kernel pointer widths. Buffer
// bytes are never packet contents; fields match the provider's event templates.
static void afd_fixture (SW_UDP_STATS *stats, const UDP_ENDPOINT *endpoint, ULONG width, USHORT id, DWORD stage, DWORD bytes, DWORD status)
{
	BYTE data[96] = {0}; EVENT_RECORD event = {0};
	ULONG prefix = 8 + 2 * width, length = prefix;
	ULONGLONG handle = 0x12340;
	event.UserContext = stats; event.UserData = data;
	event.EventHeader.ProviderId = afd_provider;
	event.EventHeader.Flags = width == 4 ? EVENT_HEADER_FLAG_32_BIT_HEADER : EVENT_HEADER_FLAG_64_BIT_HEADER;
	event.EventHeader.EventDescriptor.Id = id;
	event.EventHeader.TimeStamp.QuadPart = udp_now ();
	memcpy (data, &stage, 4); memcpy (data + 8 + width, &handle, width);
	if (id == 1000)
	{
		DWORD af = endpoint->af, type = bytes ? SOCK_STREAM : SOCK_DGRAM, protocol = bytes ? IPPROTO_TCP : IPPROTO_UDP;
		memcpy (data + prefix, &af, 4); memcpy (data + prefix + 4, &type, 4); memcpy (data + prefix + 8, &protocol, 4);
		memcpy (data + prefix + 12, &endpoint->pid, 4); memcpy (data + prefix + 12 + width, &status, 4);
		length = prefix + 16 + width;
	}
	else if (id == 1030)
	{
		DWORD address_length = endpoint->af == AF_INET ? 16 : 28;
		USHORT port = htons (endpoint->port);
		memcpy (data + prefix, &status, 4); memcpy (data + prefix + 4, &address_length, 4);
		memcpy (data + prefix + 8, &endpoint->af, 2); memcpy (data + prefix + 10, &port, 2);
		memcpy (data + prefix + (endpoint->af == AF_INET ? 12 : 16), endpoint->address, endpoint->af == AF_INET ? 4 : 16);
		if (endpoint->af == AF_INET6) memcpy (data + prefix + 32, &endpoint->scope_id, 4);
		length = prefix + 8 + address_length;
	}
	else if (id == 4006) { memcpy (data, &handle, width); length = width; }
	else if (id != 1001 && id != 1002)
	{
		DWORD buffers = 1;
		memcpy (data + prefix, &buffers, 4); memcpy (data + prefix + 4 + width, &bytes, 4);
		memcpy (data + prefix + 8 + width, &status, 4); length = prefix + 12 + width;
	}
	event.UserDataLength = (USHORT)length;
	udp_event (&event);
}

static void afd_tests (void)
{
	for (ULONG width = 4; width <= 8; width += 4)
	for (unsigned family = 0; family < 2; family++)
	{
		SW_UDP_STATS *stats = udp_stats_create ();
		UDP_ENDPOINT endpoint = {0}, other; UDP_SNAPSHOT snapshot;
		InterlockedExchange (&stats->error, 0);
		endpoint.pid = 3456; endpoint.port = 55001; endpoint.created = 1;
		endpoint.af = family ? AF_INET6 : AF_INET;
		endpoint.address[family ? 15 : 3] = 1;
		endpoint.scope_id = family ? 4 : 0;
		udp_stats_read (stats, &endpoint, &snapshot);
		afd_fixture (stats, &endpoint, width, 1007, 1, 999, 0); // pre-existing/unmapped socket
		udp_stats_read (stats, &endpoint, &snapshot); CHECK (snapshot.error == ERROR_NOT_READY);
		afd_fixture (stats, &endpoint, width, 1000, 0, 0, 0);
		afd_fixture (stats, &endpoint, width, 1007, 1, 999, 0); // not bound yet
		udp_stats_read (stats, &endpoint, &snapshot); CHECK (snapshot.error == ERROR_NOT_READY);
		afd_fixture (stats, &endpoint, width, 1030, 1, 0, 0);
		if (family)
		{
			other = endpoint; other.scope_id++;
			udp_stats_read (stats, &other, &snapshot);
		}
		const USHORT sends[] = {1003,1005,1007,1011,1013}, receives[] = {1004,1006,1009,1012,1015};
		for (unsigned i = 0; i < 5; i++)
		{
			afd_fixture (stats, &endpoint, width, sends[i], 0, 999, 0); // request is not completion
			afd_fixture (stats, &endpoint, width, sends[i], 1, 999, 0x103); // pending
			afd_fixture (stats, &endpoint, width, receives[i], 1, 999, 0xc0000120); // cancelled
			afd_fixture (stats, &endpoint, width, sends[i], 1, 1200, 0);
			afd_fixture (stats, &endpoint, width, receives[i], 1, 800, 0);
		}
		udp_stats_read (stats, &endpoint, &snapshot);
		CHECK (!snapshot.error && snapshot.sent == 6000 && snapshot.received == 4000);
		if (family) { udp_stats_read (stats, &other, &snapshot); CHECK (snapshot.error == ERROR_NOT_READY); }
		// Reused kernel handle must not keep crediting an old UDP socket as TCP.
		afd_fixture (stats, &endpoint, width, 1000, 0, 1, 0);
		CHECK (stats->socket_count == 0);
		afd_fixture (stats, &endpoint, width, 1003, 1, 999, 0);
		udp_stats_read (stats, &endpoint, &snapshot); CHECK (snapshot.sent == 6000);
		afd_fixture (stats, &endpoint, width, 1000, 0, 0, 0);
		afd_fixture (stats, &endpoint, width, 1030, 1, 0, 0);
		afd_fixture (stats, &endpoint, width, 4006, 0, 0, 0);
		udp_stats_read (stats, &endpoint, &snapshot); CHECK (snapshot.error == ERROR_NOT_SUPPORTED);
		afd_fixture (stats, &endpoint, width, 1002, 0, 0, 0);
		CHECK (stats->socket_count == 0);
		afd_fixture (stats, &endpoint, width, 1001, 0, 0, 0); // duplicate cleanup is harmless
		udp_stats_destroy (stats);
	}
}

static void refresh_collision_tests (void)
{
	SW_UDP_STATS *stats = udp_stats_create ();
	UDP_ENDPOINT endpoints[5] = {0};
	UDP_SNAPSHOT snapshot;
	CHECK (stats != NULL);
	if (!stats)
		return;
	InterlockedExchange (&stats->error, 0);
	udp_stats_begin_refresh (stats);
	for (unsigned i = 0; i < 5; i++)
	{
		endpoints[i].pid = 1234;
		endpoints[i].af = i == 0 ? AF_INET6 : AF_INET;
		endpoints[i].port = (USHORT)(5000 + i * UDP_BUCKETS);
		endpoints[i].created = 1;
		udp_stats_read (stats, &endpoints[i], &snapshot);
		CHECK (snapshot.error == ERROR_NOT_READY);
	}
	CHECK (stats->count == 5);
	// One collision chain: prune its head and middle, keep refreshed rows,
	// and retain its stale IPv6 tail while that table's enumeration has failed.
	udp_stats_begin_refresh (stats);
	udp_stats_read (stats, &endpoints[1], &snapshot);
	udp_stats_read (stats, &endpoints[3], &snapshot);
	udp_stats_end_refresh (stats, TRUE, FALSE);
	CHECK (stats->count == 3);
	UDP_ENTRY *entry = stats->buckets[udp_bucket (1234, 5000)];
	const unsigned retained[] = {3, 1, 0};
	for (unsigned i = 0; i < sizeof (retained) / sizeof (retained[0]); i++)
	{
		CHECK (entry != NULL);
		if (!entry)
			break;
		CHECK (entry->endpoint.port == endpoints[retained[i]].port);
		entry = entry->next;
	}
	CHECK (entry == NULL);
	udp_stats_end_refresh (stats, FALSE, TRUE);
	CHECK (stats->count == 2);
	udp_stats_begin_refresh (stats);
	udp_stats_end_refresh (stats, TRUE, TRUE);
	CHECK (stats->count == 0);
	CHECK (stats->buckets[udp_bucket (1234, 5000)] == NULL);
	udp_stats_destroy (stats);
}

static void inject (SW_UDP_STATS *stats, const UDP_ENDPOINT *endpoint, BOOL receive, DWORD bytes, ULONGLONG time)
{
    udp_account (stats, endpoint->pid, bytes, endpoint->port, endpoint->af, endpoint->address, MAXDWORD, receive, time, ERROR_SUCCESS);
}
static void unit_tests (void)
{
	SW_UDP_STATS *stats = udp_stats_create ();
	UDP_ENDPOINT exact = {0}, wildcard, wrong, dual, scoped;
	UDP_SNAPSHOT snapshot;
	EVENT_RECORD bad = {0};
	CHECK (stats != NULL);
	InterlockedExchange (&stats->error, 0);
	exact.pid = 1234;
	exact.af = AF_INET;
	exact.port = 443;
	exact.address[0] = 127;
	exact.address[3] = 1;
	exact.created = 1;
	wildcard = exact;
	ZeroMemory (wildcard.address, 16);
	udp_stats_begin_refresh (stats);
	udp_stats_read (stats, &wildcard, &snapshot);
	udp_stats_read (stats, &exact, &snapshot);
	CHECK (snapshot.error == ERROR_NOT_READY); // a running session is not proof of measurement
	inject (stats, &exact, FALSE, 1200, udp_now ());
	inject (stats, &exact, TRUE, 800, udp_now ());
	udp_stats_read (stats, &exact, &snapshot);
	CHECK (!snapshot.error && snapshot.sent == 1200 && snapshot.received == 800);
	udp_stats_read (stats, &wildcard, &snapshot);
	CHECK (snapshot.sent == 0 && snapshot.received == 0); // exact bind wins
	wrong = exact;
	wrong.pid++;
	inject (stats, &wrong, FALSE, 99000, udp_now ());
	wrong = exact;
	wrong.port++;
	inject (stats, &wrong, TRUE, 99000, udp_now ());
	udp_stats_read (stats, &exact, &snapshot);
	CHECK (snapshot.sent == 1200 && snapshot.received == 800);
	// A new bind of the same port starts at zero and rejects delayed old events.
	exact.created = udp_now () + 100;
	udp_stats_read (stats, &exact, &snapshot);
	inject (stats, &exact, FALSE, 999, exact.created - 1);
	inject (stats, &exact, TRUE, 50, exact.created + 1);
	udp_stats_read (stats, &exact, &snapshot);
	CHECK (snapshot.sent == 0 && snapshot.received == 50);
	dual = exact;
	dual.af = AF_INET6;
	dual.port = 5000;
	dual.created = 1;
	ZeroMemory (dual.address, 16);
	udp_stats_read (stats, &dual, &snapshot);
	wrong = exact;
	wrong.port = dual.port;
	inject (stats, &wrong, FALSE, 150, udp_now ());
	wrong.af = AF_INET6;
	ZeroMemory (wrong.address, 16);
	wrong.address[15] = 1;
	inject (stats, &wrong, TRUE, 250, udp_now ());
	udp_stats_read (stats, &dual, &snapshot);
	CHECK (snapshot.sent == 150 && snapshot.received == 250);
	// Identical link-local addresses on different scopes cannot be distinguished.
	scoped = wrong;
	scoped.scope_id = 1;
	scoped.created = 1;
	udp_stats_read (stats, &scoped, &snapshot);
	scoped.scope_id = 2;
	udp_stats_read (stats, &scoped, &snapshot);
	inject (stats, &wrong, TRUE, 999, udp_now ());
	udp_stats_read (stats, &scoped, &snapshot);
	CHECK (snapshot.error == ERROR_INVALID_DATA);
	// Failed table enumeration retains entries. Successful empty tables prune them.
	udp_stats_begin_refresh (stats);
	udp_stats_end_refresh (stats, FALSE, FALSE);
	CHECK (stats->count == 5);
	udp_stats_end_refresh (stats, TRUE, TRUE);
	CHECK (stats->count == 0);
	bad.UserContext = stats;
	bad.EventHeader.ProviderId = afd_provider;
	bad.EventHeader.EventDescriptor.Id = 1007;
	bad.EventHeader.EventDescriptor.Version = 0;
	udp_event (&bad); // truncated packet metadata must never be read
	udp_stats_read (stats, &exact, &snapshot);
	CHECK (snapshot.error == ERROR_NOT_SUPPORTED);
	InterlockedExchange (&stats->error, 0);
	EVENT_TRACE_LOGFILEW lost = {0};
	lost.Context = stats;
	lost.EventsLost = 1;
	udp_buffer (&lost);
	udp_stats_read (stats, &exact, &snapshot);
	CHECK (snapshot.error == ERROR_DATA_NOT_ACCEPTED);
	// Irrelevant TCP events must not poison the UDP decoder's health.
	InterlockedExchange (&stats->error, 0);
	bad.EventHeader.ProviderId.Data1 = 0x9a280ac0;
	udp_event (&bad);
	CHECK (!InterlockedCompareExchange (&stats->error, 0, 0));
	udp_stats_destroy (stats);
	printf ("UNIT: %s\n", failures ? "FAIL" : "PASS");
}

static BOOL lookup_endpoint (SOCKET socket, ADDRESS_FAMILY af, UDP_ENDPOINT *endpoint)
{
	SOCKADDR_STORAGE local = {0};
	int length = sizeof (local);
	DWORD size = 0, status;
	void *table;
	USHORT port;
	if (getsockname (socket, (SOCKADDR *)&local, &length))
		return FALSE;
	port = af == AF_INET ? ((SOCKADDR_IN *)&local)->sin_port : ((SOCKADDR_IN6 *)&local)->sin6_port;
	GetExtendedUdpTable (NULL, &size, FALSE, af, UDP_TABLE_OWNER_MODULE, 0);
	table = calloc (1, size);
	status = GetExtendedUdpTable (table, &size, FALSE, af, UDP_TABLE_OWNER_MODULE, 0);
	ZeroMemory (endpoint, sizeof (*endpoint));
	if (!status && af == AF_INET)
	{
		PMIB_UDPTABLE_OWNER_MODULE rows = table;
		for (DWORD i = 0; i < rows->dwNumEntries; i++)
			if (rows->table[i].dwOwningPid == GetCurrentProcessId () && rows->table[i].dwLocalPort == port)
			{
				endpoint->created = rows->table[i].liCreateTimestamp.QuadPart;
				memcpy (endpoint->address, &rows->table[i].dwLocalAddr, 4);
				break;
			}
	}
	else if (!status)
	{
		PMIB_UDP6TABLE_OWNER_MODULE rows = table;
		for (DWORD i = 0; i < rows->dwNumEntries; i++)
			if (rows->table[i].dwOwningPid == GetCurrentProcessId () && rows->table[i].dwLocalPort == port)
			{
				endpoint->created = rows->table[i].liCreateTimestamp.QuadPart;
				endpoint->scope_id = rows->table[i].dwLocalScopeId;
				memcpy (endpoint->address, rows->table[i].ucLocalAddr, 16);
				break;
			}
	}
	free (table);
	endpoint->pid = GetCurrentProcessId ();
	endpoint->af = af;
	endpoint->port = ntohs (port);
	return endpoint->created != 0;
}

static void wait_samples (SW_UDP_STATS *stats, UDP_ENDPOINT *endpoints, UDP_SNAPSHOT *snapshots, unsigned count, ULONGLONG expected)
{
	ULONGLONG started = GetTickCount64 ();
	for (;;)
	{
		BOOL ready = TRUE;
		for (unsigned i = 0; i < count; i++)
		{
			udp_stats_read (stats, &endpoints[i], &snapshots[i]);
			if (snapshots[i].error || snapshots[i].sent < expected || snapshots[i].received < expected) ready = FALSE;
		}
		if (ready || GetTickCount64 () - started >= 15000) break;
		Sleep (50);
	}
	printf ("ETW_WAIT_MS=%llu\n", GetTickCount64 () - started);
}

static void live_pair (SW_UDP_STATS *stats, ADDRESS_FAMILY af, BOOL wildcard, BOOL connected, unsigned packets)
{
	SOCKET sockets[2];
	SOCKADDR_STORAGE destinations[2] = {0};
	UDP_ENDPOINT endpoints[2];
	UDP_SNAPSHOT snapshots[2];
	char data[1200] = {0}, received[1200];
	DWORD timeout = 2000;
	ULONGLONG expected = (ULONGLONG)packets * sizeof (data);
	int length = af == AF_INET ? sizeof (SOCKADDR_IN) : sizeof (SOCKADDR_IN6);
	for (int i = 0; i < 2; i++)
	{
		sockets[i] = socket (af, SOCK_DGRAM, IPPROTO_UDP);
		CHECK (sockets[i] != INVALID_SOCKET);
		setsockopt (sockets[i], SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof (timeout));
		destinations[i].ss_family = af;
		if (af == AF_INET)
			((SOCKADDR_IN *)&destinations[i])->sin_addr.s_addr = wildcard ? INADDR_ANY : htonl (INADDR_LOOPBACK);
		else if (!wildcard)
			((SOCKADDR_IN6 *)&destinations[i])->sin6_addr.u.Byte[15] = 1;
		CHECK (!bind (sockets[i], (SOCKADDR *)&destinations[i], length));
		CHECK (lookup_endpoint (sockets[i], af, &endpoints[i]));
		CHECK (!getsockname (sockets[i], (SOCKADDR *)&destinations[i], &length));
		if (af == AF_INET)
			((SOCKADDR_IN *)&destinations[i])->sin_addr.s_addr = htonl (INADDR_LOOPBACK);
		else
			((SOCKADDR_IN6 *)&destinations[i])->sin6_addr.u.Byte[15] = 1;
		udp_stats_read (stats, &endpoints[i], &snapshots[i]);
	}
	if (connected)
		for (int i = 0; i < 2; i++)
			CHECK (!connect (sockets[i], (SOCKADDR *)&destinations[1 - i], length));
	for (unsigned packet = 0; packet < packets; packet++)
	{
		for (int i = 0; i < 2; i++)
		{
			int sent = connected ? send (sockets[i], data, sizeof (data), 0) : sendto (sockets[i], data, sizeof (data), 0, (SOCKADDR *)&destinations[1 - i], length);
			int got = recv (sockets[1 - i], received, sizeof (received), 0);
			if (sent != sizeof (data) || got != sizeof (data))
			{
				CHECK (FALSE);
				printf ("Socket error=%d sent=%d received=%d\n", WSAGetLastError (), sent, got);
				goto done;
			}
		}
	}
	wait_samples (stats, endpoints, snapshots, 2, expected);
	CHECK (udp_stats_poll (stats) == ERROR_SUCCESS);
	for (int i = 0; i < 2; i++)
	{
		udp_stats_read (stats, &endpoints[i], &snapshots[i]);
		printf ("UDP%d wildcard=%d connected=%d socket=%d packets=%u payload=%llu sent=%llu received=%llu error=%lu\n", af == AF_INET ? 4 : 6, wildcard, connected, i, packets, expected, snapshots[i].sent, snapshots[i].received, snapshots[i].error);
		CHECK (!snapshots[i].error);
		CHECK (snapshots[i].sent == expected);
		CHECK (snapshots[i].received == expected);
#ifdef UDP_TEST_VERIFY_ENDPOINT
		UDP_TEST_VERIFY_ENDPOINT (stats, &endpoints[i], &snapshots[i]);
#endif
	}
done:
	for (int i = 0; i < 2; i++)
		closesocket (sockets[i]);
	udp_stats_begin_refresh (stats);
	udp_stats_end_refresh (stats, TRUE, TRUE);
}

static void live_remote (SW_UDP_STATS *stats, const char *host, const char *service, ADDRESS_FAMILY af, BOOL connected, unsigned packets)
{
	ADDRINFOA hints = {0}, *destination = NULL;
	SOCKADDR_STORAGE local = {0};
	UDP_ENDPOINT endpoint;
	UDP_SNAPSHOT snapshot;
	char data[1200] = {0}, response[1200];
	DWORD timeout = 2000;
	SOCKET socket_handle;
	hints.ai_family = af;
	hints.ai_socktype = SOCK_DGRAM;
	CHECK (!getaddrinfo (host, service, &hints, &destination));
	if (!destination)
		return;
	socket_handle = socket (af, SOCK_DGRAM, IPPROTO_UDP);
	setsockopt (socket_handle, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof (timeout));
	local.ss_family = af;
	CHECK (!bind (socket_handle, (SOCKADDR *)&local, af == AF_INET ? sizeof (SOCKADDR_IN) : sizeof (SOCKADDR_IN6)));
	CHECK (lookup_endpoint (socket_handle, af, &endpoint));
	udp_stats_read (stats, &endpoint, &snapshot);
	if (connected)
		CHECK (!connect (socket_handle, destination->ai_addr, (int)destination->ai_addrlen));
	ULONGLONG started = GetTickCount64 ();
	for (unsigned i = 0; i < packets; i++)
	{
		int sent = connected ? send (socket_handle, data, sizeof (data), 0) : sendto (socket_handle, data, sizeof (data), 0, destination->ai_addr, (int)destination->ai_addrlen);
		int got = recv (socket_handle, response, sizeof (response), 0);
		if (sent != sizeof (data) || got != sizeof (response))
		{
			printf ("REMOTE socket failure: %d\n", WSAGetLastError ());
			CHECK (FALSE);
			break;
		}
	}
	ULONGLONG elapsed = GetTickCount64 () - started;
	ULONGLONG expected = (ULONGLONG)packets * sizeof (data);
	wait_samples (stats, &endpoint, &snapshot, 1, expected);
	CHECK (!udp_stats_poll (stats));
	udp_stats_read (stats, &endpoint, &snapshot);
	printf ("REMOTE UDP%d connected=%d packets=%u elapsed_ms=%llu payload=%llu sent=%llu received=%llu error=%lu\n", af == AF_INET ? 4 : 6, connected, packets, elapsed, expected, snapshot.sent, snapshot.received, snapshot.error);
	CHECK (!snapshot.error);
	CHECK (snapshot.sent == expected);
	CHECK (snapshot.received == expected);
	closesocket (socket_handle);
	freeaddrinfo (destination);
	udp_stats_begin_refresh (stats);
	udp_stats_end_refresh (stats, TRUE, TRUE);
}

static void lifecycle_test (void)
{
	WSADATA wsa; SOCKADDR_IN address = {0};
	UDP_ENDPOINT endpoint; UDP_SNAPSHOT snapshot;
	CHECK (!WSAStartup (MAKEWORD (2,2), &wsa));
	SOCKET socket_handle = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	address.sin_family = AF_INET; address.sin_addr.S_un.S_addr = htonl (INADDR_LOOPBACK);
	CHECK (!bind (socket_handle, (SOCKADDR *)&address, sizeof (address)));
	int length = sizeof (address);
	CHECK (!getsockname (socket_handle, (SOCKADDR *)&address, &length));
	DWORD timeout = 2000;
	setsockopt (socket_handle, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof (timeout));
	SW_UDP_STATS *stats = udp_stats_create ();
	DWORD status = udp_stats_start (stats); CHECK (!status);
	if (!status)
	{
		CHECK (lookup_endpoint (socket_handle, AF_INET, &endpoint));
		udp_stats_read (stats, &endpoint, &snapshot);
		char bytes[1200] = {0};
		CHECK (sendto (socket_handle, bytes, sizeof (bytes), 0, (SOCKADDR *)&address, sizeof (address)) == sizeof (bytes));
		CHECK (recv (socket_handle, bytes, sizeof (bytes), 0) == sizeof (bytes));
		Sleep (3000);
		udp_stats_read (stats, &endpoint, &snapshot);
		CHECK (snapshot.error == ERROR_NOT_READY && !snapshot.sent && !snapshot.received);
		printf ("PREEXISTING_SOCKET error=%lu (expected unavailable, not a verified zero)\n", snapshot.error);
		udp_stats_stop (stats); udp_stats_stop (stats); // idempotent
		CHECK (udp_stats_poll (stats) == ERROR_OPERATION_ABORTED);
	}
	udp_stats_destroy (stats); closesocket (socket_handle);
	stats = udp_stats_create ();
	status = udp_stats_start (stats); CHECK (!status);
	if (!status) live_pair (stats, AF_INET, FALSE, FALSE, 100);
	udp_stats_destroy (stats);
	UDP_TRACE_PROPERTIES properties; udp_properties (&properties);
	CHECK (ControlTraceW (0, UDP_SESSION_NAME, &properties.properties, EVENT_TRACE_CONTROL_QUERY) == ERROR_WMI_INSTANCE_NOT_FOUND);
	WSACleanup ();
	printf ("LIFECYCLE: %s\n", failures ? "FAIL" : "PASS");
}

static void watch_marker (const char *report, const char *suffix)
{
	char path[MAX_PATH]; FILE *file;
	sprintf_s (path, sizeof (path), "%s.%s", report, suffix);
	if (!fopen_s (&file, path, "w")) fclose (file);
}

static void watch_process (SW_UDP_STATS *stats, DWORD pid, const char *report)
{
	UDP_ENDPOINT endpoints[128]; UDP_SNAPSHOT snapshots[128];
	unsigned count = 0;
	ULONGLONG started = GetTickCount64 (), done_at = 0;
	char done[MAX_PATH];
	sprintf_s (done, sizeof (done), "%s.done", report);
	watch_marker (report, "started");
	for (;;)
	{
		BOOL complete[2] = {FALSE,FALSE};
		count = 0;
		udp_stats_begin_refresh (stats);
		for (unsigned family = 0; family < 2; family++)
		{
			DWORD size = 0; ADDRESS_FAMILY af = family ? AF_INET6 : AF_INET;
			GetExtendedUdpTable (NULL, &size, FALSE, af, UDP_TABLE_OWNER_MODULE, 0);
			void *table = calloc (1, size);
			if (table && !GetExtendedUdpTable (table, &size, FALSE, af, UDP_TABLE_OWNER_MODULE, 0))
			{
				complete[family] = TRUE;
				DWORD rows = *(DWORD *)table;
				for (DWORD i=0;i<rows;i++)
				{
					UDP_ENDPOINT endpoint = {0}; endpoint.af = af;
					if (family)
					{
						MIB_UDP6ROW_OWNER_MODULE *row = &((MIB_UDP6TABLE_OWNER_MODULE *)table)->table[i];
						endpoint.pid=row->dwOwningPid; endpoint.port=ntohs ((USHORT)row->dwLocalPort);
						endpoint.created=row->liCreateTimestamp.QuadPart; endpoint.scope_id=row->dwLocalScopeId;
						memcpy (endpoint.address,row->ucLocalAddr,16);
					}
					else
					{
						MIB_UDPROW_OWNER_MODULE *row = &((MIB_UDPTABLE_OWNER_MODULE *)table)->table[i];
						endpoint.pid=row->dwOwningPid; endpoint.port=ntohs ((USHORT)row->dwLocalPort);
						endpoint.created=row->liCreateTimestamp.QuadPart;
						memcpy (endpoint.address,&row->dwLocalAddr,4);
					}
					if (endpoint.pid == pid && count < 128)
					{
						endpoints[count]=endpoint;
						udp_stats_read (stats,&endpoint,&snapshots[count++]);
					}
				}
			}
			free (table);
		}
		udp_stats_end_refresh (stats,complete[0],complete[1]);
		if (count >= 2) watch_marker (report,"ready");
		if (!done_at && GetFileAttributesA (done) != INVALID_FILE_ATTRIBUTES) done_at=GetTickCount64 ();
		if ((done_at && GetTickCount64 ()-done_at>3000) || GetTickCount64 ()-started>45000) break;
		Sleep (50);
	}
	CHECK (done_at != 0 && count >= 2);
	CHECK (!udp_stats_poll (stats));
	for (unsigned i=0;i<count;i++)
	{
		udp_stats_read (stats,&endpoints[i],&snapshots[i]);
		printf ("WATCH pid=%lu af=%u port=%u sent=%llu received=%llu error=%lu\n",pid,endpoints[i].af,endpoints[i].port,snapshots[i].sent,snapshots[i].received,snapshots[i].error);
		CHECK (!snapshots[i].error);
#ifdef UDP_TEST_VERIFY_ENDPOINT
		UDP_TEST_VERIFY_ENDPOINT (stats, &endpoints[i], &snapshots[i]);
#endif
	}
	watch_marker (report,"finished");
}

int main (int argc, char **argv)
{
	if (argc > 1 && (argc < 3 ||
		(strcmp (argv[1], "--denied") && strcmp (argv[1], "--live") && strcmp (argv[1], "--watch") && strcmp (argv[1], "--lifecycle")) ||
		(argc > 1 && !strcmp (argv[1], "--watch") && (argc != 4 || !strtoul (argv[3], NULL, 10)))))
	{
		fprintf (stderr, "Usage: test [--denied|--live|--lifecycle REPORT] or --watch REPORT PID\n"); return 2;
	}
	if (argc > 2)
	{
		FILE *report;
		freopen_s (&report, argv[2], "w", stdout);
	}
	setvbuf (stdout, NULL, _IONBF, 0);
	refresh_collision_tests ();
	unit_tests ();
	afd_tests ();
#ifdef UDP_TEST_EXTRA
	UDP_TEST_EXTRA ();
#endif
	events_seen = own_seen = 0; // live diagnostics exclude injected fixtures
	if (argc > 1 && !strcmp (argv[1], "--lifecycle")) lifecycle_test ();
	if (argc > 1 && strcmp (argv[1], "--denied") == 0)
	{
		SW_UDP_STATS *stats = udp_stats_create ();
		UDP_ENDPOINT endpoint = {0};
		UDP_SNAPSHOT snapshot;
		DWORD result = udp_stats_start (stats);
		printf ("NONADMIN start=%lu\n", result);
		CHECK (result == ERROR_ACCESS_DENIED || result == ERROR_PRIVILEGE_NOT_HELD);
		udp_stats_read (stats, &endpoint, &snapshot);
		CHECK (snapshot.error == result);
		udp_stats_destroy (stats);
	}
	if (argc > 1 && (strcmp (argv[1], "--live") == 0 || strcmp (argv[1], "--watch") == 0))
	{
		WSADATA wsa;
		HANDLE token;
		TOKEN_PRIVILEGES privileges = {0};
		if (OpenProcessToken (GetCurrentProcess (), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
		{
			privileges.PrivilegeCount = 1;
			LookupPrivilegeValueW (NULL, SE_SYSTEM_PROFILE_NAME, &privileges.Privileges[0].Luid);
			privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges (token, FALSE, &privileges, 0, NULL, NULL);
			printf ("PROFILE_PRIVILEGE=%lu\n", GetLastError ());
			CloseHandle (token);
		}
		SW_UDP_STATS *stats = udp_stats_create ();
		DWORD status = udp_stats_start (stats);
		printf ("ETW start=%lu\n", status);
		UDP_TRACE_PROPERTIES state;
		udp_properties (&state);
		ControlTraceW (stats->session, NULL, &state.properties, EVENT_TRACE_CONTROL_QUERY);
		printf ("FLAGS=%lx MODE=%lx BUFFERS=%lu\n", state.properties.EnableFlags, state.properties.LogFileMode, state.properties.NumberOfBuffers);
		CHECK (status == ERROR_SUCCESS);
		if (!status)
		{
			SW_UDP_STATS *second = udp_stats_create ();
			CHECK (udp_stats_start (second) == ERROR_ALREADY_EXISTS);
			udp_stats_destroy (second);
			CHECK (!udp_stats_poll (stats)); // competing instance must leave us alone
			CHECK (!WSAStartup (MAKEWORD (2, 2), &wsa));
#ifdef UDP_TEST_LIVE_EXTRA
			UDP_TEST_LIVE_EXTRA ();
#endif
			udp_stats_begin_refresh (stats);
			if (strcmp (argv[1], "--watch") == 0 && argc > 3)
			{
				watch_process (stats, strtoul (argv[3], NULL, 10), argv[2]);
			}
			else if (argc > 4)
			{
				live_remote (stats, argv[3], argv[4], AF_INET, FALSE, 100);
				live_remote (stats, argv[3], argv[4], AF_INET, TRUE, 100);
				if (argc > 5)
				{
					live_remote (stats, argv[5], argv[4], AF_INET6, FALSE, 100);
					live_remote (stats, argv[5], argv[4], AF_INET6, TRUE, 100);
				}
				live_remote (stats, argv[3], argv[4], AF_INET, FALSE, 10000);
			}
			else
			{
			live_pair (stats, AF_INET, FALSE, FALSE, 100);
			live_pair (stats, AF_INET, TRUE, TRUE, 100);
			live_pair (stats, AF_INET6, FALSE, FALSE, 100);
			live_pair (stats, AF_INET6, TRUE, TRUE, 100);
			live_pair (stats, AF_INET, TRUE, FALSE, 10000);
			}
			WSACleanup ();
		}
		udp_stats_destroy (stats);
		printf ("REAL_ETW_EVENTS all=%u own=%u\n", events_seen, own_seen);
		UDP_TRACE_PROPERTIES properties;
		udp_properties (&properties);
		if (!status)
		{
			status = ControlTraceW (0, UDP_SESSION_NAME, &properties.properties, EVENT_TRACE_CONTROL_QUERY);
			CHECK (status == ERROR_WMI_INSTANCE_NOT_FOUND);
			printf ("SESSION_CLEANUP=%lu (4201 means removed)\n", status);
		}
	}
	printf ("RESULT: %u failures\n", failures);
	FILETIME created, exited, kernel, user;
	PROCESS_MEMORY_COUNTERS memory = {0};
	if (GetProcessTimes (GetCurrentProcess (), &created, &exited, &kernel, &user) &&
		K32GetProcessMemoryInfo (GetCurrentProcess (), &memory, sizeof (memory)))
		printf ("TEST_PROCESS cpu_ms=%llu peak_working_set_bytes=%zu\n",
			((((ULONGLONG)kernel.dwHighDateTime << 32) | kernel.dwLowDateTime) + (((ULONGLONG)user.dwHighDateTime << 32) | user.dwLowDateTime)) / 10000,
			memory.PeakWorkingSetSize);
	return failures ? 1 : 0;
}
