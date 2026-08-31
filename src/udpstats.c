// simplewall
// UDP events contain metadata only; no packet payload is captured or stored.
#include "udpstats.h"
#include <evntrace.h>
#include <evntcons.h>

#pragma comment(lib, "advapi32.lib")

#define UDP_BUCKETS 256
#define UDP_MAX_ENDPOINTS 8192
#define UDP_SESSION_NAME L"simplewall-UDP"

static const GUID afd_provider = {0xe53c6823, 0x7bb8, 0x44bb, {0x90, 0xdc, 0x3f, 0x86, 0x09, 0x0d, 0x48, 0xa6}};
static const GUID udp_session = {0x4bfa58d6, 0x5d5d, 0x46f2, {0x93, 0x93, 0xc9, 0xe0, 0x5e, 0x27, 0xb4, 0x71}};

typedef struct UDP_ENTRY
{
	struct UDP_ENTRY *next;
	UDP_ENDPOINT endpoint;
	ULONGLONG since;
	ULONGLONG received;
	ULONGLONG sent;
	ULONG epoch;
	DWORD error;
	BOOL observed;
} UDP_ENTRY;

typedef struct UDP_AFD_SOCKET
{
	struct UDP_AFD_SOCKET *next;
	ULONGLONG handle;
	UDP_ENDPOINT endpoint;
	BOOL bound;
	BOOL unsupported;
} UDP_AFD_SOCKET;

typedef struct UDP_TRACE_PROPERTIES
{
	EVENT_TRACE_PROPERTIES properties;
	WCHAR name[64];
} UDP_TRACE_PROPERTIES;

struct SW_UDP_STATS
{
	SRWLOCK lock;
	SRWLOCK control_lock;
	UDP_ENTRY *buckets[UDP_BUCKETS];
	UDP_AFD_SOCKET *sockets[UDP_BUCKETS]; // owned by the ETW consumer thread
	ULONG socket_count;
	ULONG count;
	ULONG epoch;
	TRACEHANDLE session;
	TRACEHANDLE consumer;
	HANDLE thread;
	HANDLE guard;
	BOOL owns_guard;
	volatile LONG stopping;
	volatile LONG error;
};

static ULONGLONG udp_now (void)
{
	FILETIME time;
	GetSystemTimeAsFileTime (&time);
	return ((ULONGLONG)time.dwHighDateTime << 32) | time.dwLowDateTime;
}

static ULONG udp_bucket (DWORD pid, USHORT port)
{
	return (pid ^ port) % UDP_BUCKETS;
}

static void udp_properties (UDP_TRACE_PROPERTIES *buffer)
{
	ZeroMemory (buffer, sizeof (*buffer));
	buffer->properties.Wnode.BufferSize = sizeof (*buffer);
	buffer->properties.Wnode.Guid = udp_session;
	buffer->properties.Wnode.ClientContext = 1; // QPC; ProcessTrace converts to FILETIME
	buffer->properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	buffer->properties.BufferSize = 64;
	buffer->properties.MinimumBuffers = 0;
	buffer->properties.MaximumBuffers = 128;
	buffer->properties.FlushTimer = 1;
	buffer->properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	buffer->properties.LoggerNameOffset = FIELD_OFFSET (UDP_TRACE_PROPERTIES, name);
}

// Select a bound socket, not a remote flow. UDP listeners may use wildcard
// addresses and IPv6 sockets may receive IPv4. Never credit two rows for one event.
static int udp_match (const UDP_ENDPOINT *endpoint, ADDRESS_FAMILY af, const BYTE *address)
{
	static const BYTE zero[16] = {0};
	if (endpoint->af == af)
	{
		SIZE_T length = af == AF_INET ? 4 : 16;
		if (memcmp (endpoint->address, address, length) == 0)
			return 3;
		if (memcmp (endpoint->address, zero, length) == 0)
			return 2;
	}
	else if (af == AF_INET && endpoint->af == AF_INET6)
	{
		static const BYTE mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
		if (memcmp (endpoint->address, mapped, 12) == 0 && memcmp (endpoint->address + 12, address, 4) == 0)
			return 2;
		if (memcmp (endpoint->address, zero, 16) == 0)
			return 1;
	}
	return 0;
}

static void udp_account (SW_UDP_STATS *stats, DWORD pid, DWORD size, USHORT port, ADDRESS_FAMILY af, const BYTE *address, ULONG scope_id, BOOL receive, ULONGLONG timestamp, DWORD error)
{
	UDP_ENTRY *entry, *best = NULL;
	int score = 0;
	BOOL ambiguous = FALSE;
	AcquireSRWLockExclusive (&stats->lock);
	for (entry = stats->buckets[udp_bucket (pid, port)]; entry; entry = entry->next)
	{
		int candidate;
		if (entry->endpoint.pid != pid || entry->endpoint.port != port)
			continue;
		if (af == AF_INET6 && scope_id != MAXDWORD && entry->endpoint.scope_id != scope_id)
			continue;
		candidate = udp_match (&entry->endpoint, af, address);
		if (candidate > score)
		{
			best = entry;
			score = candidate;
			ambiguous = FALSE;
		}
		else if (candidate && candidate == score)
		{
			ambiguous = TRUE;
		}
	}
	if (best && !ambiguous && timestamp >= best->since)
	{
		if (error) best->error = error;
		best->observed = TRUE;
		if (receive)
			best->received += size;
		else
			best->sent += size;
	}
	else if (ambiguous)
	{
		// Never silently attribute an event to one of several equally good rows.
		for (entry = stats->buckets[udp_bucket (pid, port)]; entry; entry = entry->next)
			if (entry->endpoint.pid == pid && entry->endpoint.port == port && udp_match (&entry->endpoint, af, address) == score)
				entry->error = ERROR_INVALID_DATA;
	}
	ReleaseSRWLockExclusive (&stats->lock);
}

static DWORD udp_u32 (const BYTE *data) { DWORD value; memcpy (&value, data, 4); return value; }

static void udp_afd_event (SW_UDP_STATS *stats, EVENT_RECORD *event)
{
	USHORT id = event->EventHeader.EventDescriptor.Id;
	const BYTE *data = event->UserData;
	ULONG pointer_size = (event->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) ? 4 : 8;
	ULONG prefix = 8 + 2 * pointer_size;
	ULONGLONG handle = 0;
	UDP_AFD_SOCKET **link, *socket;
	BOOL receive = id == 1004 || id == 1006 || id == 1009 || id == 1012 || id == 1015;
	BOOL transfer = receive || id == 1003 || id == 1005 || id == 1007 || id == 1011 || id == 1013;
	// RIO uses a different completion path. Mark just that socket unavailable.
	if (id == 4006)
	{
		if (event->EventHeader.EventDescriptor.Version != 0 || !data || event->UserDataLength < pointer_size) goto unsupported;
		memcpy (&handle, data, pointer_size);
		for (socket = stats->sockets[(handle >> 4) % UDP_BUCKETS]; socket; socket = socket->next)
			if (socket->handle == handle)
			{
				socket->unsupported = TRUE;
				if (socket->bound)
					udp_account (stats, socket->endpoint.pid, 0, socket->endpoint.port, socket->endpoint.af,
						socket->endpoint.address, socket->endpoint.scope_id, FALSE, event->EventHeader.TimeStamp.QuadPart, ERROR_NOT_SUPPORTED);
				break;
			}
		return;
	}
	if (id != 1000 && id != 1001 && id != 1002 && id != 1030 && !transfer)
		return;
	if (event->EventHeader.EventDescriptor.Version != 0 || !data || event->UserDataLength < prefix)
		goto unsupported;
	memcpy (&handle, data + 8 + pointer_size, pointer_size);
	link = &stats->sockets[(handle >> 4) % UDP_BUCKETS];
	while (*link && (*link)->handle != handle) link = &(*link)->next;
	socket = *link;
	if ((id == 1001 || id == 1002) && udp_u32 (data) == 0)
	{
		if (socket) { *link = socket->next; HeapFree (GetProcessHeap (), 0, socket); stats->socket_count--; }
		return;
	}
	if (id == 1000 && udp_u32 (data) == 0)
	{
		if (event->UserDataLength < prefix + 12 + pointer_size + 4) goto unsupported;
		// Kernel endpoint addresses are reused, including by TCP sockets.
		if (socket) { *link = socket->next; HeapFree (GetProcessHeap (), 0, socket); stats->socket_count--; socket = NULL; }
		if (udp_u32 (data + prefix + 4) != SOCK_DGRAM || udp_u32 (data + prefix + 8) != IPPROTO_UDP) return;
		if (!socket)
		{
			if (stats->socket_count >= UDP_MAX_ENDPOINTS) { InterlockedExchange (&stats->error, ERROR_NOT_ENOUGH_MEMORY); return; }
			socket = HeapAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY, sizeof (*socket));
			if (!socket) { InterlockedExchange (&stats->error, ERROR_NOT_ENOUGH_MEMORY); return; }
			socket->next = *link; *link = socket; stats->socket_count++;
		}
		socket->handle = handle; socket->bound = FALSE;
		ZeroMemory (&socket->endpoint, sizeof (socket->endpoint));
		socket->endpoint.pid = udp_u32 (data + prefix + 12);
		return;
	}
	if (!socket || udp_u32 (data) != 1) return;
	if (id == 1030)
	{
		ULONG length;
		USHORT af, port;
		if (event->UserDataLength < prefix + 8) goto unsupported;
		if (udp_u32 (data + prefix) != ERROR_SUCCESS) return;
		length = udp_u32 (data + prefix + 4);
		if (length > event->UserDataLength - prefix - 8 || length < 4) goto unsupported;
		memcpy (&af, data + prefix + 8, 2); memcpy (&port, data + prefix + 10, 2);
		if ((af != AF_INET && af != AF_INET6) || length < (af == AF_INET ? 16U : 28U)) goto unsupported;
		socket->endpoint.af = af;
		socket->endpoint.port = (USHORT)((port >> 8) | (port << 8));
		memcpy (socket->endpoint.address, data + prefix + (af == AF_INET ? 12 : 16), af == AF_INET ? 4 : 16);
		socket->endpoint.scope_id = af == AF_INET6 ? udp_u32 (data + prefix + 32) : 0;
		socket->bound = socket->endpoint.port != 0;
		if (socket->bound && socket->unsupported)
			udp_account (stats, socket->endpoint.pid, 0, socket->endpoint.port, af, socket->endpoint.address,
				socket->endpoint.scope_id, FALSE, event->EventHeader.TimeStamp.QuadPart, ERROR_NOT_SUPPORTED);
		return;
	}
	if (transfer && socket->bound)
	{
		ULONG size_offset = prefix + 4 + pointer_size;
		if (event->UserDataLength < size_offset + 8) goto unsupported;
		if (udp_u32 (data + size_offset + 4) != ERROR_SUCCESS) return;
		udp_account (stats, socket->endpoint.pid, udp_u32 (data + size_offset), socket->endpoint.port,
			socket->endpoint.af, socket->endpoint.address, socket->endpoint.scope_id, receive, event->EventHeader.TimeStamp.QuadPart,
			socket->unsupported ? ERROR_NOT_SUPPORTED : ERROR_SUCCESS);
	}
	return;
unsupported:
	InterlockedExchange (&stats->error, ERROR_NOT_SUPPORTED);
}

static void WINAPI udp_event (EVENT_RECORD *event)
{
#ifdef UDP_STATS_DIAGNOSTIC
	UDP_STATS_DIAGNOSTIC (event);
#endif
	SW_UDP_STATS *stats = event->UserContext;
	if (InterlockedCompareExchange (&stats->stopping, 0, 0)) return;
	if (IsEqualGUID (&event->EventHeader.ProviderId, &afd_provider))
	{
		udp_afd_event (stats, event); return;
	}
}

static ULONG WINAPI udp_buffer (EVENT_TRACE_LOGFILEW *buffer)
{
	SW_UDP_STATS *stats = buffer->Context;
	if (buffer->EventsLost)
		InterlockedExchange (&stats->error, ERROR_DATA_NOT_ACCEPTED);
	return !InterlockedCompareExchange (&stats->stopping, 0, 0);
}

static DWORD WINAPI udp_thread (void *parameter)
{
	SW_UDP_STATS *stats = parameter;
	ULONG result = ProcessTrace (&stats->consumer, 1, NULL, NULL);
	if (!InterlockedCompareExchange (&stats->stopping, 0, 0))
		InterlockedExchange (&stats->error, result ? result : ERROR_OPERATION_ABORTED);
	return result;
}

SW_UDP_STATS *udp_stats_create (void)
{
	SW_UDP_STATS *stats = HeapAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY, sizeof (SW_UDP_STATS));
	if (stats)
	{
		stats->consumer = INVALID_PROCESSTRACE_HANDLE;
		stats->error = ERROR_NOT_READY;
	}
	return stats;
}

DWORD udp_stats_start (SW_UDP_STATS *stats)
{
	UDP_TRACE_PROPERTIES properties;
	EVENT_TRACE_LOGFILEW logfile = {0};
	TRACEHANDLE session = 0;
	DWORD status;
	if (!stats)
		return ERROR_NOT_ENOUGH_MEMORY;
	if (stats->guard || InterlockedCompareExchange (&stats->stopping, 0, 0))
		return ERROR_ALREADY_INITIALIZED;
	// A global semaphore distinguishes an orphan left by a crash from an active
	// simplewall instance. Never stop another tracing application's session.
	stats->guard = CreateSemaphoreW (NULL, 1, 1, L"Global\\simplewall-UDP-owner");
	if (!stats->guard)
		status = GetLastError ();
	else
	{
		status = WaitForSingleObject (stats->guard, 0);
		stats->owns_guard = status == WAIT_OBJECT_0;
		status = stats->owns_guard ? ERROR_SUCCESS : ERROR_ALREADY_EXISTS;
	}
	if (status)
		goto fail;
	udp_properties (&properties);
	status = StartTraceW (&session, UDP_SESSION_NAME, &properties.properties);
	if (status == ERROR_ALREADY_EXISTS)
	{
		udp_properties (&properties);
		status = ControlTraceW (0, UDP_SESSION_NAME, &properties.properties, EVENT_TRACE_CONTROL_QUERY);
		if (!status && IsEqualGUID (&properties.properties.Wnode.Guid, &udp_session))
		{
			status = ControlTraceW (0, UDP_SESSION_NAME, &properties.properties, EVENT_TRACE_CONTROL_STOP);
			if (!status)
			{
				udp_properties (&properties);
				status = StartTraceW (&session, UDP_SESSION_NAME, &properties.properties);
			}
		}
		else if (!status)
			status = ERROR_ALREADY_EXISTS;
	}
	if (status)
		goto fail;
	stats->session = session;
	// DATAGRAM plus RIO lifecycle metadata; no verbose packet-buffer events.
	status = EnableTraceEx2 (session, &afd_provider, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0x41, 0, 0, NULL);
	if (status) goto fail;
	logfile.LoggerName = UDP_SESSION_NAME;
	logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
	logfile.EventRecordCallback = udp_event;
	logfile.BufferCallback = udp_buffer;
	logfile.Context = stats;
	stats->consumer = OpenTraceW (&logfile);
	if (stats->consumer == INVALID_PROCESSTRACE_HANDLE)
	{
		status = GetLastError ();
		goto fail;
	}
	InterlockedExchange (&stats->error, ERROR_SUCCESS);
	stats->thread = CreateThread (NULL, 0, udp_thread, stats, 0, NULL);
	if (!stats->thread)
	{
		status = GetLastError ();
		goto fail;
	}
	return ERROR_SUCCESS;
fail:
	udp_stats_stop (stats);
	InterlockedExchange (&stats->error, status);
	return status;
}

void udp_stats_stop (SW_UDP_STATS *stats)
{
	UDP_TRACE_PROPERTIES properties;
	if (!stats)
		return;
	AcquireSRWLockExclusive (&stats->control_lock);
	InterlockedExchange (&stats->stopping, TRUE);
	InterlockedExchange (&stats->error, ERROR_OPERATION_ABORTED);
	if (stats->session)
	{
		udp_properties (&properties);
		ControlTraceW (stats->session, NULL, &properties.properties, EVENT_TRACE_CONTROL_STOP);
		stats->session = 0;
	}
	if (stats->consumer != INVALID_PROCESSTRACE_HANDLE)
	{
		CloseTrace (stats->consumer);
	}
	if (stats->thread)
	{
		WaitForSingleObject (stats->thread, INFINITE);
		CloseHandle (stats->thread);
		stats->thread = NULL;
	}
	stats->consumer = INVALID_PROCESSTRACE_HANDLE;
	if (stats->guard)
	{
		if (stats->owns_guard)
			ReleaseSemaphore (stats->guard, 1, NULL);
		CloseHandle (stats->guard);
		stats->guard = NULL;
		stats->owns_guard = FALSE;
	}
	ReleaseSRWLockExclusive (&stats->control_lock);
}

void udp_stats_destroy (SW_UDP_STATS *stats)
{
	if (!stats)
		return;
	udp_stats_stop (stats);
	for (ULONG i = 0; i < UDP_BUCKETS; i++)
	{
		UDP_AFD_SOCKET *socket = stats->sockets[i];
		while (socket)
		{
			UDP_AFD_SOCKET *next = socket->next;
			HeapFree (GetProcessHeap (), 0, socket); socket = next;
		}
		UDP_ENTRY *entry = stats->buckets[i];
		while (entry)
		{
			UDP_ENTRY *next = entry->next;
			HeapFree (GetProcessHeap (), 0, entry);
			entry = next;
		}
	}
	HeapFree (GetProcessHeap (), 0, stats);
}

DWORD udp_stats_poll (SW_UDP_STATS *stats)
{
	UDP_TRACE_PROPERTIES properties;
	DWORD status;
	if (!stats)
		return ERROR_NOT_READY;
	AcquireSRWLockExclusive (&stats->control_lock);
	status = InterlockedCompareExchange (&stats->error, 0, 0);
	if (!status && stats->session)
	{
		udp_properties (&properties);
		status = ControlTraceW (stats->session, NULL, &properties.properties, EVENT_TRACE_CONTROL_QUERY);
		if (!status && (properties.properties.EventsLost || properties.properties.RealTimeBuffersLost || properties.properties.LogBuffersLost))
			status = ERROR_DATA_NOT_ACCEPTED;
		if (status)
			InterlockedExchange (&stats->error, status);
	}
	ReleaseSRWLockExclusive (&stats->control_lock);
	return status;
}

void udp_stats_begin_refresh (SW_UDP_STATS *stats)
{
	if (!stats)
		return;
	AcquireSRWLockExclusive (&stats->lock);
	stats->epoch++;
	ReleaseSRWLockExclusive (&stats->lock);
}

void udp_stats_read (SW_UDP_STATS *stats, const UDP_ENDPOINT *endpoint, UDP_SNAPSHOT *snapshot)
{
	ULONG bucket;
	UDP_ENTRY *entry;
	ZeroMemory (snapshot, sizeof (*snapshot));
	snapshot->error = stats ? InterlockedCompareExchange (&stats->error, 0, 0) : ERROR_NOT_READY;
	if (snapshot->error)
		return;
	bucket = udp_bucket (endpoint->pid, endpoint->port);
	AcquireSRWLockExclusive (&stats->lock);
	for (entry = stats->buckets[bucket]; entry; entry = entry->next)
	{
		if (entry->endpoint.pid == endpoint->pid && entry->endpoint.port == endpoint->port && entry->endpoint.af == endpoint->af &&
			entry->endpoint.scope_id == endpoint->scope_id && memcmp (entry->endpoint.address, endpoint->address, endpoint->af == AF_INET ? 4 : 16) == 0)
			break;
	}
	if (!entry)
	{
		if (stats->count < UDP_MAX_ENDPOINTS)
			entry = HeapAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY, sizeof (*entry));
		if (!entry)
		{
			snapshot->error = ERROR_NOT_ENOUGH_MEMORY;
			ReleaseSRWLockExclusive (&stats->lock);
			return;
		}
		entry->next = stats->buckets[bucket];
		stats->buckets[bucket] = entry;
		stats->count++;
	}
	if (!entry->since || entry->endpoint.created != endpoint->created)
	{
		entry->endpoint = *endpoint;
		entry->since = udp_now ();
		if (endpoint->created > entry->since)
			entry->since = endpoint->created;
		entry->received = entry->sent = 0;
		entry->error = ERROR_SUCCESS;
		entry->observed = FALSE;
	}
	entry->epoch = stats->epoch;
	snapshot->received = entry->received;
	snapshot->sent = entry->sent;
	snapshot->error = entry->error ? entry->error : (entry->observed ? ERROR_SUCCESS : ERROR_NOT_READY);
	ReleaseSRWLockExclusive (&stats->lock);
}

void udp_stats_end_refresh (SW_UDP_STATS *stats, BOOL ipv4_complete, BOOL ipv6_complete)
{
	if (!stats)
		return;
	AcquireSRWLockExclusive (&stats->lock);
	for (ULONG i = 0; i < UDP_BUCKETS; i++)
	{
		UDP_ENTRY *entry = stats->buckets[i], *previous = NULL;
		while (entry)
		{
			UDP_ENTRY *next = entry->next;
			if (entry->epoch != stats->epoch && (entry->endpoint.af == AF_INET ? ipv4_complete : ipv6_complete))
			{
				if (previous)
					previous->next = next;
				else
					stats->buckets[i] = next;
				HeapFree (GetProcessHeap (), 0, entry);
				stats->count--;
			}
			else
				previous = entry;
			entry = next;
		}
	}
	ReleaseSRWLockExclusive (&stats->lock);
}
