// simplewall - UDP socket I/O accounting through Windows Winsock/AFD ETW.
#pragma once

#include <winsock2.h>
#include <windows.h>

typedef struct SW_UDP_STATS SW_UDP_STATS;

typedef struct UDP_ENDPOINT
{
	DWORD pid;
	ADDRESS_FAMILY af;
	USHORT port; // host byte order
	BYTE address[16];
	DWORD scope_id;
	ULONGLONG created; // UDP owner table bind timestamp, in FILETIME units
} UDP_ENDPOINT;

typedef struct UDP_SNAPSHOT
{
	ULONGLONG received;
	ULONGLONG sent;
	DWORD error; // nonzero means totals must not be presented as complete
} UDP_SNAPSHOT;

SW_UDP_STATS *udp_stats_create (void);
DWORD udp_stats_start (SW_UDP_STATS *stats);
void udp_stats_stop (SW_UDP_STATS *stats);
void udp_stats_destroy (SW_UDP_STATS *stats);
DWORD udp_stats_poll (SW_UDP_STATS *stats);
void udp_stats_begin_refresh (SW_UDP_STATS *stats);
void udp_stats_read (SW_UDP_STATS *stats, const UDP_ENDPOINT *endpoint, UDP_SNAPSHOT *snapshot);
void udp_stats_end_refresh (SW_UDP_STATS *stats, BOOL ipv4_complete, BOOL ipv6_complete);
