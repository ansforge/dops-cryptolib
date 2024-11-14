//
// tls_chainlist.h
//

#ifndef _TLS_CHAINLIST
#define _TLS_CHAINLIST

#define PTR *

#define TLS_INDEX_NONE ((LPVOID)0)

BOOL tls_addToTlsList(DWORD _dwThreadID, LPVOID _pvContext);
LPVOID tls_getTlsIndexByThreadId(DWORD dwThreadID);
void tls_deleteTlsEntryByThreadId(DWORD dwThreadID);
void tls_deleteList(void);

// fonction de DEBUG
void trace_line(char * mesg, ...);

#endif
