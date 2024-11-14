/*
* internal-winscard.h:  Mostly copied from pcsc-lite, this is the minimum required
*
* Copyright (C) 2010-2016, ASIP Santé
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __INTERNAL_WINSCARD_H
#define __INTERNAL_WINSCARD_H

/* */

#if defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#elif defined(_MSC_VER)
typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int8 uint8_t;
#else
#warning no uint32_t type available, please contact opensc - devel@opensc-project.org
#endif
#ifndef WIN32
#define ERROR_INVALID_HANDLE  SCARD_E_INVALID_HANDLE
#endif

#ifdef HAVE_WINSCARD_H
#if defined(WIN32)
#include <winscard.h>
typedef ULONG int32_t;
typedef int32_t PCSC_RET;
#elif defined(UNIX_LUX)
#include <winscard.h>
#elif defined(__APPLE__)
#include <PCSC/winscard.h>
#include "sysdef.h"
typedef int32_t PCSC_RET;
typedef int32_t DWORD;
typedef int32_t* LPDWORD;
typedef const char * LPCSTR;
#ifndef SCARD_STATE_UNPOWERED
#define SCARD_STATE_UNPOWERED    0x0400  /**< Unpowered card */
#endif
#endif
#else
#include "sysdef.h"
/* mingw32 does not have winscard.h */

#define MAX_ATR_SIZE      33  /**< Maximum ATR size */

#define SCARD_PROTOCOL_T0    0x0001  /**< T=0 active protocol. */
#define SCARD_PROTOCOL_T1    0x0002  /**< T=1 active protocol. */
#define SCARD_PROTOCOL_RAW    0x0004  /**< Raw active protocol. */

#define SCARD_UNKNOWN       0x0001  /* Unknown state. */
#define SCARD_ABSENT        0x0002  /* Card is absent.*/
#define SCARD_PRESENT       0x0004  /* Card is present. */
#define SCARD_SWALLOWED     0x0008  /* Card not powered. */
#define SCARD_POWERED       0x0010  /* Card is powered. */
#define SCARD_NEGOTIABLE    0x0020  /* Ready for PTS.  */
#define SCARD_SPECIFIC      0x0040  /* PTS has been set. */

#define SCARD_STATE_UNAWARE    0x0000  /**< App wants status */
#define SCARD_STATE_IGNORE    0x0001  /**< Ignore this reader */
#define SCARD_STATE_CHANGED    0x0002  /**< State has changed */
#define SCARD_STATE_EMPTY    0x0010  /**< Card removed */
#define SCARD_STATE_PRESENT    0x0020  /**< Card inserted */
#define SCARD_STATE_INUSE    0x0100  /**< Shared Mode */
#define SCARD_STATE_MUTE                0x0200  /**< Card mute */

#define SCARD_SHARE_EXCLUSIVE    0x0001  /**< Exclusive mode only */
#define SCARD_SHARE_SHARED    0x0002  /**< Shared mode only */

#define SCARD_LEAVE_CARD    0x0000  /**< Do nothing on close */
#define SCARD_RESET_CARD    0x0001  /**< Reset on close */
#define SCARD_UNPOWER_CARD    0x0002  /**< Power down on close */

#define SCARD_SCOPE_USER    0x0000  /**< Scope in user space */

#ifndef SCARD_S_SUCCESS  /* conflict in mingw-w64 */
#define SCARD_S_SUCCESS      0x00000000 /**< No error was encountered. */
#define SCARD_E_INVALID_HANDLE    0x80100003 /**< The supplied handle was invalid. */
#define SCARD_E_TIMEOUT      0x8010000A /**< The user-specified timeout value has expired. */
#define SCARD_E_SHARING_VIOLATION  0x8010000B /**< The smart card cannot be accessed because of other connections outstanding. */
#define SCARD_E_NOT_TRANSACTED    0x80100016 /**< An attempt was made to end a non-existent transaction. */
#define SCARD_E_READER_UNAVAILABLE  0x80100017 /**< The specified reader is not currently available for use. */
#define SCARD_E_NO_SERVICE    0x8010001D /**< The Smart card resource manager is not running. */
#define SCARD_E_NO_READERS_AVAILABLE    0x8010002E /**< Cannot find a smart card reader. */
#define SCARD_W_UNRESPONSIVE_CARD  0x80100066 /**< The smart card is not responding to a reset. */
#define SCARD_W_UNPOWERED_CARD    0x80100067 /**< Power has been removed from the smart card, so that further communication is not possible. */
#define SCARD_W_RESET_CARD    0x80100068 /**< The smart card has been reset, so any shared state information is invalid. */
#define SCARD_W_REMOVED_CARD    0x80100069 /**< The smart card has been removed, so further communication is not possible. */
#define SCARD_E_INVALID_VALUE           0x80100011 /**<One or more of the supplied parameters values could not be properly interpreted. */
#if defined (UNIX_LUX)
/* BPER (@@20121214) ajout d'un code erreur pcscd */
#define SCARD_E_SERVICE_STOPPED         0x8010001E /**< pcscd service has stopped. */
#define SCARD_E_NO_SMARTCARD						0x8010000C /**<The operation requires a smart card, but no smart card is currently in the device.*/
#endif
#endif

typedef int32_t   DWORD;
typedef int32_t * LPDWORD;

/* BPER (@@20140416) ajout de typedefs pour le portage 64 bits */
#ifdef UNIX_X64
typedef unsigned long PCSC_RET;
#else
typedef int32_t PCSC_RET;
#endif
typedef long SCARDCONTEXT; /**< \p hContext returned by SCardEstablishContext() */
typedef SCARDCONTEXT *PSCARDCONTEXT;
typedef SCARDCONTEXT *LPSCARDCONTEXT;
typedef long SCARDHANDLE; /**< \p hCard returned by SCardConnect() */
typedef SCARDHANDLE *PSCARDHANDLE;
typedef SCARDHANDLE *LPSCARDHANDLE;

typedef struct
{
  const char *szReader;
  void *pvUserData;
  unsigned long dwCurrentState;
  unsigned long dwEventState;
  unsigned long cbAtr;
  unsigned char rgbAtr[MAX_ATR_SIZE];
}
SCARD_READERSTATE_A;

typedef struct _SCARD_IO_REQUEST
{
  unsigned long dwProtocol;  /* Protocol identifier */
  unsigned long cbPciLength;  /* Protocol Control Inf Length */
}
SCARD_IO_REQUEST, *PSCARD_IO_REQUEST, *LPSCARD_IO_REQUEST;

typedef const SCARD_IO_REQUEST *LPCSCARD_IO_REQUEST;
typedef SCARD_READERSTATE_A SCARD_READERSTATE, *PSCARD_READERSTATE_A,
*LPSCARD_READERSTATE_A;

#endif  /* HAVE_SCARD_H */

#if defined(_WIN32)
#define PCSC_API WINAPI
#elif defined(USE_CYGWIN)
#define PCSC_API __stdcall
#else
#undef PCSC_API
#define PCSC_API
#endif


#if defined(UNIX_X64)
typedef unsigned long PCSC_RET;
typedef const char *LPCSTR;
#endif

typedef PCSC_RET(PCSC_API *SCardEstablishContext_t)(int32_t dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext);
typedef PCSC_RET(PCSC_API *SCardReleaseContext_t)(SCARDCONTEXT hContext);
typedef PCSC_RET(PCSC_API *SCardConnect_t)(SCARDCONTEXT hContext, LPCSTR szReader, int32_t dwShareMode, int32_t dwPreferredProtocols, LPSCARDHANDLE phCard, int32_t* pdwActiveProtocol);
typedef PCSC_RET(PCSC_API *SCardReconnect_t)(SCARDHANDLE hCard, int32_t dwShareMode, int32_t dwPreferredProtocols, int32_t dwInitialization, int32_t* pdwActiveProtocol);
typedef PCSC_RET(PCSC_API *SCardDisconnect_t)(SCARDHANDLE hCard, int32_t dwDisposition);
typedef PCSC_RET(PCSC_API *SCardBeginTransaction_t)(SCARDHANDLE hCard);
typedef PCSC_RET(PCSC_API *SCardEndTransaction_t)(SCARDHANDLE hCard, int32_t dwDisposition);
typedef PCSC_RET(PCSC_API *SCardStatus_t)(SCARDHANDLE hCard, LPSTR mszReaderNames, int32_t* pcchReaderLen,
  int32_t* pdwState, int32_t* pdwProtocol, LPBYTE pbAtr, int32_t* pcbAtrLen);
typedef PCSC_RET(PCSC_API *SCardGetStatusChange_t)(SCARDCONTEXT hContext, int32_t dwTimeout,
  LPSCARD_READERSTATE_A rgReaderStates, int32_t cReaders);
typedef PCSC_RET(PCSC_API *SCardControlOLD_t)(SCARDHANDLE hCard, LPCVOID pbSendBuffer, int32_t cbSendLength,
  LPVOID pbRecvBuffer, int32_t* lpBytesReturned);
typedef PCSC_RET(PCSC_API *SCardControl_t)(SCARDHANDLE hCard, int32_t dwControlCode, LPCVOID pbSendBuffer,
  int32_t cbSendLength, LPVOID pbRecvBuffer, int32_t cbRecvLength,
  int32_t* lpBytesReturned);
typedef PCSC_RET(PCSC_API *SCardTransmit_t)(SCARDHANDLE hCard, LPCSCARD_IO_REQUEST pioSendPci,
  LPCBYTE pbSendBuffer, int32_t cbSendLength, LPSCARD_IO_REQUEST pioRecvPci,
  LPBYTE pbRecvBuffer, int32_t* pcbRecvLength);
typedef PCSC_RET(PCSC_API *SCardListReaders_t)(SCARDCONTEXT hContext, LPCSTR mszGroups,
  LPSTR mszReaders, int32_t* pcchReaders);
#if defined (WIN32) || (__APPLE__)
typedef int32_t(PCSC_API *SCardIsValidContext_t)(SCARDCONTEXT hContext);
#endif

/* Copied from pcsc-lite reader.h */

#ifndef SCARD_CTL_CODE
#ifdef _WIN32
#include <winioctl.h>
#define SCARD_CTL_CODE(code) CTL_CODE(FILE_DEVICE_SMARTCARD,(code),METHOD_BUFFERED,FILE_ANY_ACCESS)
#else
#define SCARD_CTL_CODE(code) (0x42000000 + (code))
#endif
#endif

/**
 * PC/SC v2.02.05 part 10 reader tags
 */
#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)

#define FEATURE_VERIFY_PIN_START         0x01
#define FEATURE_VERIFY_PIN_FINISH        0x02
#define FEATURE_MODIFY_PIN_START         0x03
#define FEATURE_MODIFY_PIN_FINISH        0x04
#define FEATURE_GET_KEY_PRESSED          0x05
#define FEATURE_VERIFY_PIN_DIRECT        0x06
#define FEATURE_MODIFY_PIN_DIRECT        0x07
#define FEATURE_MCT_READERDIRECT         0x08
#define FEATURE_MCT_UNIVERSAL            0x09
#define FEATURE_IFD_PIN_PROPERTIES       0x0A
#define FEATURE_ABORT                    0x0B
#define FEATURE_SET_SPE_MESSAGE          0x0C
#define FEATURE_VERIFY_PIN_DIRECT_APP_ID 0x0D
#define FEATURE_MODIFY_PIN_DIRECT_APP_ID 0x0E
#define FEATURE_WRITE_DISPLAY            0x0F
#define FEATURE_GET_KEY                  0x10
#define FEATURE_IFD_DISPLAY_PROPERTIES   0x11

 /* structures used (but not defined) in PCSC Part 10 revision 2.01.02:
  * "IFDs with Secure Pin Entry Capabilities" */

  /* Set structure elements aligment on bytes
   * http://gcc.gnu.org/onlinedocs/gcc/Structure_002dPacking-Pragmas.html */
#ifdef __APPLE__
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

   /** the structure must be 6-bytes long */
typedef struct
{
  uint8_t tag;
  uint8_t length;
  uint32_t value;  /**< This value is always in BIG ENDIAN format as documented in PCSC v2 part 10 ch 2.2 page 2. You can use ntohl() for example */
} PCSC_TLV_STRUCTURE;

/** the wLangId and wPINMaxExtraDigit are 16-bits long so are subject to byte
 * ordering */
#define HOST_TO_CCID_16(x) (x)
#define HOST_TO_CCID_32(x) (x)

 /** structure used with \ref FEATURE_VERIFY_PIN_DIRECT */
typedef struct
{
  uint8_t bTimerOut;  /**< timeout is seconds (00 means use default timeout) */
  uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
  uint8_t bmFormatString; /**< formatting options */
  uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
                          * bits 3-0 PIN block size in bytes after
                          * justification and formatting */
  uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
                           * bit 4 set if system units are bytes, clear if
                           * system units are bits,
                           * bits 3-0 PIN length position in system units */
  uint16_t wPINMaxExtraDigit; /**< 0xXXYY where XX is minimum PIN size in digits,
                              and YY is maximum PIN size in digits */
  uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
                                   * be considered complete */
  uint8_t bNumberMessage; /**< Number of messages to display for PIN verification */
  uint16_t wLangId; /**< Language for messages */
  uint8_t bMsgIndex; /**< Message index (should be 00) */
  uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
  uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
  uint8_t abData[1]; /**< Data to send to the ICC */
} PIN_VERIFY_STRUCTURE;

/** structure used with \ref FEATURE_MODIFY_PIN_DIRECT */
typedef struct
{
  uint8_t bTimerOut;  /**< timeout is seconds (00 means use default timeout) */
  uint8_t bTimerOut2; /**< timeout in seconds after first key stroke */
  uint8_t bmFormatString; /**< formatting options */
  uint8_t bmPINBlockString; /**< bits 7-4 bit size of PIN length in APDU,
                          * bits 3-0 PIN block size in bytes after
                          * justification and formatting */
  uint8_t bmPINLengthFormat; /**< bits 7-5 RFU,
                           * bit 4 set if system units are bytes, clear if
                           * system units are bits,
                           * bits 3-0 PIN length position in system units */
  uint8_t bInsertionOffsetOld; /**< Insertion position offset in bytes for
                               the current PIN */
  uint8_t bInsertionOffsetNew; /**< Insertion position offset in bytes for
                               the new PIN */
  uint16_t wPINMaxExtraDigit;
  /**< 0xXXYY where XX is minimum PIN size in digits,
     and YY is maximum PIN size in digits */
  uint8_t bConfirmPIN; /**< Flags governing need for confirmation of new PIN */
  uint8_t bEntryValidationCondition; /**< Conditions under which PIN entry should
                                   * be considered complete */
  uint8_t bNumberMessage; /**< Number of messages to display for PIN verification*/
  uint16_t wLangId; /**< Language for messages */
  uint8_t bMsgIndex1; /**< index of 1st prompting message */
  uint8_t bMsgIndex2; /**< index of 2d prompting message */
  uint8_t bMsgIndex3; /**< index of 3d prompting message */
  uint8_t bTeoPrologue[3]; /**< T=1 block prologue field to use (fill with 00) */
  uint32_t ulDataLength; /**< length of Data to be sent to the ICC */
  uint8_t abData[1]; /**< Data to send to the ICC */
} PIN_MODIFY_STRUCTURE;

typedef struct {
  uint16_t wLcdLayout; /**< display characteristics */
  uint16_t wLcdMaxCharacters;
  uint16_t wLcdMaxLines;
  uint8_t bEntryValidationCondition;
  uint8_t bTimeOut2;
} PIN_PROPERTIES_STRUCTURE;

/* restore default structure elements alignment */
#ifdef __APPLE__
#pragma pack()
#else
#pragma pack(pop)
#endif

#endif
