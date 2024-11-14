#ifdef _WIN32

#define E_AIGUE "\x82"
#define A_ACCENT "\x85"
#define E_GRAVE "\x8A"
#define E_ACCENT "\x88"
#else
#define E_AIGUE "√©"
#define A_ACCENT "à"
#define E_GRAVE "√®"
#define E_ACCENT "ê"
#endif

// classes des fonctions PKCS#11 ‡ tester
#define GENPURP_FUNCTIONS 100
#define SESSION_FUNCTIONS 200
#define OBJECTS_FUNCTIONS 300
#define ENCRYPT_FUNCTIONS 400
#define ENCRYPT_FUNCTIONS_CPS3 400
#define DECRYPT_FUNCTIONS 500
#define SIGNATU_FUNCTIONS 600
#define VERISGN_FUNCTIONS 700
#define MDIGEST_FUNCTIONS 800
#define CPSDATA_TEST_CPS3 900
#define SIGSHA256_FUNCTIONS 1000
#define CONTACTLESS_TEST_CPS3 1100
/* Section des tests divers et variÈs*/
#define MISCELLANEOUS_TEST 1200
/* Section des tests de signature RSA PSS */
#define SIGNATU_RSA_PSS_FUNCTIONS 1300

#define CKR_ASIPTEST_FAILED CKR_VENDOR_DEFINED + 2

#define MAX_SLOTS 10
#define MAX_MSG_LEN  256

#define AT_SIGN_HASH   4
#ifndef __WINCRYPT_H__
// key specs
#define AT_SIGNATURE   2
#define AT_KEYEXCHANGE 1
#endif

/* Hash algorithms */
#define SHA1   0
#define SHA256 1

#define TYPE_CPS4 0x80

extern CK_BBOOL isCPS3;
extern CK_BBOOL isContactLess;
extern CK_BBOOL isCPS3_Card;

typedef struct
{
	unsigned short      TestLevel;
	unsigned long      usExpectedRc;
	char       Msg[MAX_MSG_LEN];
} sTESTS_MSGS;

/* DER EncodÈ du digestinfo pour l'algo SHA1 */
const unsigned char kbyoidSHA1[] =
{
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};

/* BPER (@@20131009-1104) - Support de l'algorithme SHA_256 */
/* DER EncodÈ du digestinfo pour l'algo SHA256 */
const unsigned char kbyoidSHA256[] =
{
   0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
     0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
