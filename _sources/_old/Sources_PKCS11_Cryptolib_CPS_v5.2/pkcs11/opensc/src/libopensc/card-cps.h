#ifndef _CARD_CPS_H
#define _CARD_CPS_H

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------*/
/* CPS Specific driver data */
struct cps_priv_data {
  int contactless;
  int bad_actua;
  int cps_type;
};

/* Gestion de la mise à jour des fichiers de situations */
struct sc_pkcs15_ef_actua {
  time_t actua_start_date;
  time_t actua_end_date;
};

struct sc_ef_actua_fields {
  const u8 actua_template_tag;
  const u8 actua_start_date_tag;
  const u8 actua_end_date_tag;
};

static struct sc_ef_actua_fields cps3_ef_actua_fields = { 0xEC,0x81,0x82 };

typedef struct sc_match_atr
{
  const u8*     atr;
  const u8*     mask;
  const size_t  length;
  u8            type;
}sc_match_atr;

/*---------------------------------------------*/

#define CPS_UNKNOWN      -1
#define CPS3_CONTACT      0
#define CPS3_CONTACTLESS  1
#define CPS4_CONTACT      2

#define PREFIX_SN           "8025000001" /* préfix du numéro de série */
#define CPS3_EF_ACTUA_PATH  "3F00D010"
#define CPS_EF_SN_PATH      "3F00D003"
#define CPS3_MODEL          "IAS ECC"
#define CPS4_MODEL          "ChipDoc"

#define CPS2TER_SW1_BYTES_AVAILABLE   0x9f
#define CPS3_SW1_BYTES_AVAILABLE      0x61
#define CPS4_SW1_BYTES_AVAILABLE      CPS3_SW1_BYTES_AVAILABLE

#define DRVDATA(card)   ((struct cps_priv_data *) (card->drv_data))

/**
 MACRO for memory allocation
 1st param (OUT)   : Error Status
 2nd param (IN/OUT): buffer ponter
 3rd param (IN)    : size
 4th param (IN OPT): card driver
*/
#define ALLOCATE(rc, buffer, size, card)             \
  buffer = calloc(size, sizeof(u8)); \
  if(buffer == NULL) { \
    if( card != NULL){ sc_debug(card->ctx, "No more memory"); \
    rc = SC_ERROR_OUT_OF_MEMORY;}                     \
  }                                                  \
  rc = SC_SUCCESS;

extern int cps2ter_select_file(sc_card_t* card, const sc_path_t* in_path, sc_file_t** file_out);
extern int cps_get_model(sc_card_t* card, u8* model);
extern int cps_is_visible(const sc_path_t* path);
extern int cps_finish(sc_card_t* card);
extern int cps_is_valid(sc_card_t* card);
extern int cps_end_exlusivity(sc_card_t* card);
extern int cps_start_exlusivity(sc_card_t* card);
extern int cps_free_transmit(sc_card_t* card, const u8* data, size_t data_len, u8* out, size_t* outlen, unsigned char ins_type);
extern void cps_get_status(sc_card_t* card);
extern int _is_cps_card(u8* atr, size_t szAtr, int* pType);
extern void _cps_get_pin_info(sc_card_t* card, u8* pbuff, size_t buffLen, sc_pin_counter_t* pPinCounter);
extern int _cps_read_efsnicc(sc_card_t* card);

#ifdef __cplusplus
}
#endif

#endif