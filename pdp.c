// Author: lex@realisticgroup.com (Alexey Lapitsky)

#include <linux/netfilter.h>

#include "ipt_pdp.h"
#include "pdp.h"
#include "whitelist.h"

/* Define length of PDP Create Context headers (without type / length fields)
 * Headers with zero size either not implemented or
 * are using type -> size -> value format */

struct header_len gtp_headers[] = {
    {GTP_EXT_IMSI, 8},
    {GTP_EXT_RAI, 6},
    {GTP_EXT_RECOVER, 1},
    {GTP_EXT_SEL_MODE, 1},
    {GTP_EXT_TEID, 4},
    {GTP_EXT_TEID_CP, 4},
    {GTP_EXT_NSAPI, 1},
    {GTP_EXT_CHRG_CHAR, 2},
    {GTP_EXT_TRACE_REF, 2},
    {GTP_EXT_TRACE_TYPE, 2},
    {GTP_EXT_USER_ADDR, 4},
    {GTP_EXT_APN, 0},
    {GTP_EXT_PROTO_CONF, 0},
    {GTP_EXT_GSN_ADDR, 0},
    {GTP_EXT_MSISDN, 0},
    {GTP_EXT_QOS_UMTS, 0},
    {GTP_EXT_TFT, 0},
    {GTP_EXT_TRIGGER_ID, 0},
    {GTP_EXT_OMC_ID, 0},
    /* TS 29.060 V6.11.0 */
    {GTP_EXT_APN_RES, 0},
    {GTP_EXT_RAT_TYPE, 0},
    {GTP_EXT_USR_LOC_INF, 0},
    {GTP_EXT_MS_TIME_ZONE, 0},
    {GTP_EXT_IMEISV, 0},
    {GTP_EXT_CAMEL_CHG_INF_CON, 0},
    {GTP_EXT_ADD_TRS_INF, 0},
    {GTP_EXT_PRIV_EXT, 0}
};

size_t gtp_headers_size()
{
    return sizeof(gtp_headers) / sizeof(gtp_headers[0]);
}


bool pdp_stationid_match(uint64_t stationid, const struct xt_pdp_mtinfo *info)
{
    uint8_t i;
    if (stationid == 0)
	return false;
    if (info->type == PDP_RESERVED)
	for(i = 0; i < wl_stationid_size(); i++)
	    if ((stationid >= wl_stationid[i].min) && (stationid <= wl_stationid[i].max)) {
		return true;
	    }
    if ((info->type == PDP_STATION_ID) && (info->n == stationid)){
	return true;
    }
    return false;
}


uint64_t msisdn_to_uint64(const uint8_t * ad, uint8_t len)
{

    char str[17] = "                ";
    uint8_t bits8to5, bits4to1;
    uint8_t i = 1;
    uint8_t j = 0;
    const char hex_digits[10] = "0123456789";

    for (i = 1; i < len && i < 9; i++) {
	bits8to5 = (ad[i] >> 4) & 0x0F;
	bits4to1 = ad[i] & 0x0F;
	if (bits4to1 < 0xA)
	    str[j++] = hex_digits[bits4to1];
	if (bits8to5 < 0xA)
	    str[j++] = hex_digits[bits8to5];
    }
    str[j] = '\0';

    return simple_strtoull(str, NULL, 10);
}

uint64_t imsi_to_uint64(const uint8_t * ad) {
    char str[17] = "                ";
    uint8_t i, j = 0;

    for (i = 0; i < 8; i++) {
        if ((ad[i] & 0x0F) <= 9)
	    str[j++] = (ad[i] & 0x0F) + 0x30;
	if (((ad[i] >> 4) & 0x0F) <= 9)
	    str[j++] = ((ad[i] >> 4) & 0x0F) + 0x30;
    }
    str[j] = '\0';

    return simple_strtoull(str, NULL, 10);
}

