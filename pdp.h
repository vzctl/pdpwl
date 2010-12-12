#ifndef _PDP_H
#define _PDP_H

struct gtp_hdr {
    unsigned char flags;        // Version, etc
    unsigned char message_type; // 0x10 create PDP Context
    uint16_t len;               // length in octets
    uint32_t teid;              // tunnel endpoint id
    uint16_t sequence;          // sequence number
    unsigned char npdu;         // N-PDU NUMBER
    unsigned char next_ext;     // 0x00 Next ext header type
};

#define PDP_CREATE_CONTEXT_REQ 0x10

extern bool pdp_stationid_match(uint64_t stationid, const struct xt_pdp_mtinfo *info);
extern uint64_t msisdn_to_uint64(const uint8_t * ad, uint8_t len);

struct header_len{
    uint8_t type;
    uint8_t length;
};

extern struct header_len gtp_headers[];
extern size_t gtp_headers_size(void);

// Define all possible headers for PDP Create Context
// (imported from wireshark)

#define GTP_EXT_IMSI                0x02
#define GTP_EXT_RAI                 0x03
#define GTP_EXT_RECOVER             0x0E
#define GTP_EXT_SEL_MODE            0x0F
#define GTP_EXT_TEID                0x10    /* 0xFF10 3G */
#define GTP_EXT_TEID_CP             0x11    /* 0xFF11 3G */
#define GTP_EXT_NSAPI               0x14    /* 3G */
#define GTP_EXT_CHRG_CHAR           0x1A    /* 3G */
#define GTP_EXT_TRACE_REF           0x1B    /* 3G */
#define GTP_EXT_TRACE_TYPE          0x1C    /* 3G */
#define GTP_EXT_USER_ADDR           0x80
#define GTP_EXT_APN                 0x83
#define GTP_EXT_PROTO_CONF          0x84
#define GTP_EXT_GSN_ADDR            0x85
#define GTP_EXT_MSISDN              0x86
#define GTP_EXT_QOS_UMTS            0x87    /* 3G */
#define GTP_EXT_TFT                 0x89    /* 3G */
#define GTP_EXT_TRIGGER_ID          0x8E    /* 3G   142 7.7.41 */
#define GTP_EXT_OMC_ID              0x8F    /* 3G   143 TLV OMC Identity 7.7.42 */
#define GTP_EXT_APN_RES             0x95    /* 3G   149 */
#define GTP_EXT_RAT_TYPE            0x97    /* 3G   151 TLV RAT Type 7.7.50 */
#define GTP_EXT_USR_LOC_INF         0x98    /* 3G   152 TLV User Location Information 7.7.51 */
#define GTP_EXT_MS_TIME_ZONE        0x99    /* 3G   153 TLV MS Time Zone 7.7.52 */
#define GTP_EXT_IMEISV              0x9A    /* 3G */
#define GTP_EXT_CAMEL_CHG_INF_CON   0x9B    /* 3G   155 TLV CAMEL Charging Information Container 7.7.54 */
#define GTP_EXT_ADD_TRS_INF         0xA2    /* 3G   162 TLV Additional Trace Info 7.7.62 */
#define GTP_EXT_PRIV_EXT            0xFF

#endif
