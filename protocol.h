static const int retr_intval[9] = { 15, 30, 60, 100, 150, 170, 350, 650, 1000 };

#define MT_MACTELNET      21 // 0x0015
#define MT_CONTROL_MAGIC  4279383126U

/* Packet Type */
#define MT_PTYPE_SESS_START  0
#define MT_PTYPE_DATA        1
#define MT_PTYPE_ACK         2
#define MT_PTYPE_SESS_END    255

/* Control section */
#define MT_CPTYPE_BEGINAUTH      0
#define MT_CPTYPE_ENCRYPTKEY     1
#define MT_CPTYPE_PASSWORD       2
#define MT_CPTYPE_USERNAME       3
#define MT_CPTYPE_TERM_TYPE      4
#define MT_CPTYPE_TERM_WIDTH     5
#define MT_CPTYPE_TERM_HEIGHT    6
#define MT_CPTYPE_PACKET_ERROR   7
#define MT_CPTYPE_ENDAUTH        9


struct __attribute__((packed)) mt_client_packet_hdr
{
  u_int8_t ver,
           ptype;
  u_int8_t srcmac[6],
           dstmac[6];
  u_int16_t sesskey,
            ctype;
  u_int32_t seq;
};

struct __attribute__((packed)) mt_server_packet_hdr
{
  u_int8_t ver,
           ptype;
  u_int8_t srcmac[6],
           dstmac[6];
  u_int16_t ctype,
            sesskey;
  u_int32_t seq;
};

struct __attribute__((packed)) mt_control_packet_hdr
{
  u_int32_t cpmagic;
  u_int8_t  cptype;
  u_int32_t cplen;
};
