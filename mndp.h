#define MNDP_TYPE_ADDRESS   0x0001
#define MNDP_TYPE_IDENTITY  0x0005
#define MNDP_TYPE_VERSION   0x0007
#define MNDP_TYPE_PLATFORM  0x0008
#define MNDP_TYPE_TIMESTAMP 0x000a
#define MNDP_TYPE_SOFTID    0x000b
#define MNDP_TYPE_CPUARCH   0x000c

struct mndp_header {
  u_int8_t version;
  u_int8_t ttl;
  u_int16_t cksum;
};
