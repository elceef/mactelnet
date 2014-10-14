/*
 * MAC-Telnet - Telnet over Layer-2
 * --------------------------------
 * Copyright (c) 2011 Marcin Ulikowski <elceef@itsec.pl>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#define _GNU_SOURCE
#define VERSION "0.05"

#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <libnet.h>
#include <pcap.h>
#include "mndp.h"
#include "protocol.h"
#include "md5.h"


static libnet_t *l;
static u_int8_t *dstmac;
static struct libnet_ether_addr *srcmac;
static char libnet_errbuff[LIBNET_ERRBUF_SIZE];

static pcap_t *p;
static int pcapfd;
static struct bpf_program fp;
static char libpcap_errbuff[PCAP_ERRBUF_SIZE];

static struct termios oflags, nflags;
static struct winsize ws;
static int sndrcv = 1;
static u_int16_t sesskey;
static u_int32_t outseq = 0,
                 inseq = 0,
                 keepcnt = 0;
static u_int16_t srcport;
static u_int8_t data[1500];
static unsigned char encryptkey[128];
static char username[64];
static char password[64];


static void bug(char *format, ...);
static char* getpassword(const char *prompt);
static int init_packet_header(u_int8_t *packet, u_int8_t ptype, u_int8_t *srcmac, u_int8_t *dstmac, u_int32_t cnt);
static int init_control_packet_header(u_int8_t *packet, u_int8_t cptype, u_int32_t cplen);
static void handle_mt(u_int8_t *args, struct pcap_pkthdr *header, u_int8_t *packet);
static void handle_mndp(u_int8_t *args, struct pcap_pkthdr *header, u_int8_t *packet);
static int send_frame(u_int8_t *dstmac, u_int16_t srcport, u_int16_t dstport, u_int8_t *payload, u_int16_t psize, u_int32_t retr);


int main(int argc, char *argv[])
{
  int stat, i;
  fd_set fds;
  struct timeval timeout;

  if (argc < 2) {
    fprintf(stderr, "MAC-Telnet " VERSION "\n");
    fprintf(stderr, "Usage: %s [ interface ] [ MAC address ]\n", argv[0]);
    fprintf(stderr, "Example: %s eth0 ee:11:cc:ee:ee:ff\n", argv[0]);
    exit(0);
  }

  if (!(p = pcap_open_live(argv[1], 1514, 0, 1, libpcap_errbuff)))
    bug("%s\n", libpcap_errbuff);

  if (!(l = libnet_init(LIBNET_LINK, argv[1], libnet_errbuff)))
    bug("%s\n", libnet_errbuff);

  if (argc == 2) // MNDP
  {
    printf("Discovering Mikrotik routers... (CTRL+C to abort)\n");
    send_frame((u_int8_t *)"\xff\xff\xff\xff\xff\xff", 5678, 5678, (u_int8_t *)"\0\0\0\0", 4, 0);

    if (pcap_compile(p, &fp, "udp and port 5678 and len > 46", 1, 0))
      bug("pcap_compile(): syntax error\n");

    pcap_setfilter(p, &fp);

    pcap_loop(p, -1, (pcap_handler)&handle_mndp, 0);

    exit(0);
  }

  if (!(dstmac = libnet_hex_aton(argv[2], &i)))
    bug("%s\n", libnet_geterror(l));

  if (!(srcmac = libnet_get_hwaddr(l)))
    bug("%s\n", libnet_geterror(l));

  if (pcap_compile(p, &fp, "udp and src port 20561", 1, 0))
    bug("pcap_compile(): syntax error\n");

  pcap_setfilter(p, &fp);

  if (pcap_setnonblock(p, 1, libpcap_errbuff) == -1)
    fprintf(stderr, "%s", libpcap_errbuff);

  pcapfd = pcap_get_selectable_fd(p);
//  pcapfd = pcap_fileno(p);

  printf("Trying %02x:%02x:%02x:%02x:%02x:%02x ...\n",
         dstmac[0], dstmac[1], dstmac[2], dstmac[3], dstmac[4], dstmac[5]);

  printf("Username: ");
  scanf("%63s", username);

  char *tmpass;
  tmpass = getpassword("Password: ");
  strncpy(password, tmpass, sizeof(password) - 1);
  password[sizeof(password) - 1] = '\0';
  bzero(tmpass, strlen(tmpass));
  free(tmpass);

  srcport = libnet_get_prand(LIBNET_PRu16);
  sesskey = libnet_get_prand(LIBNET_PRu16);

  bzero(data, sizeof(data));
  init_packet_header(data, MT_PTYPE_SESS_START, srcmac->ether_addr_octet, dstmac, 0);
  send_frame(dstmac, srcport, 20561, data, sizeof(struct mt_client_packet_hdr), 1);

  bzero(data, sizeof(data));
  init_packet_header(data, MT_PTYPE_DATA, srcmac->ether_addr_octet, dstmac, 0);
  outseq += init_control_packet_header(data + sizeof(struct mt_client_packet_hdr), MT_CPTYPE_BEGINAUTH, 0);
  send_frame(dstmac, srcport, 20561, data, sizeof(struct mt_client_packet_hdr) + sizeof(struct mt_control_packet_hdr), 1);

  setvbuf(stdout, (char *)NULL, _IONBF, 0);

  while (sndrcv) {
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    FD_SET(pcapfd, &fds);
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    bzero(data, sizeof(data));

    stat = select(pcapfd + 1, &fds, NULL, NULL, &timeout);

    if (stat > 0)
    {
      if (FD_ISSET(pcapfd, &fds))
      {
        pcap_dispatch(p, 1, (pcap_handler)&handle_mt, (u_char *)NULL);
      }

      if (FD_ISSET(STDIN_FILENO, &fds))
      {
        unsigned char buttons[256];
        unsigned int bn;

        if ((bn = read(STDIN_FILENO, &buttons, sizeof(buttons))) <= 0)
          perror("read()");

        init_packet_header(data, MT_PTYPE_DATA, srcmac->ether_addr_octet, dstmac, outseq);
        memcpy(&data[22], buttons, bn);

        outseq += bn;

        send_frame(dstmac, srcport, 20561, data, sizeof(struct mt_client_packet_hdr) + bn, 1);
      }
    }
    else
    {
      if (keepcnt++ == 10) {
        init_packet_header(data, MT_PTYPE_ACK, srcmac->ether_addr_octet, dstmac, outseq);
        send_frame(dstmac, srcport, 20561, data, sizeof(struct mt_client_packet_hdr), 0);
      }
    }
  }

  libnet_destroy(l);
  pcap_close(p);
  free(dstmac);

  printf("\nQuestions? Complaints? You can reach the author at <marcin@ulikowski.pl>\n");

  return 0;
}


static void bug(char *format, ...) {
  char buffer[255];
  va_list args;

  va_start(args, format);
  vsnprintf(buffer, sizeof(buffer) - 1, format, args);
  fprintf(stderr, "%s", buffer);
  va_end(args);

  exit(1);
}


static char* getpassword(const char *prompt)
{
  char *ptr = malloc(256+1);
  char *p;
  sigset_t sig, sigsave;
  struct termios term, termsave;
  FILE *fp;
  int i = 0, c;

  if ( (fp = fopen(ctermid(NULL), "r+")) == NULL )
    return NULL;
  setbuf(fp, NULL);

  sigemptyset(&sig);
  sigaddset(&sig, SIGINT);
  sigaddset(&sig, SIGTSTP);
  sigprocmask(SIG_BLOCK, &sig, &sigsave);

  tcgetattr(fileno(fp), &termsave);
  term = termsave;
  term.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
  tcsetattr(fileno(fp), TCSAFLUSH, &term);

  fputs(prompt, fp);

  p = ptr;

  while ( (c = getc(fp)) != EOF && c != '\n')
  {
    if (i++ < 256) *ptr++ = c;
  }

  *ptr = 0;
  putc('\n', fp);

  tcsetattr(fileno(fp), TCSAFLUSH, &termsave);

  sigprocmask(SIG_SETMASK, &sigsave, NULL);
  fclose(fp);

  return p;
}


static void send_auth(char *user, char *pass) {
  u_int16_t width = 0,
            height = 0;
  char *terminal = getenv("TERM");
  char md5data[100];
  unsigned char md5sum[17];
  u_int16_t plen = 0;
  md5_state_t state;

  md5data[0] = 0;
  strncpy(md5data + 1, pass, 82);
  md5data[83] = '\0';
  memcpy(md5data + 1 + strlen(pass), encryptkey, 16);

  md5_init(&state);
  md5_append(&state, (const md5_byte_t *)md5data, strlen(pass) + 17);
  md5_finish(&state, (md5_byte_t *)md5sum + 1);
  md5sum[0] = 0;

  bzero(data, sizeof(data));
  plen = init_packet_header(data, MT_PTYPE_DATA, srcmac->ether_addr_octet, dstmac, outseq);

  plen += init_control_packet_header(data + plen, MT_CPTYPE_PASSWORD, sizeof(md5sum));
  memcpy(data + plen, md5sum, sizeof(md5sum));
  plen += sizeof(md5sum);

  plen += init_control_packet_header(data + plen, MT_CPTYPE_USERNAME, strlen(user));
  memcpy(data + plen, username, strlen(user));
  plen += strlen(user);

  plen += init_control_packet_header(data + plen, MT_CPTYPE_TERM_TYPE, strlen(terminal));
  memcpy(data + plen, terminal, strlen(terminal));
  plen += strlen(terminal);

  if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) != 0)
    perror("ioctl()");

  width = (ws.ws_col) ? ws.ws_col : 80;
  height = (ws.ws_row) ? ws.ws_row : 25;

  plen += init_control_packet_header(data + plen, MT_CPTYPE_TERM_WIDTH, 2);
#if BYTE_ORDER == LITTLE_ENDIAN
  width = htons(width);
#endif
  memcpy(data + plen, &width, 2);
  plen += 2;
  plen += init_control_packet_header(data + plen, MT_CPTYPE_TERM_HEIGHT, 2);
#if BYTE_ORDER == LITTLE_ENDIAN
  height = htons(height);
#endif
  memcpy(data + plen, &height, 2);
  plen += 2;

  send_frame(dstmac, srcport, 20561, data, plen, 1);

  outseq += plen - sizeof(struct mt_client_packet_hdr);
}


static int init_packet_header(u_int8_t *packet, u_int8_t ptype, u_int8_t *smac, u_int8_t *dmac, u_int32_t cnt)
{
  struct mt_client_packet_hdr *mtp = (struct mt_client_packet_hdr *)packet;

  mtp->ver = 1;
  mtp->ptype = ptype;
  memcpy(mtp->srcmac, smac, 6);
  memcpy(mtp->dstmac, dmac, 6);
#if BYTE_ORDER == LITTLE_ENDIAN
  mtp->sesskey = htons(sesskey);
  mtp->ctype = htons(MT_MACTELNET);
  mtp->seq = htonl(cnt);
#else
  mtp->sesskey = sesskey;
  mtp->ctype = MT_MACTELNET;
  mtp->seq = cnt;
#endif

  return sizeof(struct mt_client_packet_hdr);
}


static int init_control_packet_header(u_int8_t *packet, u_int8_t cptype, u_int32_t cplen)
{
  struct mt_control_packet_hdr *mtcp = (struct mt_control_packet_hdr *)packet;

  mtcp->cpmagic = MT_CONTROL_MAGIC;
  mtcp->cptype = cptype;
#if BYTE_ORDER == LITTLE_ENDIAN
  mtcp->cplen = htonl(cplen);
#else
  mtcp->cplen = cplen;
#endif
  return sizeof(struct mt_control_packet_hdr);
}


static void handle_mt(u_int8_t *args, struct pcap_pkthdr *header, u_int8_t *packet)
{
  struct libnet_ipv4_hdr *ipv4_hdr;
  struct libnet_udp_hdr *udp_hdr;
  struct mt_server_packet_hdr *mtp_hdr;
  struct mt_control_packet_hdr *mtcp_hdr;
  u_int8_t *pdata;
  u_int32_t dlen;
  int i;

  ipv4_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
  udp_hdr = (struct libnet_udp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4_hdr->ip_hl << 2));
  mtp_hdr = (struct mt_server_packet_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4_hdr->ip_hl << 2) + sizeof(struct libnet_udp_hdr));
  pdata = (u_int8_t *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4_hdr->ip_hl << 2) + sizeof(struct libnet_udp_hdr) + sizeof(struct mt_server_packet_hdr));

#if BYTE_ORDER == LITTLE_ENDIAN
  if (htons(mtp_hdr->sesskey) != sesskey)
#else
  if (mtp_hdr->sesskey != sesskey)
#endif
  {
#ifdef __DEBUG
    fprintf(stderr, "Wrong session key!\n");
#endif
    return;
  }

  if (mtp_hdr->ptype == MT_PTYPE_DATA)
  {
#if BYTE_ORDER == LITTLE_ENDIAN
    dlen = ntohs(ipv4_hdr->ip_len) - (ipv4_hdr->ip_hl << 2) - sizeof(struct libnet_udp_hdr) - sizeof(struct mt_server_packet_hdr);
#else
    dlen = ipv4_hdr->ip_len - (ipv4_hdr->ip_hl << 2) - sizeof(struct libnet_udp_hdr) - sizeof(struct mt_server_packet_hdr);
#endif

    bzero(data, sizeof(data));
#if BYTE_ORDER == LITTLE_ENDIAN
    init_packet_header(data, MT_PTYPE_ACK, srcmac->ether_addr_octet, dstmac, ntohl(mtp_hdr->seq) + dlen);
#else
    init_packet_header(data, MT_PTYPE_ACK, srcmac->ether_addr_octet, dstmac, mtp_hdr->seq + dlen);
#endif
    send_frame(dstmac, srcport, 20561, data, sizeof(struct mt_client_packet_hdr), 0);

#if BYTE_ORDER == LITTLE_ENDIAN
    if (!inseq || ntohl(mtp_hdr->seq) > inseq || (inseq - ntohl(mtp_hdr->seq)) > 65535)
    {
      inseq = ntohl(mtp_hdr->seq);
    } else {
      return;
    }
#else
    if (!inseq || mtp_hdr->seq > inseq || (inseq - mtp_hdr->seq) > 65535)
    {
      inseq = mtp_hdr->seq;
    } else {
      return;
    }
#endif

    for (i = 0; i < dlen; i++)
    {
      mtcp_hdr = (struct mt_control_packet_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4_hdr->ip_hl << 2) + sizeof(struct libnet_udp_hdr) + sizeof(struct mt_server_packet_hdr) + i);

      if (mtcp_hdr->cpmagic == MT_CONTROL_MAGIC) // control data
      {
        if (mtcp_hdr->cptype == MT_CPTYPE_ENCRYPTKEY)
        {
#if BYTE_ORDER == LITTLE_ENDIAN
           memcpy(&encryptkey, pdata + sizeof(struct mt_control_packet_hdr), ntohl(mtcp_hdr->cplen));
#else
           memcpy(&encryptkey, pdata + sizeof(struct mt_control_packet_hdr), mtcp_hdr->cplen);
#endif
           send_auth(username, password);
        }
        else
        if (mtcp_hdr->cptype == MT_CPTYPE_ENDAUTH)
        {
          if (tcgetattr(STDIN_FILENO, &oflags) < 0)
          perror("tcgetattr()");

          memcpy(&nflags, &oflags, sizeof(struct termios));

          cfmakeraw(&nflags);

          if (tcsetattr(STDIN_FILENO, TCSANOW, &nflags) < 0)
            perror("tcsetattr()");

          setvbuf(stdin, (char *)NULL, _IONBF, 0);
        }
      }
      else
      {
        printf("%s", pdata);
        break;
      }

      i += mtcp_hdr->cplen + sizeof(struct mt_control_packet_hdr) - 1;
    }
  }
  else
  if (mtp_hdr->ptype == MT_PTYPE_ACK)
  {
  //TODO:
  }
  else
  if (mtp_hdr->ptype == MT_PTYPE_SESS_END)
  {
    bzero(data, sizeof(data));
    init_packet_header(data, MT_PTYPE_SESS_END, srcmac->ether_addr_octet, dstmac, 0);
    send_frame(dstmac, srcport, 20561, data, sizeof(struct mt_client_packet_hdr), 0);

    fprintf(stderr, "\nConnection closed.\n");

    if (tcsetattr(STDIN_FILENO, TCSANOW, &oflags) < 0)
      perror("tcsetattr()");

    sndrcv = 0;
  }
  else
  {
#ifdef __DEBUG
    fprintf(stderr, "Unhandled packet type: %d\n", mtp_hdr->ptype);
#endif
  }
}


static void handle_mndp(u_int8_t *args, struct pcap_pkthdr *header, u_int8_t *packet)
{
  struct libnet_ipv4_hdr *ipv4_hdr;
  struct libnet_udp_hdr *udp_hdr;
  struct mndp_header *mndp_hdr;

  ipv4_hdr = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
  udp_hdr = (struct libnet_udp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4_hdr->ip_hl << 2));
  mndp_hdr = (struct mndp_header *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4_hdr->ip_hl << 2) + sizeof(struct libnet_udp_hdr));

  int i, j;
  u_int8_t *p;
  u_int16_t type, len, uh_ulen;
  u_int32_t ip;

#if BYTE_ORDER == LITTLE_ENDIAN
  uh_ulen = htons(udp_hdr->uh_ulen);
#else
  uh_ulen = udp_hdr->uh_ulen;
#endif

  p = (u_int8_t *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4_hdr->ip_hl << 2) + sizeof(struct libnet_udp_hdr) + sizeof(struct mndp_header));

  for (i = 0; i < (uh_ulen - sizeof(struct libnet_udp_hdr) - 4); i++) {

    memcpy(&type, p, 2);
    memcpy(&len, p+2, 2);
#if BYTE_ORDER == LITTLE_ENDIAN
    type = ntohs(type);
    len = ntohs(len);
#endif
    p+=4;

    switch (type) {

      case MNDP_TYPE_ADDRESS:
        printf("%02x:%02x:%02x:%02x:%02x:%02x  ", *p, *(p+1), *(p+2), *(p+3), *(p+4), *(p+5));
        break;

      case MNDP_TYPE_IDENTITY:
      case MNDP_TYPE_VERSION:
      case MNDP_TYPE_PLATFORM:
#ifdef __DEBUG
      case MNDP_TYPE_SOFTID:
#endif
      case MNDP_TYPE_CPUARCH:
        for (j = 0; j < len; j++) {
          putchar(*(p+j));
        }
        putchar(' ');
        break;

      case MNDP_TYPE_TIMESTAMP:
        memcpy(&j, p, 4);
        printf("up~%udays%uh ", j/86400, j%86400/3600);
        break;

      default:
#ifdef __DEBUG
        printf("type=%04x len=%u val=", type, len);
        for (j = 0; j < len; j++) {
          printf("%02x", *(p+j));
        }
        putchar('|');
        for (j = 0; j < len; j++) {
          if (*(p+j) >= 32 && *(p+j) < 128)
          {
            putchar(*(p+j));
          } else {
            putchar('.');
          }
        }
        putchar(' ');
#endif
        break;
    }

    p += len;
    i += len + 3;
  }

  memcpy(&ip, &ipv4_hdr->ip_src.s_addr, 4);
#if BYTE_ORDER == LITTLE_ENDIAN
  ip = ntohl(ip);
#endif
  p = (u_int8_t *)&ip;
  printf("%u.%u.%u.%u\n", p[3], p[2], p[1], p[0]);
}


static int send_frame(u_int8_t *dmac, u_int16_t sport, u_int16_t dport, u_int8_t *payload, u_int16_t psize, u_int32_t retr)
{
  unsigned int i, bytes;

  keepcnt = 0;

  libnet_build_udp
  (
    sport,
    dport,
    LIBNET_UDP_H + psize,
    0,
    payload,
    psize,
    l,
    0
  );

  libnet_build_ipv4
  (
    LIBNET_UDP_H + LIBNET_IPV4_H + psize, // length
    0, // ToS
    0, // id autogenerated
    0, // fragmentation bits & offset
    64, // TTL
    IPPROTO_UDP,
    0, // checksum autogenerated
    0, // srcip = 0.0.0.0
    4294967295U, // dstip = 255.255.255.255
    NULL,
    0,
    l,
    0
  );


  libnet_autobuild_ethernet
  (
    dmac,
    ETHERTYPE_IP,
    l
  );

  bytes = libnet_write(l);
  libnet_clear_packet(l);

  if (retr) //TODO: stop only if ACK
  {
    for (i = 0; i < 9; ++i)
    {
      fd_set rfds;
      int stat = 0;
      struct timeval timeout;
      int intval = retr_intval[i] * 1000;

      FD_ZERO(&rfds);
      FD_SET(pcapfd, &rfds);
      timeout.tv_sec = 0;
      timeout.tv_usec = intval;

      stat = select(pcapfd + 1, &rfds, NULL, NULL, &timeout);

      if (stat && FD_ISSET(pcapfd, &rfds)) {
        return bytes;
      }

      send_frame(dmac, sport, dport, payload, psize, 0);
    }

    fprintf(stderr, "\nConnection timed out\n");
    exit(1);
  }

  return bytes;
}
