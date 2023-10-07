#ifndef __DNS_PROTOCOL_H__
#define __DNS_PROTOCOL_H__

int qname_len;

/*
//both uint32_t n uint16_t works fine

static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x0080;
static const uint32_t Z_MASK = 0x0000;
static const uint32_t RCODE_MASK = 0x000F;
*/

static const uint16_t QR_MASK = 0x8000;
static const uint16_t OPCODE_MASK = 0x7800;
static const uint16_t AA_MASK = 0x0400;
static const uint16_t TC_MASK = 0x0200;
static const uint16_t RD_MASK = 0x0100;
static const uint16_t RA_MASK = 0x0080;
static const uint16_t Z_MASK = 0x0000;
static const uint16_t RCODE_MASK = 0x000F;

struct dns_header{
    uint16_t id;
    uint16_t qr;        //:1;
    uint16_t opcode; // :4;
    uint16_t aa;       //:1;
    uint16_t tc;        //:1;
    uint16_t rd;      // :1;
    uint16_t ra;       // :1;
    uint16_t z;        //:3;
    uint16_t rcode ;   // :4;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dns_question{
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
    struct dns_question *next;
};

struct dns_answer{
    char *name;
    uint16_t  type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t addr[4];
    struct dns_answer *next;
};

extern struct dns_answer *answer;

struct dns_r_packet{
    struct dns_header *r_header;
    struct dns_question *r_question;
    struct dns_answer *r_answer;
};

extern struct dns_r_packet *r_packet;

#endif


/*
struct dns_packet{
    struct dns_header header;
    struct dns_question question;
    char *data;
    u_int16_t data_size;
};
ghbn n
*/