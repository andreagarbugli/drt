#define DRT_IMPLEMENTATION
#include "drt.h"

#include <signal.h>

///////////////////////////////////////////////////////////////////////////////
// Network Specific Includes
#if OS_LINUX
# include <pthread.h>
# include <arpa/inet.h>
# include <linux/if.h>
# include <linux/if_tun.h>     // IFF_TAP
# include <netinet/in.h>
# include <sys/ioctl.h>
# include <sys/socket.h>
#endif
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Definitions
#define TUN_NAME            "utcp0"
#define TUN_PATH            "/dev/net/tun"

#define DEVICE_ADDRESS      "10.0.0.10"
#define NETDEV1_HWADDR      "00:00:00:00:00:10"

// --- Double Linked List
#define dllist_init(l, n)                   \
    do {                                    \
        (l)->head = (l)->tail = (n);        \
    } while(0)

#define dllist_push(l, n)                   \
    do {                                    \
        if ((l)->head == NULL) {            \
            dllist_init(l, n);              \
        } else {                            \
            (n)->prev       = (l)->tail;    \
            (n)->next       = NULL;         \
            (l)->tail->next = (n);          \
            (l)->tail       = (n);          \
        }                                   \
    } while(0)

#define dllist_push_front(l, n)             \
    do {                                    \
        if ((l)->head == NULL) {            \
            dllist_init_node(l, n);         \
        } else {                            \
            (n)->prev       = NULL;         \
            (n)->next       = (l)->head;    \
            (l)->head->prev = (n);          \
            (l)->head       = (n);          \
        }                                   \
    } while(0)

#define dllist_insert(l, p, n)                      \
    do {                                            \
        if ((l)->head == NULL) {                    \
            dllist_init(l, n);                      \
        } else {                                    \
            (n)->prev       = (p);                  \
            (n)->next       = (p)->next;            \
            (p)->next->prev = (n);                  \
            (p)->next       = (n);                  \
            if ((l)->tail == (p)) (l)->tail = (n);  \
        }                                           \
    } while(0)

#define dllist_remove(l, n)                                         \
    do {                                                            \
        if ((n)->prev == (n)) {                                     \
            dllist_init(l, NULL);                                   \
        } else {                                                    \
            if ((n)->prev)        (n)->prev->next = (n)->next;      \
            if ((n)->next)        (n)->next->prev = (n)->prev;      \
            if ((l)->head == (n)) (l)->head = (n)->next;            \
            if ((l)->tail == (n)) (l)->tail = (n)->prev;            \
        }                                                           \
    } while(0)

#define dllist_foreach(l, n)                \
    for (n = (l)->head; n; n = n->next)

///////////////////////////////////////////////////////////////////////////////
// Common Functions

void
ipv4_to_cstr(u32 ip, char out_str[16])
{
    memory_zero(out_str, 16);
    // NOTE(garbu): The ip address is stored in host byte order.
    u8 *bytes = (u8 *)&ip;
    snprintf(out_str, 16, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

#if ENDIAN_LITTLE
# define host_to_net_u16(x) u16_swap_endian(x)
# define host_to_net_u32(x) u32_swap_endian(x)
# define net_to_host_u16(x) u16_swap_endian(x)
# define net_to_host_u32(x) u32_swap_endian(x)
#else // BIG ENDIAN
# define host_to_net_u16(x) (x)
# define host_to_net_u32(x) (x)
# define net_to_host_u16(x) (x)
# define net_to_host_u32(x) (x)
#endif

///////////////////////////////////////////////////////////////////////////////
// Structs

// --- Network Stack
//  --- Ethernet
#define ETH_ADDR_LEN          6
#define ETH_HDR_LEN           14
#define ETH_VLAN_HDR_LEN      18

#define ETH_PTYPE_IPV4         0x0800
#define ETH_PTYPE_ARP          0x0806
#define ETH_PTYPE_IPV6         0x86DD
#define ETH_PTYPE_VLAN         0x8100

typedef struct eth_addr eth_addr;
struct eth_addr
{
    u8 addr[6];
};

static inline void snprint_eth_addr(eth_addr *addr, char buf[18]) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr->addr[0], addr->addr[1], addr->addr[2],
             addr->addr[3], addr->addr[4], addr->addr[5]);
}

typedef struct eth_hdr eth_hdr;
struct_packed eth_hdr
{
    eth_addr    dst;
    eth_addr    src;
    u16         type;
} struct_packed_end;

inline_fn char *
eth_etype_to_string(u16 etype)
{
    switch(etype) {
    case ETH_PTYPE_IPV4:    return "ipv4";
    case ETH_PTYPE_ARP:     return "arp";
    case ETH_PTYPE_IPV6:    return "ipv6";
    case ETH_PTYPE_VLAN:    return "vlan";
    default:                return "unknown";
    }
}

static inline void 
print_eth_hdr(eth_hdr *hdr) {
    printf("ETH: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x [%s (0x%04x)]\n",
           hdr->src.addr[0], hdr->src.addr[1], hdr->src.addr[2], hdr->src.addr[3], hdr->src.addr[4], hdr->src.addr[5],
           hdr->dst.addr[0], hdr->dst.addr[1], hdr->dst.addr[2], hdr->dst.addr[3], hdr->dst.addr[4], hdr->dst.addr[5],
           eth_etype_to_string(hdr->type), hdr->type
    );
}

typedef struct eth_vlan_hdr eth_vlan_hdr;
struct_packed eth_vlan_hdr
{
    eth_hdr     hdr;
    u16         tci;
    u16         type;
} struct_packed_end;

//  --- ARP
#define ARP_HW_TYPE_ETHERNET  0x0001
#define ARP_PROTO_IPV4        0x0800

#define ARP_OP_REQUEST        0x0001
#define ARP_OP_REPLY          0x0002

static const char *s_arp_op_str[] = {
    "UNKNOWN",
    "REQUEST",
    "REPLY",
};

typedef struct arp_hdr arp_hdr;
struct_packed arp_hdr
{
    u16 hw_type;
    u16 proto_type;
    u8  hw_addr_len;
    u8  proto_addr_len;
    u16 op;
} struct_packed_end;

inline_fn void
arp_header_net_to_host(arp_hdr *hdr)
{
    hdr->hw_type     = net_to_host_u16(hdr->hw_type);
    hdr->proto_type  = net_to_host_u16(hdr->proto_type);
    hdr->op          = net_to_host_u16(hdr->op);
}

inline_fn void
arp_header_host_to_net(arp_hdr *hdr)
{
    hdr->hw_type     = host_to_net_u16(hdr->hw_type);
    hdr->proto_type  = host_to_net_u16(hdr->proto_type);
    hdr->op          = host_to_net_u16(hdr->op);
}

typedef struct arp_ipv4 arp_ipv4;
struct_packed arp_ipv4
{
    arp_hdr hdr;
    u8      src_hw[6];
    u32     src_ip;
    u8      dst_hw[6];
    u32     dst_ip;
} struct_packed_end;

inline_fn void
arp_ipv4_net_to_host(arp_ipv4 *arp)
{
    arp_header_net_to_host(&arp->hdr);
    arp->src_ip = net_to_host_u32(arp->src_ip);
    arp->dst_ip = net_to_host_u32(arp->dst_ip);
}

inline_fn void
arp_ipv4_host_to_net(arp_ipv4 *arp)
{
    arp_header_host_to_net(&arp->hdr);
    arp->src_ip = host_to_net_u32(arp->src_ip);
    arp->dst_ip = host_to_net_u32(arp->dst_ip);
}

#define ARP_STATE_UNKNOWN   0
#define ARP_STATE_RESOLVED  1
#define ARP_STATE_STALE     2

static const char *s_arp_state_str[] = {
    "UNKNOWN",
    "RESOLVED",
    "STALE",
};

typedef struct arp_entry arp_entry;
struct arp_entry
{
    arp_entry *next;
    arp_entry *prev;

    u32        ip;
    eth_addr   addr;
    u8         state;
};

typedef struct arp_table arp_table;
struct arp_table
{
    arena    *arena;

    arp_entry *head;
    arp_entry *tail;
    usize      count;
};

arp_table *
arp_table_alloc()
{
    arena *arena     = arena_vm_alloc(.reserve_size=MB(1));
    arp_table *table = arena_push_struct(arena, arp_table);
    table->arena     = arena;
    dllist_init(table, NULL);
    return table;
}

//  --- IPv4

inline_fn u16
u16_checksum(void *buf, usize len)
{
    u16 *data = (u16 *)buf;
    u32 sum = 0;

    // sum all the 16-bit words
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }

    // if len is odd, add the last byte padded with 0
    if (len > 0)    sum += *(u8 *)data;

    // fold 32-bit sum to 16 bits
    while (sum >> 16)   sum = (sum & 0xFFFF) + (sum >> 16);

    return (u16)(~sum);
}

#define IPV4_HDR_LEN_MIN        20
#define IPV4_HDR_LEN_MAX        60
#define IPV4_HDR_LEN_OPT        40
#define IPV4_ADDR_LEN           4

#define IP_PROTO_ICMP         0x01
#define IP_PROTO_TCP          0x06
#define IP_PROTO_UDP          0x11

static const char *s_ipv4_proto_str[] = {
    [IP_PROTO_ICMP] = "ICMP",
    [IP_PROTO_TCP]  = "TCP",
    [IP_PROTO_UDP]  = "UDP",
};

///////////////////////////////////////////////////////////////////////////////
// # IPv4
// The IPv4 header is used to encapsulate the data being sent over the network
//
//      0               1               2               3               4
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |Version|  IHL  |Type of Service|          Total Length         |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |         Identification        |Flags|      Fragment Offset    |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |  Time to Live |    Protocol   |         Header Checksum       |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                       Source Address                          |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                    Destination Address                        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                    Options                    |    Padding    |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
typedef struct ip_hdr ip_hdr;
struct_packed ip_hdr
{
    union {
        u8  ver_ihl;
        struct {
            u8  ihl:4;
            u8  ver:4;
        };
    };
    u8      tos;
    u16     len;
    u16     id;
    u16     frag_off;
    u8      ttl;
    u8      proto;
    u16     csum;
    u32     src;
    u32     dst;
} struct_packed_end;

void
print_ipv4_hdr(ip_hdr *hdr)
{
    char src_str[16], dst_str[16];
    ipv4_to_cstr(hdr->src, src_str);
    ipv4_to_cstr(hdr->dst, dst_str);
    printf("IPv4: %s -> %s [0x%04x]\n", src_str, dst_str, hdr->proto);
}

#define IP_VERSION_4          4
#define IP_IHL_MIN            5

#define IP_FLAG_DF                  0x4000  // Don't Fragment flag (bit 14)
#define IP_FLAG_MF                  0x2000  // More Fragments flag (bit 13)

#define IP_HDR_GET_FLAGS(hdr)       ((hdr->frag_off) & 0xE000)
#define IP_HDR_GET_OFFSET(hdr)      ((hdr->frag_off) & 0x1FFF)

#define IP_HDR_SET_FLAGS(hdr, f)    ((hdr->frag_off) |= (f))
#define IP_HDR_SET_OFFSET(hdr, o)   ((hdr->frag_off) |= (o & 0x1FFF))

#define IP_SET_DF(hdr)              IP_HDR_SET_FLAGS(hdr, IP_FLAG_DF)
#define IP_CLEAR_DF(hdr)            ((hdr->frag_off) &= ~IP_FLAG_DF)
#define IP_SET_MF(hdr)              IP_HDR_SET_FLAGS(hdr, IP_FLAG_MF)
#define IP_CLEAR_MF(frag_off)       ((hdr->frag_off) &= ~IP_FLAG_MF)

inline_fn u16 ipv4_header_len (ip_hdr *hdr) { return hdr->ihl * 4; }
inline_fn u16 ipv4_csum       (ip_hdr *hdr) { return u16_checksum(hdr, ipv4_header_len(hdr)); }

static inline void
ipv4_header_net_to_host(ip_hdr *ip)
{
    ip->len      = net_to_host_u16(ip->len);
    ip->id       = net_to_host_u16(ip->id);
    ip->frag_off = net_to_host_u16(ip->frag_off);
    ip->csum     = net_to_host_u16(ip->csum);
    ip->src      = net_to_host_u32(ip->src);
    ip->dst      = net_to_host_u32(ip->dst);
}

static inline void
ipv4_header_host_to_net(ip_hdr *ip)
{
    ip->len      = host_to_net_u16(ip->len);
    ip->id       = host_to_net_u16(ip->id);
    ip->frag_off = host_to_net_u16(ip->frag_off);
    ip->csum     = host_to_net_u16(ip->csum);
    ip->src      = host_to_net_u32(ip->src);
    ip->dst      = host_to_net_u32(ip->dst);
}

///////////////////////////////////////////////////////////////////////////////
// # ICMP

#define ICMP_TYPE_ECHO_REPLY    0
#define ICMP_TYPE_DEST_UNREACH  3
#define ICMP_TYPE_ECHO_REQUEST  8

static const char *s_icmp_type_str[] = {
    [ICMP_TYPE_ECHO_REPLY]   = "ECHO_REPLY",
    [ICMP_TYPE_ECHO_REQUEST] = "ECHO_REQUEST",
};

///////////////////////////////////////////////////////////////////////////////
// # ICMPv4
// The ICMPv4 header is used to send error messages and operational information
//
//     0               1               2               3               4
//      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |     Type      |     Code      |          Checksum             |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
typedef struct icmp4_hdr icmp4_hdr;
struct_packed icmp4_hdr
{
    u8  type;
    u8  code;
    u16 csum;
} struct_packed_end;

// # ICMPv4 Echo
//
//     0               1               2               3               4
//      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |     Type      |     Code      |          Checksum             |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     |           Identifier          |        Sequence Number        |
//     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
typedef struct icmp4_echo icmp4_echo;
struct_packed icmp4_echo
{
    icmp4_hdr hdr;
    u16       id;
    u16       seq;
} struct_packed_end;

inline_fn u16 icmp4_csum(icmp4_hdr *hdr, u16 len) { return u16_checksum(hdr, len); }

//  --- Routing
typedef struct route_entry route_entry;
struct route_entry
{
    route_entry *next;
    route_entry *prev;

    u32 destination;
    u32 gateway;
    u32 netmask;
    u8  flags;
    u32 metric;
};

typedef struct route_list route_list;
struct route_list
{
    route_entry *head;
    route_entry *tail;
    usize        count;
};

void
route_list_push(route_list *list, route_entry *entry)
{
    dllist_push(list, entry);
    list->count += 1;
}

route_entry *
route_list_remove(route_list *list, route_entry *entry)
{
    dllist_remove(list, entry);
    list->count -= 1;
    return entry;
}

// --- TCP

#define TCP_HDR_LEN_MIN        20
#define TCP_HDR_LEN_OPT        40
#define TCP_HDR_LEN_MAX        60

///////////////////////////////////////////////////////////////////////////////
// # TCP Header Format
//
//      0               1               2               3               4
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |          Source Port          |       Destination Port        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                        Sequence Number                        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                    Acknowledgment Number                      |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |  Data |       |C|E|U|A|P|R|S|F|                               |
//      | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
//      |       |       |R|E|G|K|H|T|N|N|                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |           Checksum            |         Urgent Pointer        |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                           [Options]                           |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               :
//      :                             Data                              :
//      :                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
typedef struct tcp_hdr tcp_hdr;
struct_packed tcp_hdr
{
    u16     src_port;
    u16     dst_port;
    u32     seq;
    u32     ack_seq;
    u8      reserved : 4;
    u8      data_offset : 4; // The number of 32-bit words in the TCP header
    u8      flags;
    u16     window;
    u16     csum;
    u16     urg_ptr;
} struct_packed_end;

inline_fn void
tcp_header_net_to_host(tcp_hdr *hdr)
{
    hdr->src_port = net_to_host_u16(hdr->src_port);
    hdr->dst_port = net_to_host_u16(hdr->dst_port);
    hdr->seq      = net_to_host_u32(hdr->seq);
    hdr->ack_seq  = net_to_host_u32(hdr->ack_seq);
    hdr->window   = net_to_host_u16(hdr->window);
    hdr->csum     = net_to_host_u16(hdr->csum);
    hdr->urg_ptr  = net_to_host_u16(hdr->urg_ptr);
}

inline_fn void
tcp_header_host_to_net(tcp_hdr *hdr)
{
    hdr->src_port = host_to_net_u16(hdr->src_port);
    hdr->dst_port = host_to_net_u16(hdr->dst_port);
    hdr->seq      = host_to_net_u32(hdr->seq);
    hdr->ack_seq  = host_to_net_u32(hdr->ack_seq);
    hdr->window   = host_to_net_u16(hdr->window);
    hdr->csum     = host_to_net_u16(hdr->csum);
    hdr->urg_ptr  = host_to_net_u16(hdr->urg_ptr);
}

#define TCP_FLAG_FIN    0x01
#define TCP_FLAG_SYN    0x02
#define TCP_FLAG_RST    0x04
#define TCP_FLAG_PSH    0x08
#define TCP_FLAG_ACK    0x10
#define TCP_FLAG_URG    0x20

#define TCP_HDR_SET_FLAG(h, x)  ((h)->flags |= (x))
#define TCP_HDR_CLR_FLAG(h, x)  ((h)->flags &= ~(x))
#define TCP_HDR_IS_FLAG(h, x)   ((h)->flags & (x))

static const char *s_tcp_flag_str[] = {
    [TCP_FLAG_FIN] = "FIN",
    [TCP_FLAG_SYN] = "SYN",
    [TCP_FLAG_RST] = "RST",
    [TCP_FLAG_PSH] = "PSH",
    [TCP_FLAG_ACK] = "ACK",
    [TCP_FLAG_URG] = "URG",
};

///////////////////////////////////////////////////////////////////////////////
// # TCP Pseudo Header
// The TCP pseudo header is used to calculate the TCP checksum
//
// 0       7 8     15 16    23 24    31
// +--------+--------+--------+--------+
// |           Source Address          |
// +--------+--------+--------+--------+
// |         Destination Address       |
// +--------+--------+--------+--------+
// |  zero  |  PTCL  |    TCP Length   |
// +--------+--------+--------+--------+
typedef struct tcp_ipv4_pseudo_hdr tcp_ipv4_pseudo_hdr;
struct_packed tcp_ipv4_pseudo_hdr
{
    u32 src_ip;
    u32 dst_ip;
    u8  zero;
    u8  proto;
    u16 len;
} struct_packed_end;

///////////////////////////////////////////////////////////////////////////////
// # TCP Options
// The generic format of the TCP options is as follows:
//
//      0               1               2               3
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |     Kind      |    Length     |    Kind-Dependent Values...   |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//  - The "Kind" field is one octet and specifies the option kind.
//  - The "Length" field is one octet and specifies the total length of the
//    option, including the kind and length fields.
//  - The "Kind-Dependent Values" field is zero or more octets long, and its
//    contents are determined by the value of the "Kind" field.
//
// ## TCP End of Option List Option
// The End of Option List option indicates the end of the list of TCP options.
//
//      0               1
//       0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+
//      |       0       |
//      +---------------+
//
// ## TCP No-Operation Option
// The No-Operation option is used to align the beginning of an option on a
// four-octet boundary.
//
//      0               1
//       0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+
//      |       1       |
//      +---------------+
//
// ## TCP Maximum Segment Size Option
// The Maximum Segment Size option specifies the maximum segment size that
// the sender of this option is willing to receive.
//
//      0               1               2               3               4
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |       2       |    Length=4   |   Maximum Segment Size (MSS)  |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// ## TCP Window Scale Option
// The Window Scale option specifies a scale factor that can be used to
// multiply the window size value in a TCP header to obtain the true window
// size.
//
//      0               1               2               3
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |       3       |    Length=3   |  shift.cnt    |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// ## TCP Selective Acknowledgment Option
//
// ## TCP Timestamps Option
// The Timestamps option is used for RTT estimation and PAWS.
//
//      0               1               2               3               4
//       0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |       8       |    Length=10  |   TS Value    | TS Echo Reply |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#define TCP_OPT_END         0x00
#define TCP_OPT_NOP         0x01
#define TCP_OPT_MSS         0x02
#define TCP_OPT_WS          0x03
#define TCP_OPT_SACK        0x04
#define TCP_OPT_TS          0x08

static const char *s_tcp_opt_str[] = {
    [TCP_OPT_END]  = "END",
    [TCP_OPT_NOP]  = "NOP",
    [TCP_OPT_MSS]  = "MSS",
    [TCP_OPT_WS]   = "WS",
    [TCP_OPT_SACK] = "SACK",
    [TCP_OPT_TS]   = "TS",
};

typedef struct tcp_opt tcp_opt;
struct_packed tcp_opt
{
    u8 kind;
    u8 len;
    union {
        u16 mss;
        u8  ws;
        u8  sack;
        struct {
            u32 ts_val;
            u32 ts_ecr;
        };
    };
} struct_packed_end;

// --- TCP Functions

inline_fn u16
tcp_csum(tcp_ipv4_pseudo_hdr *phdr, void *data, usize len)
{
    u32 sum = 0;
    u16 *ptr;

    // Add pseudo-header fields to the checksum
    ptr = (u16 *)phdr;
    for (usize i = 0; i < sizeof(tcp_ipv4_pseudo_hdr) / 2; i++) {
        sum += *ptr++;
    }

    // Add TCP segment data to the checksum
    ptr = (u16 *)data;
    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    // Handle any remaining byte if the length is odd
    if (len > 0) {
        sum += *(u8 *)ptr;
    }

    // Fold the checksum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return the one's complement of the checksum
    return (u16)(~sum);
}

void
snprint_tcp_flags(u8 flags, char buf[16])
{
    memory_zero(buf, 16);
    usize i = 0;
    if (flags & TCP_FLAG_FIN) buf[i++] = 'F';
    buf[i++] = '|';
    if (flags & TCP_FLAG_SYN) buf[i++] = 'S';
    buf[i++] = '|';
    if (flags & TCP_FLAG_RST) buf[i++] = 'R';
    buf[i++] = '|';
    if (flags & TCP_FLAG_PSH) buf[i++] = 'P';
    buf[i++] = '|';
    if (flags & TCP_FLAG_ACK) buf[i++] = 'A';
    buf[i++] = '|';
    if (flags & TCP_FLAG_URG) buf[i++] = 'U';
}

void print_tcp_hdr(tcp_hdr *hdr) {
    char flags[16];
    snprint_tcp_flags(hdr->flags, flags);
    printf("TCP: %d -> %d [%s] SEQ: %u ACK: %u OFF: %d CSUM: 0x%04x URG: %d\n", 
           hdr->src_port, hdr->dst_port,
           flags,
           hdr->seq, hdr->ack_seq,
           hdr->data_offset, hdr->csum, hdr->urg_ptr 
    );

    if (hdr->data_offset > 5) {
    }

    printf("\n");
}

///////////////////////////////////////////////////////////////////////////////
// # TCP State Machine
typedef enum {
    TCP_STATE_CLOSED,           // No connection state
    TCP_STATE_LISTEN,           // Waiting for a connection request from any remote TCP and port
    TCP_STATE_SYN_SENT,         // Waiting for a matching connection request after having sent a connection request
    TCP_STATE_SYN_RECEIVED,     // Waiting for a confirming connection request acknowledgment after having both received and sent a connection request
    TCP_STATE_ESTABLISHED,      // Open connection
    TCP_STATE_FIN_WAIT_1,       // Waiting for a connection termination request from the remote TCP, or an acknowledgment of the connection termination request previously sent
    TCP_STATE_FIN_WAIT_2,       // Waiting for a connection termination request from the remote TCP
    TCP_STATE_CLOSE_WAIT,       // Waiting for a connection termination request from the local user
    TCP_STATE_CLOSING,          // Waiting for a connection termination request acknowledgment from the remote TCP
    TCP_STATE_LAST_ACK,         // Waiting for an acknowledgment of the connection termination request previously sent to the remote TCP
    TCP_STATE_TIME_WAIT,        // Waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connection termination request
} tcp_state;

static const char *s_tcp_state_str[] = {
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RECEIVED",
    "ESTABLISHED",
    "FIN_WAIT_1",
    "FIN_WAIT_2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
};

///////////////////////////////////////////////////////////////////////////////
// # TCP Control Block

typedef struct tcp_tcb tcp_tcb;
struct tcp_tcb
{
    // --- Doubly Linked List
    tcp_tcb *next;
    tcp_tcb *prev;

    tcp_state state;
    bool passive;

    u32 local_ip;
    u32 remote_ip;
    u16 local_port;
    u16 remote_port;

    // Send Sequence Variables
    u32 snd_una; // Send unacknowledged
    u32 snd_nxt; // Send next
    u32 snd_wnd; // Send window
    u32 snd_up;  // Send urgent pointer
    u32 snd_wl1; // Segment sequence number used for last window update
    u32 snd_wl2; // Segment acknowledgment number used for last window update
    u32 iss;     // Initial send sequence number

    // Receive Sequence Variables
    u32 rcv_nxt; // Receive next
    u32 rcv_wnd; // Receive window
    u32 rcv_up;  // Receive urgent pointer
    u32 irs;     // Initial receive sequence number

    // Window size
    u16 send_window;
    u16 recv_window;

    // Current Segment Variables
    u32 seg_seq; // Segment sequence number
    u32 seg_ack; // Segment acknowledgment number
    u32 seg_len; // Segment length
    u32 seg_wnd; // Segment window
    u32 seg_up;  // Segment urgent pointer
};

// --- TCB List
typedef struct tcp_tcb_list tcp_tcb_list;
struct tcp_tcb_list
{
    tcp_tcb *head;
    tcp_tcb *tail;
    usize    count;
};

void 
print_tcp_tcb_list(tcp_tcb_list *list)
{
    printf("TCP TCB List:\n");
    if (list->count == 0) {
        printf("  (empty)\n");
    } else {
        int i = 0;
        char local_ip_str[16], remote_ip_str[16];
        tcp_tcb *tcb = NULL;
        char print_buf[256]; 
        dllist_foreach(list, tcb) {
            memory_zero(print_buf, 256);
            ipv4_to_cstr(tcb->local_ip, local_ip_str);
            ipv4_to_cstr(tcb->remote_ip, remote_ip_str);

            int n = snprintf(print_buf, sizeof(print_buf), "  [%d] [%s] %s:%d -> %s:%d",
                             i, s_tcp_state_str[tcb->state], local_ip_str, tcb->local_port,
                             remote_ip_str, tcb->remote_port
                    );

            if (tcb->state != TCP_STATE_ESTABLISHED)    snprintf(print_buf + n, sizeof(print_buf) - n, " (peerless)");

            printf("%s\n", print_buf);    
        }
    }
}

void
tcp_tcb_list_push(tcp_tcb_list *list, tcp_tcb *tcb)
{
    dllist_push(list, tcb);
    list->count += 1;
}

void 
tcp_tcb_list_remove(tcp_tcb_list *list, tcp_tcb *tcb)
{
    dllist_remove(list, tcb);
    list->count -= 1;
}

tcp_tcb *
tcp_tcb_list_find(tcp_tcb_list *list, u16 local_port, u16 remote_port)
{
    tcp_tcb *result = NULL, *tcb = NULL; 
    dllist_foreach(list, tcb) {
        if (tcb->local_port == local_port && tcb->remote_port == remote_port) {
            result = tcb;
            break;
        }
    }
    return result;
}

tcp_tcb *
tcp_tcb_list_find_local_peer(tcp_tcb_list *list, u32 local_ip, u16 local_port)
{
    tcp_tcb *result = NULL, *tcb = NULL; 
    dllist_foreach(list, tcb) {
        if (tcb->local_ip == local_ip && tcb->local_port == local_port) {
            result = tcb;
            break;
        }
    }

    return result;
}

// --- Memory Buffer
typedef struct mem_buf mem_buf;
struct mem_buf
{
    u8      *data;
    usize    len;
    usize    used;

    // --- Buffer Management
    usize    init_hr;   // The initial headroom of the buffer
    //  - The Headroom is where the buffer starts, but the data starts after the headroom.
    //    This is useful for when we need to prepend data to the buffer, e.g. extra headers.
    usize    start_off; // The actual start of the buffer
    usize    data_off;  // The start of the data
    usize    end_off;   // The end of the buffer

    usize    l2_size;
    usize    l3_size;
    usize    l4_size;

    u32     l2_type;
    u32     l3_type;
    u32     l4_type;
};

static inline mem_buf 
mem_buf_init(void *data, usize len, usize headroom)
{
    mem_buf buf;
    memory_zero_struct(&buf);
    buf.len  = len;
    buf.used = 0;
    buf.data = data;

    buf.init_hr   = headroom;
    buf.start_off = headroom;
    buf.data_off  = headroom;
    buf.end_off   = len;

    return buf;
}

inline_fn void 
mem_buf_clear(mem_buf *buf)
{
    memory_zero(buf->data, buf->len);
    buf->used      = 0;
    buf->start_off = buf->init_hr;
    buf->data_off  = buf->start_off;

    buf->l2_size = 0;
    buf->l3_size = 0;
    buf->l4_size = 0;

    buf->l2_type = 0;
    buf->l3_type = 0;
    buf->l4_type = 0;
}

inline_fn void mem_buf_set_l2 (mem_buf *buf, usize size) { buf->l2_size = size; }
inline_fn void mem_buf_set_l3 (mem_buf *buf, usize size) { buf->l3_size = size; }
inline_fn void mem_buf_set_l4 (mem_buf *buf, usize size) { buf->l4_size = size; }

inline_fn void *mem_buf_data   (mem_buf *buf) { return buf->data + buf->data_off; }
inline_fn void *mem_buf_buffer (mem_buf *buf) { return buf->data; }
inline_fn void *mem_buf_start  (mem_buf *buf) { return buf->data + buf->start_off; }

static inline void *
mem_buf_reserve_backwards (mem_buf *buf, usize size) 
{
    buf->start_off -= size; 
    buf->used      += size;
    return buf->data + buf->start_off;
}

inline_fn void *mem_buf_reserve_l2 (mem_buf *mbuf, usize size) { mem_buf_set_l2(mbuf, size); return mem_buf_reserve_backwards(mbuf, size); }
inline_fn void *mem_buf_reserve_l3 (mem_buf *mbuf, usize size) { mem_buf_set_l3(mbuf, size); return mem_buf_reserve_backwards(mbuf, size); }
inline_fn void *mem_buf_reserve_l4 (mem_buf *mbuf, usize size) { mem_buf_set_l4(mbuf, size); return mem_buf_reserve_backwards(mbuf, size); }

static inline void *mem_buf_get_at(mem_buf *buf, usize offset) { return buf->data + buf->start_off + offset; }
#define mem_buf_get_at_type(buf, offset, type)  ((type *)mem_buf_get_at((buf), (offset)))
#define mem_buf_l2(buf, type)                   mem_buf_get_at_type(buf, 0, type)
#define mem_buf_l3(buf, type)                   mem_buf_get_at_type(buf, buf->l2_size, type)
#define mem_buf_l4(buf, type)                   mem_buf_get_at_type(buf, buf->l2_size + buf->l3_size, type)

///////////////////////////////////////////////////////////////////////////////
// Functions

// --- IP Address

bool
string_to_ipv4(string s, u32 *out_ip)
{
    s = string_trim(s);

    u32 ip  = 0;
    usize i = 0, num_bytes = 0;
    while (i < s.len) {
        u32 byte          = 0;
        isize byte_length = 0;

        // Read digits of each segment (should be between 1-3 digits)
        while (i < s.len && s.data[i] != '.' && byte_length < 3) {
            if (!is_digit(s.data[i])) return false;

            byte = byte * 10 + (s.data[i] - '0');
            byte_length++;
            i++;
        }

        // Validate byte range (0-255)
        if (byte > 255) return false;

        // Shift the current value of ip left by 8 bits and add the new byte
        // the result is the new ip address in network byte order.
        //  e.g 0x12345678
        //   addr. 0x100 0x101 0x102 0x103
        //     BE:  0x12  0x34  0x56  0x78 <- Network Byte Order
        //     LE:  0x78  0x56  0x34  0x12
        ip = (ip << 8) | byte;
        num_bytes++;

        // If this isn't the last byte, expect a '.' delimiter
        if (i < s.len) {
            if (s.data[i] != '.') return false;
            i++; // Skip '.'
        }
    }

    if (num_bytes != 4) return false;

    *out_ip = net_to_host_u32(ip);
    return true;
}

bool
string_to_eth_addr(string s, eth_addr *out_addr)
{
    memory_zero_struct(out_addr);

    s = string_trim(s);
    usize i = 0, j = 0;
    while (i < s.len) {
        u32 byte = 0;
        isize byte_length = 0;
        while (i < s.len && s.data[i] != ':' && byte_length < 2) {
            if (!is_hex(s.data[i])) return false;
            byte = byte * 16 + (s.data[i] - '0');
            byte_length++;
            i++;
        }

        if (byte > 255) return false;

        if (i < s.len) {
            if (s.data[i] != ':') return false;
            i++;
        }

        out_addr->addr[j++] = byte;
    }

    return true;
}


// --- ARP Table

arp_entry *
arp_table_find(arp_table *table, u32 ip)
{
    arp_entry *entry = NULL;
    dllist_foreach(table, entry) {
        if (entry->ip == ip) return entry;
    }

    return NULL;
}

int
arp_table_insert(arp_table *table, u32 ip, eth_addr *addr, u8 state)
{
    arp_entry *entry = arp_table_find(table, ip);
    if (entry) return -1; // Already exists

    entry = arena_push_struct(table->arena, arp_entry);
    entry->ip    = ip;
    entry->addr  = *addr;
    entry->state = state;

    dllist_push(table, entry);
    table->count += 1;

    return 0;
}

arp_entry *
arp_table_update(arp_table *table, u32 ip, eth_addr *addr)
{
    arp_entry *entry = arp_table_find(table, ip);
    if (entry) {
        entry->addr  = *addr;
        entry->state = ARP_STATE_RESOLVED;
    }

    return entry;
}

void
print_arp_table(arp_table *table)
{
    arp_entry *n = NULL;
    printf("ARP Table (%ld)\n", table->count);
    printf("   %10s\t%20s\t%20s\n", "IP", "MAC", "State");
    if (table->count == 0) {
        printf("   %10s\t%20s\t%20s\n", "----", "----------------", "-----");
        return;
    } else {
        int i = 0;
        dllist_foreach(table, n) {
            char ip_str[16];
            ipv4_to_cstr(n->ip, ip_str);
            char mac_str[18];
            snprint_eth_addr(&n->addr, mac_str);
            printf("%d) %10s\t%20s\t%20s\n", ++i, ip_str, mac_str, s_arp_state_str[n->state]);
        }
    }
}

// --- Route Table
#define ROUTE_POOL_SIZE 64
static route_list s_route_pool;
static route_list s_route_table;

int
route_table_init(arena *arena, isize size)
{
    static bool route_initialized = false;
    if (route_initialized) return 0;

    dllist_init(&s_route_table, NULL);
    dllist_init(&s_route_pool, NULL);
    for (isize i = 0; i < size; i++) {
        route_entry *entry = arena_push_struct(arena, route_entry);
        dllist_push(&s_route_pool, entry);
    }
    route_initialized = true;
    return 0;
}

route_entry *
route_pool_alloc()
{
    route_entry *entry = s_route_pool.head;
    if (entry) route_list_remove(&s_route_pool, entry);
    return entry;
}

void
route_pool_free(route_entry *entry)
{
    dllist_push(&s_route_pool, entry);
}

int
route_table_add(string dst, string gateway, string netmask, u32 flags, u32 metric)
{
    route_entry *entry = route_pool_alloc(s_route_pool);
    if (!entry) return -1;

    memory_zero_struct(entry);
    string_to_ipv4(dst, &entry->destination);
    string_to_ipv4(gateway, &entry->gateway);
    string_to_ipv4(netmask, &entry->netmask);
    entry->flags  = flags;
    entry->metric = metric;
    // TODO(garbu): add the device index or pointer to the route entry.
    route_list_push(&s_route_table, entry);

    return 0;
}

route_entry *
route_table_lookup(u32 dst)
{
    route_entry *n = NULL;
    dllist_foreach(&s_route_table, n) {
        if ((dst & n->netmask) == (n->destination & n->netmask)) break;
    }

    return n;
}

void
print_route_table()
{
    route_entry *n = NULL;
    printf("Route Table\n");
    printf("%10s\t%10s\t%10s\t%10s\t%10s\n", "Destination", "Gateway", "Netmask", "Flags", "Metric");
    char dst_str[16], gw_str[16], nm_str[16];
    dllist_foreach(&s_route_table, n) {
        ipv4_to_cstr(n->destination, dst_str);
        ipv4_to_cstr(n->gateway, gw_str);
        ipv4_to_cstr(n->netmask, nm_str);
        printf("%10s\t%10s\t%10s\t%10s\t%10d\n",
            dst_str, gw_str, nm_str,
            n->flags == 1 ? "RT_HOST" : "RT_GATEWAY",
            n->metric
        );
    }
}

///////////////////////////////////////////////////////////////////////////////
// Global Variables
global_variable arena *g_arena;
global_variable bool g_running = true;

global_variable tcp_tcb_list g_tcb_list; 

global_variable u32 device_ip = 0;
global_variable eth_addr dev_eth_addr;

global_variable mem_buf rx_mbuf;
global_variable mem_buf tx_mbuf;
global_variable int nrecv = 0;
global_variable int ntx   = 0;

global_variable arp_table *g_arp_table;

global_variable bool g_tcp_server_running = false;

///////////////////////////////////////////////////////////////////////////////

void
signal_handler(int signum)
{
    printf("Signal: %d\n", signum);
    g_tcp_server_running = false;
    g_running            = false;
}

///////////////////////////////////////////////////////////////////////////////
// Temp Functions

int tcp_in    (mem_buf *mbuf);
int icmpv4_in (mem_buf *mbuf);
int ipv4_in   (mem_buf *mbuf);
int eth_in    (mem_buf *mbuf);

// --- output
int tcp_out  (mem_buf *mbuf);
int ipv4_out (mem_buf *mbuf, u32 sip, u32 dip);
int eth_out  (mem_buf *mbuf);

int
icmpv4_reply(mem_buf *mbuf, icmp4_hdr *icmp_req, usize len, u32 sip)
{
    mem_buf_set_l4(mbuf, sizeof(icmp4_hdr));
    icmp4_hdr *icmp = mem_buf_reserve_l4(mbuf, sizeof(icmp4_hdr));
    memory_copy(icmp, icmp_req, len); 
    icmp->type = ICMP_TYPE_ECHO_REPLY;
    icmp->csum = 0;
    icmp->csum = icmp4_csum(icmp, len);

    mbuf->used    += len - sizeof(icmp4_hdr);
    mbuf->l4_type  = IP_PROTO_ICMP;
    return ipv4_out(mbuf, device_ip, sip);
}

int 
icmpv4_in(mem_buf *mbuf)
{
    mem_buf_set_l4(mbuf, sizeof(icmp4_hdr));
    icmp4_hdr *icmp = mem_buf_l4(mbuf, icmp4_hdr); 
    switch (icmp->type) {
    case ICMP_TYPE_ECHO_REQUEST: {
        ip_hdr *ip   = mem_buf_l3(mbuf, ip_hdr);
        u16 icmp_len = ip->len - ipv4_header_len(ip);
        printf("ICMP Echo Request: %d bytes\n", icmp_len);
        return icmpv4_reply(&tx_mbuf, icmp, icmp_len, ip->src);
    } break;
    default: {
        // printf("Unknown ICMP type: %d\n", icmp_type);
    } break;
    }

    return 0;
}

// Create a TCP syn packet and send it out
//  - The TCB is updated with the new state and sequence numbers
int 
tcp_syn(mem_buf *mbuf, tcp_tcb *tcb)
{
    // check if tcb is in the correct state
    if (tcb->state != TCP_STATE_CLOSED) {
        printf("[TCP SYN] TCB not in CLOSED state\n");
        return -1;
    }

    tcp_hdr *tcp = mem_buf_reserve_l4(mbuf, sizeof(tcp_hdr));
    tcp->src_port    = tcb->local_port;
    tcp->dst_port    = tcb->remote_port;
    tcp->seq         = 100; // TODO(garbu): Randomize 
    tcp->ack_seq     = 0;
    tcp->data_offset = 5; // 20 bytes, no options
    tcp->csum        = 0;
    tcp->urg_ptr     = 0;
    tcp->window      = 64000; // TODO(garbu): use a better value
    tcp->flags       = 0;
    TCP_HDR_SET_FLAG(tcp, TCP_FLAG_SYN);

    // TOOD(garbu): Add options?

    tcp_header_host_to_net(tcp);

    u16 tcp_len = sizeof(tcp_hdr);
    tcp_ipv4_pseudo_hdr tcp_pseudo_hdr = {
        .src_ip = host_to_net_u32(device_ip), 
        .dst_ip = host_to_net_u32(tcb->remote_ip),
        .zero   = 0,
        .proto  = IP_PROTO_TCP,
        .len    = host_to_net_u16(tcp_len),
    };

    tcp->csum = tcp_csum(&tcp_pseudo_hdr, tcp, tcp_len);

    mbuf->l4_type  = IP_PROTO_TCP;
    return ipv4_out(mbuf, tcb->local_ip, tcb->remote_ip);
}

int
tcp_synack(mem_buf *mbuf, tcp_tcb *tcb)
{
    tcp_hdr *tcp = mem_buf_reserve_l4(mbuf, sizeof(tcp_hdr));
    tcp->src_port    = tcb->local_port;
    tcp->dst_port    = tcb->remote_port; 
    tcp->seq         = tcb->snd_nxt; 
    tcp->ack_seq     = tcb->rcv_nxt;
    tcp->data_offset = 5; // 20 bytes, no options
    tcp->csum        = 0;
    tcp->urg_ptr     = 0;
    tcp->window      = tcb->recv_window;
    tcp->flags       = 0;
    TCP_HDR_SET_FLAG(tcp, TCP_FLAG_SYN | TCP_FLAG_ACK);

    // TOOD(garbu): Add options?

    // TODO(garbu): Debug
    printf("[TCP OUT] "); 
    print_tcp_hdr(tcp);

    tcp_header_host_to_net(tcp);

    u16 tcp_len = sizeof(tcp_hdr);
    tcp_ipv4_pseudo_hdr tcp_pseudo_hdr = {
        .src_ip = host_to_net_u32(device_ip), 
        .dst_ip = host_to_net_u32(tcb->remote_ip),
        .zero   = 0,
        .proto  = IP_PROTO_TCP,
        .len    = host_to_net_u16(tcp_len),
    };

    tcp->csum = tcp_csum(&tcp_pseudo_hdr, tcp, tcp_len);

    mbuf->l4_type  = IP_PROTO_TCP;
    return ipv4_out(mbuf, device_ip, tcb->remote_ip); 
}

int
tcp_finack(mem_buf *mbuf, tcp_tcb *tcb)
{
    tcp_hdr *tcp = mem_buf_reserve_l4(mbuf, sizeof(tcp_hdr));
    tcp->src_port    = tcb->local_port;
    tcp->dst_port    = tcb->remote_port;
    tcp->seq         = tcb->snd_nxt;
    tcp->ack_seq     = tcb->rcv_nxt;
    tcp->data_offset = 5; // 20 bytes, no options
    tcp->csum        = 0;
    tcp->urg_ptr     = 0;
    tcp->window      = tcb->recv_window;
    tcp->flags       = 0;
    TCP_HDR_SET_FLAG(tcp, TCP_FLAG_FIN | TCP_FLAG_ACK);

    // TOOD(garbu): Add options?

    // TODO(garbu): Debug
    printf("[TCP OUT] ");
    print_tcp_hdr(tcp);

    tcp_header_host_to_net(tcp);

    u16 tcp_len = sizeof(tcp_hdr);
    tcp_ipv4_pseudo_hdr tcp_pseudo_hdr = {
        .src_ip = host_to_net_u32(device_ip), 
        .dst_ip = host_to_net_u32(tcb->remote_ip),
        .zero   = 0,
        .proto  = IP_PROTO_TCP,
        .len    = host_to_net_u16(tcp_len),
    };

    tcp->csum = tcp_csum(&tcp_pseudo_hdr, tcp, tcp_len);

    mbuf->l4_type  = IP_PROTO_TCP;
    return ipv4_out(mbuf, device_ip, tcb->remote_ip);
}

int 
tcp_in(mem_buf *mbuf)
{
    ip_hdr *ip   = mem_buf_l3(mbuf, ip_hdr);
    tcp_hdr *tcp = mem_buf_l4(mbuf, tcp_hdr);
    u16 tcp_len  = tcp->data_offset * 4; 

    tcp_ipv4_pseudo_hdr tcp_pseudo_hdr = {
        .src_ip = host_to_net_u32(ip->src),
        .dst_ip = host_to_net_u32(ip->dst),
        .zero   = 0,
        .proto  = IP_PROTO_TCP,
        .len    = host_to_net_u16(tcp_len),
    };

    u16 csum = tcp_csum(&tcp_pseudo_hdr, tcp, tcp_len);
    if (csum != 0) {
        printf("[TCP IN] Checksum failed\n");
        return -1;
    }

    tcp_header_net_to_host(tcp);
    printf("[TCP IN] ");
    print_tcp_hdr(tcp);

    tcp_tcb *tcb = tcp_tcb_list_find_local_peer(&g_tcb_list, ip->dst, tcp->dst_port);
    if (!tcb) {
        printf("[TCP IN] No TCB found for port: %d\n", tcp->dst_port);
        return -1;
    }

    switch (tcb->state) {
    case TCP_STATE_LISTEN: {
        printf("[TCP IN] LISTEN state\n");
        if (TCP_HDR_IS_FLAG(tcp, TCP_FLAG_SYN)) {
            // First update the TCB
            tcb->state       = TCP_STATE_SYN_RECEIVED;
            tcb->snd_una     = 100;
            tcb->snd_nxt     = 101;
            tcb->snd_wnd     = tcp->window;
            tcb->remote_port = tcp->src_port;
            tcb->remote_ip   = ip->src;
            tcb->rcv_nxt     = tcp->seq + 1; 
            tcb->recv_window = tcp->window;
            tcb->irs         = tcp->seq;
            tcb->iss         = 100;
            tcb->send_window = tcp->window; 
            tcb->seg_seq     = tcp->seq;
            tcb->seg_ack     = tcp->ack_seq;
            tcb->seg_len     = tcp_len;
            tcb->seg_wnd     = tcp->window;

            printf("[TCP IN] SYN, sending SYN-ACK\n");
            tcp_synack(&tx_mbuf, tcb);
        }
    } break;
    case TCP_STATE_SYN_RECEIVED: {
        printf("[TCP]: SYN_RECEIVED state\n");
        if (!TCP_HDR_IS_FLAG(tcp, TCP_FLAG_ACK)) {
            printf("[TCP]: Received non-ACK packet (%s) in SYN_RECEIVED state, go back to LISTEN\n", s_tcp_flag_str[tcp->flags]);
            tcb->state = TCP_STATE_LISTEN;
            break;
        }

        // TODO(garbu): Check the ACK number, and complete the handshake

        tcb->state = TCP_STATE_ESTABLISHED;
        printf("[TCP]: Connection established\n");
    } break;
    case TCP_STATE_ESTABLISHED: {
        printf("[TCP]: ESTABLISHED state\n");
        if (TCP_HDR_IS_FLAG(tcp, TCP_FLAG_FIN)) {
            printf("[TCP]: FIN received, sending FIN-ACK\n");
            tcb->state = TCP_STATE_CLOSE_WAIT;

            // Send FIN-ACK
            tcp_finack(&tx_mbuf, tcb);
        }
    } break;
    case TCP_STATE_CLOSE_WAIT: {
        printf("[TCP]: CLOSE_WAIT state\n");
        if (TCP_HDR_IS_FLAG(tcp, TCP_FLAG_FIN)) {
            printf("[TCP]: FIN received, sending ACK\n");
            tcb->state = TCP_STATE_LAST_ACK;
            // Send ACK
        }
    } break;
    case TCP_STATE_LAST_ACK: {
        printf("[TCP]: LAST_ACK state\n");
        if (TCP_HDR_IS_FLAG(tcp, TCP_FLAG_ACK)) {
            printf("[TCP]: ACK received, closing connection\n");
            tcb->state = TCP_STATE_CLOSED;
        }
    } break;
    case TCP_STATE_FIN_WAIT_1: {
        printf("[TCP]: FIN_WAIT_1 state\n");
        if (TCP_HDR_IS_FLAG(tcp, TCP_FLAG_FIN)) {
            printf("[TCP]: FIN received, sending ACK\n");
            tcb->state = TCP_STATE_CLOSING;
            // Send ACK
        }
    } break;
    case TCP_STATE_FIN_WAIT_2: {
        printf("[TCP]: FIN_WAIT_2 state\n");
        if (TCP_HDR_IS_FLAG(tcp, TCP_FLAG_FIN)) {
            printf("[TCP]: FIN received, sending ACK\n");
            tcb->state = TCP_STATE_TIME_WAIT;
            // Send ACK
        }
    } break;
    case TCP_STATE_CLOSING: {
        printf("[TCP]: CLOSING state\n");
        if (TCP_HDR_IS_FLAG(tcp, TCP_FLAG_ACK)) {
            printf("[TCP]: ACK received, closing connection\n");
            tcb->state = TCP_STATE_CLOSED;
        }
    } break;
    default: {
        printf("[TCP IN] Unknown state\n");
        break;
    }
    }

    return 0;
}

int
ipv4_in(mem_buf *mbuf)
{
    ip_hdr *ip = mem_buf_l3(mbuf, ip_hdr);

    if (ipv4_csum(ip) != 0) {
        printf("IP checksum failed\n");
        return -1;
    }

    // Transform the header to host byte order
    ipv4_header_net_to_host(ip);

    if (ip->ttl == 0) {
        printf("IP TTL expired\n");
        return -1;
    }

    mem_buf_set_l3(mbuf, ipv4_header_len(ip)); 

    switch (ip->proto) {
        case IP_PROTO_ICMP: icmpv4_in(mbuf); break;
        case IP_PROTO_TCP:  tcp_in(mbuf);    break;
        default: {
            printf("Unknown IP protocol: %d\n", ip->proto);
        } break;
    }

    return 0;
}

int 
ipv4_out(mem_buf *mbuf, u32 sip, u32 dip)
{
    // TODO: Route the packet
    // - Check the route table for the destination IP address
    ip_hdr *ip = mem_buf_reserve_l3(mbuf, IPV4_HDR_LEN_MIN); 

    ip->ihl      = IPV4_HDR_LEN_MIN / 4;

    ip->ver      = IP_VERSION_4;
    ip->tos      = 0x00;
    printf("[IP OUT] payload len: %ld\n", mbuf->used);
    ip->len      = mbuf->used;
    ip->id       = 0;
    ip->frag_off = 0;
    ip->ttl      = 64;
    ip->proto    = mbuf->l4_type;
    ip->src      = sip;
    ip->dst      = dip; // TODO: Check if this is correct
    ip->csum     = 0;
    IP_SET_DF(ip);

    printf("[IP OUT] ");
    print_ipv4_hdr(ip);

    ipv4_header_host_to_net(ip);

    // checksum
    ip->csum = ipv4_csum(ip);

    // TODO: ARP resolution

    mbuf->l3_type = ETH_PTYPE_IPV4;
    return eth_out(mbuf);
}

int 
arp_reply(mem_buf *mbuf, arp_ipv4 *arp_req)
{
    arp_ipv4 *arp = mem_buf_reserve_l3(mbuf, sizeof(arp_ipv4));
    arp->hdr.hw_type        = ARP_HW_TYPE_ETHERNET;
    arp->hdr.proto_type     = ARP_PROTO_IPV4;
    arp->hdr.hw_addr_len    = ETH_ADDR_LEN;
    arp->hdr.proto_addr_len = IPV4_ADDR_LEN;
    arp->hdr.op             = ARP_OP_REPLY;
    arp->src_ip             = arp_req->dst_ip;
    arp->dst_ip             = arp_req->src_ip;
    memory_copy(arp->src_hw, dev_eth_addr.addr, ETH_ADDR_LEN);
    memory_copy(arp->dst_hw, arp_req->src_hw, ETH_ADDR_LEN);

    arp_ipv4_host_to_net(arp);

    mbuf->l3_type = ETH_PTYPE_ARP;
    return eth_out(mbuf);
}

int
arp_in(mem_buf *mbuf)
{
    mem_buf_set_l3(mbuf, sizeof(arp_hdr));
    arp_hdr *arp = mem_buf_l3(mbuf, arp_hdr);

    arp_header_net_to_host(arp);

    if (arp->hw_type != ARP_HW_TYPE_ETHERNET) {
        printf("ARP: Unknown hardware type: %d\n", arp->hw_type);
        return -1;
    }

    if (arp->proto_type != ARP_PROTO_IPV4) {
        printf("ARP: Unknown protocol type: %d\n", arp->proto_type);
        return -1;
    }

    arp_header_host_to_net(arp);
    arp_ipv4 *arp4 = (arp_ipv4 *)arp;
    arp_ipv4_net_to_host(arp4);

    // NOTE(garbu): Debug
    char src_ip[16], dst_ip[16];
    ipv4_to_cstr(arp4->src_ip, src_ip);
    ipv4_to_cstr(arp4->dst_ip, dst_ip);
    printf("ARP: %s -> %s\n", src_ip, dst_ip);

    arp_table_insert(g_arp_table, arp4->src_ip, (eth_addr *)arp4->src_hw, ARP_STATE_RESOLVED);

    if (arp4->dst_ip != device_ip) {
        printf("ARP: Packet not for device\n");
        return -1;
    }

    switch (arp->op) {
    case ARP_OP_REQUEST: {
        arp_reply(&tx_mbuf, arp4);
    } break;
    case ARP_OP_REPLY: {
        // TODO(garbu): Update the ARP table
    } break;
    default: {
        // printf("Unknown ARP operation: %d\n", arp_op);
    } break;
    }

    print_arp_table(g_arp_table);

    return 0;
}

int
eth_in(mem_buf *mbuf)
{
    eth_hdr *ether = mem_buf_l2(mbuf, eth_hdr);
    ether->type    = net_to_host_u16(ether->type);
    // printf("[ETH IN] ");
    // print_eth_hdr(ether);
    mem_buf_set_l2(mbuf, sizeof(eth_hdr)); 

    switch (ether->type) {
        case ETH_PTYPE_IPV4: {
            return ipv4_in(mbuf);
        }
        case ETH_PTYPE_ARP: {
            return arp_in(mbuf);
        } break;
        default: {
            // printf("Unknown eth type: 0x%04x\n", ether->type);
        } break;
    }

    return 0;
}

int 
eth_out(mem_buf *mbuf)
{
    eth_hdr *ether = mem_buf_reserve_l2(mbuf, sizeof(eth_hdr));
    memory_copy(&ether->src, dev_eth_addr.addr, ETH_ADDR_LEN);
    memory_copy(&ether->dst, g_arp_table->head->addr.addr, ETH_ADDR_LEN);
    ether->type = mbuf->l3_type;

    printf("[ETH OUT] ");
    print_eth_hdr(ether);

    ether->type = host_to_net_u16(ether->type);

    // TODO(garbu): do a real send
    ntx = 1;

    return 0;
}

void
print_hex_dump(void *data, usize len)
{
    u8 *ptr = (u8 *)data;
    for (usize i = 0; i < len; i++) {
        printf("%02x ", ptr[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}

///////////////////////////////////////////////////////////////////////////////
// Test Thread
//  - This thread will simulate an application opening a TCP connection
//    as a server and sending a response to a client.

// The open_connection function will simulate a client opening a connection
int
open_connection(string local_ip, u32 local_port, string remote_ip, u32 remote_port) 
{
    u32 sip, dip;
    string_to_ipv4(local_ip, &sip);
    string_to_ipv4(remote_ip, &dip);

    // Check if local port is already in use
    // tcp_tcb *tcb = tcp_tcb_list_find(&g_tcb_list, 
    // if (tcb) {
    //     printf("[TCP Client] Connection already open\n");
    //     return -1;
    // }

    // tcb = arena_push_struct(g_arena, tcp_tcb);
    // tcb->state       = TCP_STATE_CLOSED;
    // tcb->local_ip    = sip;
    // tcb->local_port  = local_port;
    // tcb->remote_ip   = dip;
    // tcb->remote_port = remote_port;
    // tcb->passive     = false;
    // tcp_tcb_list_push(&g_tcb_list, tcb);

    return 0;
}

// The create_connection function will simulate a server opening a connection
int 
create_connection(string local_ip, u16 local_port)
{
    u32 ip;
    string_to_ipv4(local_ip, &ip);

    tcp_tcb *tcb = tcp_tcb_list_find_local_peer(&g_tcb_list, ip, local_port);
    if (tcb) {
        printf("[TCP Server] Connection already open\n");
        return -1;
    }

    tcb = arena_push_struct(g_arena, tcp_tcb);
    tcb->state      = TCP_STATE_LISTEN;
    tcb->local_ip   = ip; 
    tcb->local_port = local_port; 
    tcb->passive    = true;
    tcp_tcb_list_push(&g_tcb_list, tcb);

    print_tcp_tcb_list(&g_tcb_list);

    return 0;
}

void *
tcp_server_thread(void *arg)
{
    UNUSED(arg);
    printf("[TCP Server Thread] waiting for start\n");

    while (!g_tcp_server_running)   usleep(10000);

    printf("[TCP Server Thread] opening connection\n"); 

    // Open a connection
    create_connection(from_cstr(DEVICE_ADDRESS), 9999);

    while (g_tcp_server_running) {
    }
}

///////////////////////////////////////////////////////////////////////////////
// Entry Point
int
main(int argc, char *argv[])
{
    UNUSED(argc);
    UNUSED(argv);
#if 0
    string ip_str = str_lit("128.0.0.1");
    u32 ip = 0;
    bool res = string_to_ipv4(ip_str, &ip);
    u32 ip_control = inet_addr(to_cstr(ip_str));
    printf("%d -> %d\n", ip, ip_control);

    char ip_cstr[16];
    ipv4_to_cstr(ip, ip_cstr);
    printf("%s\n", ip_cstr);

    printf("sizeof(hdr): %ld\n", sizeof(ip_hdr));
#else
    ////////////////////////////////////////
    // Initialize
    printf("Welcome to uTCP: a minimal TCP/IP stack\n");
    signal(SIGINT, signal_handler);

    g_arena = arena_vm_alloc(.reserve_size=GB(1));
    arena *main_arena    = arena_vm_alloc();

    g_arp_table = arp_table_alloc();
    print_arp_table(g_arp_table);

    ////////////////////////////////////////

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(sockfd != -1 && "Failed to create socket");

    int fd = open(TUN_PATH, O_RDWR);
    assert(fd != -1 && "Failed to open TUN device");

    {
        // NOTE(garbu)
        // Set the interface flags for a TAP device.
        //
        // IFF_TAP:   This flag indicates that the interface is a TAP device,
        //            which operates at the Ethernet layer (Layer 2).
        // IFF_NO_PI: This flag indicates that no packet information will be
        //            provided with the packets read from the device.
        //
        struct ifreq ifr;
        memory_zero_struct(&ifr);
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        cstring_copy(ifr.ifr_name, TUN_NAME, IFNAMSIZ);
        if(ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
            perror("ioctl(TUNSETIFF)");
            goto exit_cleanup;
        }

        if(ioctl(sockfd, SIOCGIFINDEX, (void *)&ifr) < 0) {
            perror("ioctl(SIOCGIFINDEX)");
            goto exit_cleanup;
        }

        int ifindex = ifr.ifr_ifindex;
        printf("TUN device index: %d\n", ifindex);

        ifr.ifr_flags = IFF_UP | IFF_RUNNING;
        if (ioctl(sockfd, SIOCSIFFLAGS, (void *)&ifr) < 0) {
            perror("ioctl(SIOCSIFFLAGS)");
            goto exit_cleanup;
        }
    }

    char gtwaddr_str[16]; memory_zero_array(gtwaddr_str);
    u8 devaddr_bytes[4];  memory_zero_array(devaddr_bytes);
    {
        string devaddr = from_cstr(DEVICE_ADDRESS);
        string_to_ipv4(devaddr, &device_ip);
        string_to_eth_addr(from_cstr(NETDEV1_HWADDR), &dev_eth_addr);

        // Parse the device address
        temp_arena tmp_arena = temp_arena_begin(main_arena);
        {
            char delims[] = {'.'};
            string_list devaddr_parts = string_split(tmp_arena.arena, devaddr, delims, array_count(delims));
            if (devaddr_parts.count != 4) {
                printf("Invalid device address\n");
                goto exit_cleanup;
            }

            int i = 0;
            string_node *n;
            string_list_foreach(&devaddr_parts, n) {
                devaddr_bytes[i++] = u8_from_str(n->s);
            }
        }
        temp_arena_end(tmp_arena);

        // NOTE(garbu): Set the physical device address
        // This is different from the IP address of the logical device, which will
        // be used to simulate the network stack.
        // The physical device instead is simulating a real network device, e.g a router
        // and it works as a gateway for the logical device.
        char network_str[16]; memory_zero_array(network_str);
        snprintf(gtwaddr_str, sizeof(gtwaddr_str), "%d.%d.%d.1", devaddr_bytes[0], devaddr_bytes[1], devaddr_bytes[2]);
        snprintf(network_str, sizeof(network_str), "%d.%d.%d.0", devaddr_bytes[0], devaddr_bytes[1], devaddr_bytes[2]);

        struct sockaddr_in saddr;
        memory_zero_struct(&saddr);
        saddr.sin_family      = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(gtwaddr_str);

        struct ifreq ifr;
        memory_zero_struct(&ifr);
        memory_copy(ifr.ifr_name, TUN_NAME, IFNAMSIZ);
        memory_copy(&ifr.ifr_addr, &saddr, sizeof(saddr));

        if (ioctl(sockfd, SIOCSIFADDR, (void *)&ifr) < 0) {
            perror("ioctl(SIOCSIFADDR)");
            goto exit_cleanup;
        }

        const char *netmask = "255.255.255.0";

        memory_zero_struct(&saddr);
        saddr.sin_family      = AF_INET;
        saddr.sin_addr.s_addr = inet_addr(netmask);

        memory_copy(&ifr.ifr_addr, &saddr, sizeof(saddr));
        memory_copy(ifr.ifr_name, TUN_NAME, IFNAMSIZ);

        if (ioctl(sockfd, SIOCSIFNETMASK, (void *)&ifr) < 0) {
            perror("ioctl(SIOCSIFNETMASK)");
            goto exit_cleanup;
        }

        // TODO(garbu): Add the route to the network using the syscalls
        char cmdbuf[256];
        snprintf(cmdbuf, sizeof(cmdbuf), "ip route add %s %s/24", TUN_NAME, network_str);
    }

    ////////////////////////////////////////
    // Default Routes
    {
#define RT_HOST     0x1
#define RT_GATEWAY  0x2
        string ip_zero = str_lit("0.0.0.0");
        route_table_init(main_arena, ROUTE_POOL_SIZE);
        int res = route_table_add(from_cstr(DEVICE_ADDRESS), ip_zero, str_lit("255.255.255.0"), RT_HOST, 0);
        assert(res == 0 && "Failed to add default route");

        // -- Add gateway route
        res = route_table_add(ip_zero, from_cstr(gtwaddr_str), ip_zero, RT_GATEWAY, 0);

        printf("\n");
        print_route_table();
    }

    ////////////////////////////////////////
    // Spawn the TCP Server Thread
    {
        pthread_t tcp_thread;
        int res = pthread_create(&tcp_thread, NULL, tcp_server_thread, NULL);
        if (res != 0) {
            perror("pthread_create");
            goto exit_cleanup;
        }

        g_tcp_server_running = true;
    }

    ////////////////////////////////////////
    // Network Stack data
#define MBUF_LEN    2048
#define HEADROOM    (ETH_HDR_LEN + IPV4_HDR_LEN_MAX + TCP_HDR_LEN_MAX)
    byte *rx_mbuf_data = arena_push(main_arena, MBUF_LEN);
    byte *tx_mbuf_data = arena_push(main_arena, MBUF_LEN); 
    rx_mbuf            = mem_buf_init(rx_mbuf_data, MBUF_LEN, HEADROOM);
    tx_mbuf            = mem_buf_init(tx_mbuf_data, MBUF_LEN, HEADROOM);
 
    ////////////////////////////////////////
    // Device Loop
    {
        while (g_running) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(fd, &readfds);

            struct timeval tv;
            tv.tv_sec  = 0;
            tv.tv_usec = 10000;

            int ret = select(fd + 1, &readfds, NULL, NULL, &tv);
            if (ret < 0) {
                perror("Select");
                break;
            }

            ////////////////////////////////////////
            // Read from TUN device
            nrecv = 0;
            {
                if (ret == 0) goto dev_do_tx; // Timeout

                if (FD_ISSET(fd, &readfds)) {
                    mem_buf_clear(&rx_mbuf);
                    rx_mbuf.used = read(fd, mem_buf_buffer(&rx_mbuf), rx_mbuf.len); 
                    if (rx_mbuf.used < 0) {
                        perror("Reading from TUN device");
                        break;
                    }
                    rx_mbuf.start_off = 0;   
                    mem_buf_set_l2(&rx_mbuf, ETH_HDR_LEN);
                    nrecv = 1;
                }
            }
            ////////////////////////////////////////

            ////////////////////////////////////////
            // Network Stack
            {
                if (nrecv) {
                    eth_in(&rx_mbuf);
                }
            }
            ////////////////////////////////////////

            ////////////////////////////////////////
            // Write to TUN device
dev_do_tx:
            {
                if (ntx) {
                    // print_hex_dump(mem_buf_start(&tx_mbuf), tx_mbuf.used);
                    isize len = write(fd, mem_buf_start(&tx_mbuf), tx_mbuf.used); 
                    if (len < 0) {
                        perror("Writing to TUN device");
                        break;
                    }

                    mem_buf_clear(&tx_mbuf);
                    ntx = 0;
                }
            }
            ////////////////////////////////////////
        }
    }

exit_cleanup:
    fflush(stdout);
    close(fd);
    close(sockfd);
#endif

    return 0;
}