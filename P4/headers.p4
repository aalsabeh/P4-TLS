/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

typedef bit<8> ip_protocol_t;

const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

#define COMPRESSION_STATE 0x0
#define EXTENSION_STATE 0x1
#define SESSION_LEN 0x1
#define COMP_LEN 0x2
#define CIPHER_LIM 0x3
#define EXT_LIM 0x4
#define SNI_LEN 0x5

typedef bit<8>  pkt_type_t;
// const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR_syn_counter = 1;

#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif
const mirror_type_t MIRROR_TYPE_I2E = 1;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header mirror_bridged_metadata_h {
    pkt_type_t pkt_type;
    @flexible bit<1> do_egr_mirroring;  //  Enable egress mirroring
    @flexible MirrorId_t egr_mir_ses;   // Egress mirror session ID
}

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header options_h {
    varbit<320> options;
}
header fixed_options_h {
    bit<96> options;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header tls_h { 
    bit<8> type;
    bit<16> version;
    bit<16> len;
}

header tls_hello_h {
    bit<8> type;
    bit<24> len;
    bit<16> version;
    bit<256> random;
}

header tls_session_h {
    bit<8> len;
}

header tls_cipher_h {
    bit<16> len;
    // In Client: ciphers follow
}
header tls_compression_h {
    bit<8> len;
    //  In Client: compressions follow
}
header tls_exts_len_h {
    bit<16> len;
}
header tls_ext_h {
    bit<16> type;
    bit<16> len;
}
header ctls_ext_sni_h {
    bit<16> sni_list_len;
    bit<8> type;
    bit<16> sni_len;
}
header hostname_part1 {
    bit<8> part;
}
header hostname_part2 {
    bit<16> part;
}
header hostname_part4 {
    bit<32> part;
}
header hostname_part8 {
    bit<64> part;
}
header hostname_part16 {
    bit<128> part;
}

header tls_continue_h { 
    bit<16> id;
}
/***********************  I N G R E S S  H E A D E R S  ************************/
struct my_ingress_headers_t {
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    udp_h        udp;
    tcp_h        tcp;
    tls_h        tls;
    
    // TLS Hello
    tls_hello_h tls_handshake;

    // Client Hello
    tls_session_h hello_session;
    tls_cipher_h hello_ciphers;
    tls_compression_h compressions;
    tls_exts_len_h extensions_len;
    tls_ext_h extensions;
    ctls_ext_sni_h client_servername;
    hostname_part1 servername_part1;
    hostname_part2 servername_part2;
    hostname_part4 servername_part4;
    hostname_part8 servername_part8;
    hostname_part16 servername_part16;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
struct my_ingress_metadata_t {
    bit<8> unparsed;
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
}

/***********************  E G R E S S  H E A D E R S  ***************************/

struct my_egress_headers_t {
}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}
