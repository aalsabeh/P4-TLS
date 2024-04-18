
/***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    ParserCounter() counter;

    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;

        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }
    
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select(hdr.tcp.data_offset) {
            0x5 : parse_tcp_after_options;
            // Note, could not parse a variable options field due to parser TCAM, so restricted it with the most common options lengths in TLS 
            0x8: parse_tcp_options8; 
            default: accept;
        }
    }
    state parse_tcp_options8 {
        pkt.advance(96);
        transition parse_tcp_after_options;
    }

    // state parse_tcp_options {
    //     pkt.extract(hdr.tcp_options, ((bit<32>)hdr.tcp.data_offset -5) * 32);
    //     // transition parse_tcp_after_options;
    //     transition accept;
    // }
    state parse_tcp_after_options {
        transition select(hdr.tcp.dst_port) {
            443: parse_tls;
            default: accept;
        }
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    state parse_tls {
        pkt.extract(hdr.tls);
        transition select(hdr.tls.type) {
            0x16: parse_tls_handshake;
            default: accept;
        }  
    }
    
    // /*
    state parse_tls_handshake {
        pkt.extract(hdr.tls_handshake);
        transition select(hdr.tls_handshake.type) {
            0x01: parse_session_ids;
            0x02: parse_session_ids;
            default: accept;
        }
    }

    
    state parse_session_ids {
        pkt.extract(hdr.hello_session);
        transition select(hdr.hello_session.len) {  
            0x00: hello_cipher;
            0x01: session_id1;
            0x02:  session_id2;
            0x03:  session_id3;
            0x04:  session_id4;
            0x05:  session_id5;
            0x06:  session_id6;
            0x07:  session_id7;
            0x08:  session_id8;
            0x09:  session_id9;
            0x0a:  session_id10;
            0x0b:  session_id11;
            0x0c:  session_id12;
            0x0d:  session_id13;
            0x0e:  session_id14;
            0x0f:  session_id15;
            0x10:  session_id16;
            0x11:  session_id17;
            0x12:  session_id18;
            0x13:  session_id19;
            0x14:  session_id20;
            0x15:  session_id21;
            0x16:  session_id22;
            0x17:  session_id23;
            0x18:  session_id24;
            0x19:  session_id25;
            0x1a:  session_id26;
            0x1b:  session_id27;
            0x1c:  session_id28;
            0x1d:  session_id29;
            0x1e:  session_id30;
            0x1f:  session_id31;
            0x20:  session_id32;
            default: unparsed_session;
        }
    }

    state unparsed_session {
        meta.unparsed = SESSION_LEN;
        transition accept;
    }
    state session_id1 {
        pkt.advance(8);
        transition hello_cipher;
    }
    state session_id2 {
        pkt.advance(16); 
        transition hello_cipher;
    }
    state session_id3 {
        pkt.advance(24); 
        transition hello_cipher;
    }
    state session_id4 {
        pkt.advance(32); 
        transition hello_cipher;
    }
    state session_id5 {
        pkt.advance(40); 
        transition hello_cipher;
    }
    state session_id6 {
        pkt.advance(48); 
        transition hello_cipher;
    }
    state session_id7 {
        pkt.advance(56); 
        transition hello_cipher;
    }
    state session_id8 {
        pkt.advance(64); 
        transition hello_cipher;
    }
    state session_id9 {
        pkt.advance(72); 
        transition hello_cipher;
    }
    state session_id10 {
        pkt.advance(80); 
        transition hello_cipher;
    }
    state session_id11 {
        pkt.advance(88); 
        transition hello_cipher;
    }
    state session_id12 {
        pkt.advance(96); 
        transition hello_cipher;
    }
    state session_id13 {
        pkt.advance(104); 
        transition hello_cipher;
    }
    state session_id14 {
        pkt.advance(112); 
        transition hello_cipher;
    }
    state session_id15 {
        pkt.advance(120); 
        transition hello_cipher;
    }
    state session_id16 {
        pkt.advance(128); 
        transition hello_cipher;
    }
    state session_id17 {
        pkt.advance(136); 
        transition hello_cipher;
    }
    state session_id18 {
        pkt.advance(144); 
    }
    state session_id19 {
        pkt.advance(152); 
        transition hello_cipher;
    }
    state session_id20 {
        pkt.advance(160); 
        transition hello_cipher;
    }
    state session_id21 {
        pkt.advance(168); transition hello_cipher; 
    }
    state session_id22 {
        pkt.advance(176); transition hello_cipher; 
    }
    state session_id23 {
        pkt.advance(184); transition hello_cipher; 
    }
    state session_id24 {
        pkt.advance(192); transition hello_cipher; 
    }
    state session_id25 {
        pkt.advance(200); transition hello_cipher; 
    }
    state session_id26 {
        pkt.advance(208); transition hello_cipher; 
    }
    state session_id27 {
        pkt.advance(216); transition hello_cipher; 
    }
    state session_id28 {
        pkt.advance(224); transition hello_cipher; 
    }
    state session_id29 {
        pkt.advance(232); transition hello_cipher; 
    }
    state session_id30 {
        pkt.advance(240); transition hello_cipher; 
    }
    state session_id31 {
        pkt.advance(248); transition hello_cipher; 
    }
    state session_id32 {
        pkt.advance(256); transition hello_cipher; 
    }
    
    state hello_cipher {
        pkt.extract(hdr.hello_ciphers);
        transition select(hdr.hello_ciphers.len) {
            // This will always be even, since the each cipher is 2 byte 
            0x0002: c2;
            0x0004: c4;
            0x0006: c6;
            0x0008: c8;
            0x000a: c10;
            0x000c: c12;
            0x000e: c14;
            0x0010: c16;
            0x0012: c18;
            0x0014: c20;
            0x0016: c22;
            0x0018: c24;
            0x001a: c26;
            0x001c: c28;
            0x001e: c30;
            0x0020: c32;
            0x0022: c34;
            0x0024: c36;
            0x0026: c38;
            0x0028: c40;
            0x0038: c56;
            0x003e: c62;
            default: unparsed_cipher;
            // default: cipher_loop;
        }
    }
    
    state unparsed_cipher {
        meta.unparsed = CIPHER_LIM;
        transition accept;
    }
    state c2 {
        pkt.advance(16); 
        transition parse_compressions;
    }
    state c4 {
        pkt.advance(32); 
        transition parse_compressions;
    }
    state c6 {
        pkt.advance(48); 
        transition parse_compressions;
    }
    state c8 {
        pkt.advance(64); 
        transition parse_compressions;
    }
    state c10 {
        pkt.advance(80); 
        transition parse_compressions;
    }
    state c12 {
        pkt.advance(96); 
        transition parse_compressions;
    }
    state c14 {
        pkt.advance(112); 
        transition parse_compressions;
    }
    state c16 {
        pkt.advance(128); 
        transition parse_compressions;
    }
    state c18 {
        pkt.advance(144); 
    }
    state c20 {
        pkt.advance(160); 
        transition parse_compressions;
    }
    state c22 {
        pkt.advance(176); transition parse_compressions; 
    }
    state c24 {
        pkt.advance(192); transition parse_compressions; 
    }
    state c26 {
        pkt.advance(208); transition parse_compressions; 
    }
    state c28 {
        pkt.advance(224); transition parse_compressions; 
    }
    state c30 {
        pkt.advance(240); transition parse_compressions; 
    }
    state c32 {
        pkt.advance(256); transition parse_compressions; 
    }
    state c34 {
        pkt.advance(272); transition parse_compressions; 
    }
    state c36 {
        pkt.advance(288); transition parse_compressions; 
    }
    state c38 {
        pkt.advance(304); transition parse_compressions; 
    }
    state c40 {
        pkt.advance(320); transition parse_compressions; 
    }
    state c56 {
        counter.set((bit<8>)0x38); transition cipher_loop;
    }
    state c62 {
        counter.set((bit<8>)0x3e); transition cipher_loop;
    }
    state cipher_loop {
        pkt.advance(16);
        counter.decrement(8w2);
        transition select(counter.is_zero()) {
            true: parse_compressions;
            false: cipher_loop;
        }
    }


    state parse_compressions {
        pkt.extract(hdr.compressions);
        transition select (hdr.compressions.len) {
            0x01: c1_;
            default: unparsed_compression;
        }
    }

    state unparsed_compression {
        meta.unparsed = COMP_LEN;
        transition accept;
    }
    state c1_ {
        pkt.advance(8);
        transition parse_extensions_len;
    }

    state parse_extensions_len {
        pkt.extract(hdr.extensions_len);
        transition select(hdr.extensions_len.len) {
            0: accept;
            default: parse_extensions;
        }
    }
    state parse_extensions {
        
        // pkt.extract(hdr.extensions);
        // transition select(hdr.extensions.type) {
        //     0x0000: parse_server_name;
        //     default: parse_skipped_extension_len;
        // }
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[31:16]) {
            0x0000: parse_server_name;
            default: parse_skipped_extension_len;
        }
    }

    state parse_skipped_extension_len {
        bit<32> extension = pkt.lookahead<bit<32>>();
        transition select(extension[15:0]) {
        // transition select(hdr.extensions.len) {
            0x00: c0__; 
            0x01: c1__;
            0x02: c2__;
            0x03: c3__;
            0x04: c4__;
            0x05: c5__;
            0x06: c6__;
            0x07: c7__;
            0x08: c8__;
            0x09: c9__;
            0x0a: c10__;
            0x0b: c11__;
            0x0c: c12__;
            0x0d: c13__;
            0x0e: c14__;
            0x0f: c15__;
            0x10: c16__;
            0x11: c17__;
            0x12: c18__;
            0x13: c19__;
            0x14: c20__;
            0x15: c21__;
            0x16: c22__;
            0x17: c23__;
            0x18: c24__;
            0x19: c25__;
            0x1a: c26__;
            0x1b: c27__;
            0x1c: c28__;
            0x1d: c29__;
            0x1e: c30__;
            // 0x1f: c31__;
            // 0x20: c32__;
            // 0x21: c33__;
            // 0x22: c34__;
            // 0x23: c35__;
            // 0x24: c36__;
            // 0x25: c37__;
            // 0x26: c38__;
            // 0x27: c39__;
            // 0x28: c40__;
            // 0x29: c41__;
            // 0x2a: c42__;
            // 0x2b: c43__;
            // 0x2c: c44__;
            // 0x2d: c45__;
            // 0x2e: c46__;
            // 0x2f: c47__;
            default: unparsed_extensions;
        }

    }

    state c0__ {
        pkt.advance(32); // 8 + 32 (extension header)
        transition parse_extensions;}
    state c1__ {
        pkt.advance(40); // 8 + 32 (extension header)
        transition parse_extensions;
    }
    state c2__ {pkt.advance(48); transition parse_extensions;}
    state c3__ {pkt.advance(56); transition parse_extensions;}
    state c4__ {pkt.advance(64); transition parse_extensions;}
    state c5__ {pkt.advance(72); transition parse_extensions;}
    state c6__ {pkt.advance(80); transition parse_extensions;}
    state c7__ {pkt.advance(88); transition parse_extensions;}
    state c8__ {pkt.advance(96); transition parse_extensions;}
    state c9__ {pkt.advance(104); transition parse_extensions;}
    state c10__ {pkt.advance(112); transition parse_extensions;}
    state c11__ {pkt.advance(120); transition parse_extensions;}
    state c12__ {pkt.advance(128); transition parse_extensions;}
    state c13__ {pkt.advance(136); transition parse_extensions;}
    state c14__ {pkt.advance(144); transition parse_extensions;}
    state c15__ {pkt.advance(152); transition parse_extensions;}
    state c16__ {pkt.advance(160); transition parse_extensions;}
    state c17__ {pkt.advance(136); transition parse_extensions;}
    state c18__ {pkt.advance(144); transition parse_extensions;}
    state c19__ {pkt.advance(152); transition parse_extensions;}
    state c20__ {pkt.advance(160); transition parse_extensions;}
    state c21__ {pkt.advance(168); transition parse_extensions;}
    state c22__ {pkt.advance(176); transition parse_extensions;}
    state c23__ {pkt.advance(184); transition parse_extensions;}
    state c24__ {pkt.advance(192); transition parse_extensions;}
    state c25__ {pkt.advance(200); transition parse_extensions;}
    state c26__ {pkt.advance(208); transition parse_extensions;}
    state c27__ {pkt.advance(216); transition parse_extensions;}
    state c28__ {pkt.advance(224); transition parse_extensions;}
    state c29__ {pkt.advance(232); transition parse_extensions;}
    state c30__ {pkt.advance(240); transition parse_extensions;}
    state c31__ {pkt.advance(248); transition parse_extensions;}
    // state c32__ {pkt.advance(256); transition parse_extensions;}
    // state c33__ {pkt.advance(264); transition parse_extensions;}
    // state c34__ {pkt.advance(272); transition parse_extensions;}
    // state c35__ {pkt.advance(280); transition parse_extensions;}
    // state c36__ {pkt.advance(288); transition parse_extensions;}
    // state c37__ {pkt.advance(296); transition parse_extensions;}
    // state c38__ {pkt.advance(304); transition parse_extensions;}
    // state c39__ {pkt.advance(312); transition parse_extensions;}
    // state c40__ {pkt.advance(320); transition parse_extensions;}
    // state c41__ {pkt.advance(328); transition parse_extensions;}
    // state c42__ {pkt.advance(336); transition parse_extensions;}
    // state c43__ {pkt.advance(344); transition parse_extensions;}
    // state c44__ {pkt.advance(352); transition parse_extensions;}
    // state c45__ {pkt.advance(360); transition parse_extensions;}
    // state c46__ {pkt.advance(368); transition parse_extensions;}
    // state c47__ {pkt.advance(376); transition parse_extensions;}
    state unparsed_extensions {
        meta.unparsed = EXT_LIM;
        transition accept;
    }


    state parse_server_name {
        pkt.extract(hdr.extensions);
        pkt.extract(hdr.client_servername);
        // transition accept; 
        transition select(hdr.client_servername.sni_len) {
            1: parse_dns_q1_len1;
            2: parse_dns_q1_len2;
            3: parse_dns_q1_len3;
            4: parse_dns_q1_len4;
            5: parse_dns_q1_len5;
            6: parse_dns_q1_len6;
            7: parse_dns_q1_len7;
            8: parse_dns_q1_len8;
            9: parse_dns_q1_len9;
            10: parse_dns_q1_len10;
            11: parse_dns_q1_len11;
            12: parse_dns_q1_len12;
            13: parse_dns_q1_len13;
            14: parse_dns_q1_len14;
            15: parse_dns_q1_len15;
            16: parse_dns_q1_len16;
            17: parse_dns_q1_len17;
            18: parse_dns_q1_len18;
            19: parse_dns_q1_len19;
            20: parse_dns_q1_len20;
            21: parse_dns_q1_len21;
            22: parse_dns_q1_len22;
            23: parse_dns_q1_len23;
            24: parse_dns_q1_len24;
            25: parse_dns_q1_len25;
            26: parse_dns_q1_len26;
            27: parse_dns_q1_len27;
            28: parse_dns_q1_len28;
            29: parse_dns_q1_len29;
            30: parse_dns_q1_len30;
            31: parse_dns_q1_len31;
            default: unparsed_sni;
        }
    }

    state unparsed_sni {
        meta.unparsed = SNI_LEN;
        transition accept;
    }
    state parse_dns_q1_len1 {
        pkt.extract(hdr.servername_part1);
        transition accept;
    }

    state parse_dns_q1_len2 {
        pkt.extract(hdr.servername_part2);
        transition accept;
    }

    state parse_dns_q1_len3 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part2);
        transition accept;
    }

    state parse_dns_q1_len4 {
        pkt.extract(hdr.servername_part4);
        transition accept;
    }

    state parse_dns_q1_len5 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part4);
        transition accept;
    }

    state parse_dns_q1_len6 {
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part4);
        transition accept;
    }

    state parse_dns_q1_len7 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part4);
        transition accept;
    }

    state parse_dns_q1_len8 {
        pkt.extract(hdr.servername_part8);
        transition accept;
    }

    state parse_dns_q1_len9 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part8);
        transition accept;
    }

    state parse_dns_q1_len10 {
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part8);
        transition accept;
    }

    state parse_dns_q1_len11 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part8);
        transition accept;
    }

    state parse_dns_q1_len12 {
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part8);
        transition accept;
    }

    state parse_dns_q1_len13 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part8);
        transition accept;
    }

    state parse_dns_q1_len14 {
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part8);
        transition accept;
    }

    state parse_dns_q1_len15 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part8);
        transition accept;
    }

    state parse_dns_q1_len16 {
        pkt.extract(hdr.servername_part16);
        transition accept;
    }
    
    state parse_dns_q1_len17 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len18 {
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len19 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len20 {
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len21 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len22 {
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len23 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len24 {
        pkt.extract(hdr.servername_part8);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }
    
    state parse_dns_q1_len25 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part8);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len26 {
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part8);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len27 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part8);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len28 {
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part8);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len29 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part8);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len30 {
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part8);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

    state parse_dns_q1_len31 {
        pkt.extract(hdr.servername_part1);
        pkt.extract(hdr.servername_part2);
        pkt.extract(hdr.servername_part4);
        pkt.extract(hdr.servername_part8);
        pkt.extract(hdr.servername_part16);
        transition accept;
    }

   //  */
}
