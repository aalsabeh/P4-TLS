/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control calc_long_hash (in bit<248> servername, out bit<16> hash) (bit<16> coeff) {
    CRCPolynomial<bit<16>>(coeff = coeff, reversed = false, msb = false, extended = false, init=0xFFFF, xor=0xFFFF) poly;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        hash = hash_algo.get({servername});
    }
    apply {
        do_hash();
    }
}
control calc_long_hash32 (in bit<248> servername, out bit<32> hash) (bit<32> coeff) {
    CRCPolynomial<bit<32>>(coeff = coeff, reversed = true, msb = false, extended = false, init=0xFFFFFFFF, xor=0xFFFFFFFF) poly;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        hash = hash_algo.get({servername});
    }
    apply {
        do_hash();
    }
}
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    calc_long_hash(coeff=0x1021) servername_hash_fc;
    calc_long_hash32(coeff=0x1EDC6F41) servername_hash_fc32;
    bit<248> servername;
    bit<32> servername_hash32;

    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) domain_stats;

    action send_using_port(PortId_t port){
	    ig_tm_md.ucast_egress_port = port;   
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action send_with_count(PortId_t port){
	    ig_tm_md.ucast_egress_port = port;   
        domain_stats.count();
    }

    action drop_with_count() {
        ig_dprsr_md.drop_ctl = 1;
        domain_stats.count();
    }


    table forwarding {
        key = { 
		    // ig_intr_md.ingress_port : exact; 
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            send_using_port; 
            drop;
        }
    }

    table fine_grained {
        key = {
            servername_hash32: exact;
        }

        actions = {
            send_using_port;
            NoAction;
        }
        size = 500000;
        default_action = NoAction();
    }

    
    table coarse_grained {
        key = {
            hdr.servername_part1.isValid(): ternary;
            hdr.servername_part1.part: ternary;
            hdr.servername_part2.isValid(): ternary;
            hdr.servername_part2.part: ternary;
            hdr.servername_part4.isValid(): ternary;
            hdr.servername_part4.part: ternary;
            hdr.servername_part8.isValid(): ternary;
            hdr.servername_part8.part: ternary;
            hdr.servername_part16.isValid(): ternary;
            hdr.servername_part16.part: ternary;
        }
        actions = {
            @defaultonly NoAction;
            send_with_count;
            drop_with_count;
        }
        size = 15000;
        counters = domain_stats;
    }


    apply {
	    forwarding.apply();
        
        if (hdr.client_servername.isValid() && hdr.client_servername.sni_len > 0) {
            
            if (hdr.servername_part1.isValid()) {
                servername[7:0] = hdr.servername_part1.part;
            }
            if (hdr.servername_part2.isValid()) {
                servername[23:8] = hdr.servername_part2.part;
            }
            if (hdr.servername_part4.isValid()) {
                servername[55:24] = hdr.servername_part4.part;
            }
            if (hdr.servername_part8.isValid()) {
                servername[119:56] = hdr.servername_part8.part;
            }
           if (hdr.servername_part16.isValid()) {
                servername[247:120] = hdr.servername_part16.part;
                
            }

            servername_hash_fc32.apply(servername, servername_hash32);

            // fine-grained
            fine_grained.apply();
            
            // coarse-grained // service monitoring
            coarse_grained.apply();

            
        }

    }
}
