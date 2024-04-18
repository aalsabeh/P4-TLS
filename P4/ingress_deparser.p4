    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Mirror() mirror;
    apply {
        // if (ig_dprsr_md.mirror_type == 1) {
        //     mirror.emit<mirror_h>(meta.ing_mir_ses, {(bit<8>)ig_dprsr_md.mirror_type,ig_md.syn_counts,ig_md.ack_counts});
        // }
        pkt.emit(hdr);
    }
}
