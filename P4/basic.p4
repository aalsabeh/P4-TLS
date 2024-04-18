#include <core.p4>
#include <tna.p4>
#include "headers.p4"
#include "ingress_parser.p4"
#include "ingress.p4"
#include "ingress_deparser.p4"
#include "egress_parser.p4"
#include "egress.p4"
#include "egress_deparser.p4"

/* Insert the block below this comment */
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;
Switch(pipe) main;