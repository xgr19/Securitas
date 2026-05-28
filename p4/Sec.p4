/* -*- P4_16 -*- */

/*
*Author: xgr
*/

#include <core.p4>
#include <tna.p4>

/*********************** global constent parameters ************************/
#define DUMMY_CHECKSUM  2024
#define REAL_NET 0x0A000001

// width: element bit-width
// depth: bit-width for the number of elements
typedef bit<3>         patch_depth;
typedef bit<18>        register_depth;
typedef bit<16>        register_width;  // Each patch is shorter than 1024, so 16 bits is enough; registers use saturating addition.


const bit<8>           PROTO_TCP = 6;
const bit<8>           PROTO_UDP = 17;
const register_depth   register_lens = (1 << 18) - 1; // Hash each five-tuple flow to one register.
const register_width   EACH_PATCH_SIZE = 10;  // One patch has fewer than 1024 elements.
const bit<16>          MAX_INT_16 = (1 << 16) - 1;


const PortId_t         HIGHSPEED_TRAFFIC_PORT = 0;   // input, not bidirected
const PortId_t         REAL_TRAFFIC_PORT = 4;        // bidirected
const PortId_t         OBF_TRAFFIC_PORT = 40;        // bidirected

// meta data transfer from ingress to egress
// This header is only used inside of our pipeline and will never leave the chip.
// Therefore, we let the compiler decide how to layout the fields by using the @flexible pragma.
@flexible
header global_xgr_h {                    
//  [IP header -> first part -> remaining part]; mirrored packets are slower than original packets.
    bit<4>          pkt_type;            // 0 - no action; 1 - remaining part after mirror; 2 - mirrored first part; 3 - TTL mirror
    bit<16>         mirror_len;          // 8-88 bytes; bit-width = IP.totalLen
    bit<4>          will_tuncat_suceed;  // 1 suceed, 0 fail
    PortId_t        ingress_port;
    bit<4>          pkt_type_plus_will_tuncat_suceed;
}

/*********************** H E A D E R S  ************************/

header ethernet_h {
    bit<48>    dstAddr;
    bit<48>    srcAddr;
    bit<16>    etherType;
}

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
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

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_length;
    bit<16> checksum;
}


/********  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_headers_t {
    global_xgr_h meta;
    ethernet_h   ethernet;
    ipv4_h       ipv4;
    tcp_h        tcp;
    udp_h        udp;
}

struct my_ingress_metadata_t {
    bit<16>        srcPort;
    bit<16>        dstPort;
    register_depth register_idx;
    bit<4>         mirred_pkt_type;  // 1 - the remaining part after mirror; 2 - mirrored first part; 3 - TTL mirror
    bit<4>         mirred_pkt_type_plus_will_tuncat_suceed;
    register_width pkt_cnt;          // the number of current pkt in the flow
    bit<16>        substrct1;        // temporary parameters
    bit<16>        substrct2;

    MirrorId_t     ing_mir_ses;
    patch_depth    patch_idx;        // which patch is used, 0 to 7
}


/*********************** I N G R E S S    P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        hdr.meta = {0, 0, 0, 0, 0}; // make global_xgr_h valid
        hdr.meta.ingress_port = ig_intr_md.ingress_port;
        meta = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800  : parse_ipv4;
            // default : reject; reject does not drop pkt!
            // miss in a select cause ig_prsr_md.parser_err and can then manually drop pkt
        }
    }
   
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP : parse_tcp;
            PROTO_UDP : parse_udp;
        }
    }
     
    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.srcPort = hdr.tcp.src_port;
        meta.dstPort = hdr.tcp.dst_port;
        transition accept;
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        meta.srcPort = hdr.udp.src_port;
        meta.dstPort = hdr.udp.dst_port;
        transition accept;
    }
}

/***************** I N G R E S S   M A T C H - A C T I O N  *********************/

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
    action droppacket(){
        ig_dprsr_md.drop_ctl = 1;
        exit;
    }

    // Routing is checked first to determine whether traffic leaves or enters the subnet.
    // Inbound subnet traffic is left unchanged.
    action ac_packet_forward_in(){
        ig_tm_md.ucast_egress_port = REAL_TRAFFIC_PORT;
        exit; // jump to ingress deparser
    }

    Hash<patch_depth>(HashAlgorithm_t.CRC16) hash_patch_idx;
    action ac_packet_forward_out(){
        ig_tm_md.ucast_egress_port = OBF_TRAFFIC_PORT;
        ig_tm_md.qid = 0;  // lower queue priority
        // meta.patch_idx = hash_patch_idx.get(
        //     {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol,
        //         meta.srcPort, meta.dstPort});
        meta.patch_idx = 0;
    }

    table route_egport_and_patchidx{
        key = {hdr.ipv4.dstAddr: ternary; ig_intr_md.ingress_port: exact;}
        actions = {ac_packet_forward_out; ac_packet_forward_in; droppacket;}
        const entries = {
            //  val &&& msk
            (REAL_NET&&&0xFFFFFFFF, OBF_TRAFFIC_PORT)      : ac_packet_forward_in();
            (_,                     REAL_TRAFFIC_PORT)     : ac_packet_forward_out();
            (_,                     HIGHSPEED_TRAFFIC_PORT): ac_packet_forward_out();
        }

        default_action = droppacket();
    }


    // Counting: which packet is this in the five-tuple flow?
    Register<register_width, register_depth>((bit<32>)register_lens) flow_cnting;

    RegisterAction<register_width, register_depth, 
        register_width>(flow_cnting) read_flow_cnt = {
            void apply(inout register_width register_data, out register_width cnt) {
                register_data = register_data + 1;
                cnt = register_data;
            }
    };
    
    Hash<register_depth>(HashAlgorithm_t.CRC32) hash_register_idx;
    action ac_read_register_idx(){
        meta.register_idx = hash_register_idx.get(
            {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol,
                meta.srcPort, meta.dstPort});
        // meta.pkt_cnt = read_flow_cnt.execute(meta.register_idx);  // Operations in one action are simultaneous, so this reads register_idx=0 before assignment.
    }
    

    action ac_should_TTL(bit<16> mir_len){
        hdr.meta.pkt_type = 0;
        hdr.meta.pkt_type_plus_will_tuncat_suceed = 0b0000;
        
        hdr.meta.mirror_len = mir_len;  // TTL pkt len
        ig_dprsr_md.mirror_type = 2;
        
        meta.mirred_pkt_type = 3;
        meta.mirred_pkt_type_plus_will_tuncat_suceed = 0b1100;
    }


    action ac_should_fragment(bit<16> mir_len){
        hdr.meta.pkt_type = 1;          // The current packet is the remaining fragment.
        hdr.meta.pkt_type_plus_will_tuncat_suceed = 0b0100;

        hdr.meta.mirror_len = mir_len;  // remove bytes in the current packet
        ig_dprsr_md.mirror_type = 2;
        
        meta.mirred_pkt_type = 2;       // The mirrored packet is the first fragment.
        meta.mirred_pkt_type_plus_will_tuncat_suceed = 0b1000;
    }

    action ac_jump_deparser(){exit;}

    table assign_patch_info{
        key = {meta.patch_idx: exact; meta.pkt_cnt: exact;}
        actions = {ac_should_TTL; ac_should_fragment; 
            ac_jump_deparser;}
        // WF_800.p4 is generated by web_securitas_training/generate_p4.py and copied into this directory.
        // The include below expands to this table's const entries block. Each generated
        // entry maps (patch_idx, pkt_cnt) to ac_should_TTL(mir_len) or
        // ac_should_fragment(mir_len); packets without generated entries use
        // default_action = ac_jump_deparser().
        // Each patch can have many sess_id values (tens or hundreds); update them periodically
        // through the control plane in production. sess_id 0 cannot be used.
        // If mir_len == 0, do not install this rule, or install it as ac_jump_deparser.
        #include "WF_800.p4"
        default_action = ac_jump_deparser();  // by default in parser, pkt_type = 0; mirror_type = 0
        size = 20000;
    }


    action ac_totalLen_substrct_mirLen(){
        meta.substrct1 = hdr.ipv4.totalLen - hdr.meta.mirror_len;
        meta.substrct2 = hdr.ipv4.totalLen - hdr.meta.mirror_len;
    }

    action ac_set_tuncat_suceed(){ 
        hdr.meta.will_tuncat_suceed = 1;
    }

    // predict fragment succed or not in TM
    table check_fragment_suceed{
        key = {meta.substrct1[15:15]: exact; meta.substrct2: range;}
        actions = {ac_set_tuncat_suceed; NoAction;}
        const entries = {
        //     substrct > 0
            (0, 1..MAX_INT_16) :  ac_set_tuncat_suceed();
        }       

        default_action = NoAction(); // by defualt, hdr.meta.will_tuncat_suceed = 0;
    }

    action ac_assign_sess(MirrorId_t sess_id){ meta.ing_mir_ses = sess_id; }

    table assign_mirror_sess{
        // if more than 1 net connect to the switch: every 11 sessions is assigned per net
        // by configure session in controller, we can assign the egress port of mirroed pkts
        key = {hdr.ipv4.dstAddr: ternary; hdr.meta.mirror_len: exact;}
        actions = {ac_assign_sess; droppacket;}
        const entries = {
            (_, 8)  : ac_assign_sess(1); (_, 16) : ac_assign_sess(2);
            (_, 24) : ac_assign_sess(3); (_, 32) : ac_assign_sess(4);
            (_, 40) : ac_assign_sess(5); (_, 48) : ac_assign_sess(6);
            (_, 56) : ac_assign_sess(7); (_, 64) : ac_assign_sess(8);
            (_, 72) : ac_assign_sess(9); (_, 80) : ac_assign_sess(10);
            (_, 88) : ac_assign_sess(11);
        }
        default_action = droppacket();
    }

    apply{
        if(ig_prsr_md.parser_err == PARSER_ERROR_NO_MATCH){ droppacket(); }

        route_egport_and_patchidx.apply();
        if (hdr.ipv4.ihl == 5){ // in 4-byte unit
            ac_read_register_idx();
            meta.pkt_cnt = read_flow_cnt.execute(meta.register_idx);
            meta.pkt_cnt = meta.pkt_cnt & 0b0000011111111111;  // Keep 11 of 16 bits, giving 2048; WF has 800 elements, so patch = 800/2048 = 40%.
            assign_patch_info.apply();
            assign_mirror_sess.apply();

            ac_totalLen_substrct_mirLen();
            meta.substrct1 = meta.substrct1 - 20;  // IP header is 20; >0 succeeds, while =0 or <0 fails.
            meta.substrct2 = meta.substrct2 - 20;
            check_fragment_suceed.apply();

            hdr.meta.pkt_type_plus_will_tuncat_suceed =  hdr.meta.pkt_type_plus_will_tuncat_suceed + hdr.meta.will_tuncat_suceed;
            meta.mirred_pkt_type_plus_will_tuncat_suceed = meta.mirred_pkt_type_plus_will_tuncat_suceed + hdr.meta.will_tuncat_suceed;
        }
        else{
            droppacket();
        }
    }

}

/********************* I N G R E S S    D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Mirror() mirror;

    apply {
        // Switch packets include a MAC layer, so maxlen in the control-plane session must add 14 MAC + 20 IP header + 10 extra bytes.
        // hdr.meta.mirror_len is the IP payload length.
        if (ig_dprsr_md.mirror_type == 2) {
            mirror.emit<global_xgr_h>(meta.ing_mir_ses, {
                meta.mirred_pkt_type, hdr.meta.mirror_len,
                hdr.meta.will_tuncat_suceed, hdr.meta.ingress_port, 
                meta.mirred_pkt_type_plus_will_tuncat_suceed
            });
        }

        // Original packet: the switch handles MAC frame padding and FCS itself: https://www.cnblogs.com/wander-clouds/p/9033016.html
        pkt.emit(hdr);
    }
}


/*********************** E G R E S S    H E A D E R S  ************************/

struct my_egress_headers_t {
    global_xgr_h meta;
    ethernet_h   ethernet;
    ipv4_h       ipv4;

    tcp_h        tcp;
    udp_h        udp;
}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

/*********************** E G R E S S    P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        pkt.extract(hdr.meta);
        pkt.extract(hdr.ethernet);
        pkt.extract(hdr.ipv4);
        transition select(hdr.meta.pkt_type_plus_will_tuncat_suceed) { // pkt_type = 1 (mirrored left part), succed = 1
            0b0101 : parse_payload;
            default : tcp_or_udp;
        }
    }


    state tcp_or_udp {
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP : parse_tcp;
            PROTO_UDP : parse_udp;
        }
    }


    state parse_payload{
        transition select(hdr.meta.mirror_len){
            // EgressParser: longest path through parser (311B) exceeds maximum parse depth (160B)
            8  : extract8B;
            16 : extract16B;
            24 : extract24B;
            32 : extract32B;
            40 : extract40B;
            48 : extract48B;
            56 : extract56B;
            64 : extract64B;
            72 : extract72B;
            80 : extract80B;
            88 : extract88B;
        }
    }


    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
    
    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }

    // if extract fail, egress_intrinsic_metadata_from_parser_t
    // will has a parser_err == PARSER_ERROR_PARTIAL_HDR (16w0x0002): PacketTooShort
    // The egress pipeline can still process this packet; ingress drops it if parser_err is absent from the pipeline.
    state extract8B {pkt.advance(64);  transition accept;}
    state extract16B{pkt.advance(128); transition accept;}
    state extract24B{pkt.advance(192); transition accept;}
    state extract32B{pkt.advance(256); transition accept;}
    state extract40B{pkt.advance(320); transition accept;}
    state extract48B{pkt.advance(384); transition accept;}
    state extract56B{pkt.advance(448); transition accept;}
    state extract64B{pkt.advance(512); transition accept;}
    state extract72B{pkt.advance(576); transition accept;}
    state extract80B{pkt.advance(640); transition accept;}
    state extract88B{pkt.advance(704); transition accept;}
}

/***************** E G R E S S     M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{

    action droppacket(){
        eg_dprsr_md.drop_ctl = 1;
        exit;
    }

    // Fragment success case 1: pkt_type = 1: update checksum and omit padding.
    // MF = 0, offset = pad/8, totalLen - pad
    action ac_type1_suceed_pad8(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM = 1, MF = 0, this is the last fragment
        hdr.ipv4.fragOffset = 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 8;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad16(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 2; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 16;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad24(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 3; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 24;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad32(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 4; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 32;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad40(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 5; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 40;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad48(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 6; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 48;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad64(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 8; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 64;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad56(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 7; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 56;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad72(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 9; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 72;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad80(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 10; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 80;
        // checksum update in deparser
    }

    action ac_type1_suceed_pad88(){
        hdr.ipv4.flags = 0b010;  // bits are 0, DM, MF
        hdr.ipv4.fragOffset = 11; // Fragments are in 8-byte units
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 88;
        // checksum update in deparser
    }

    // Fragment success case 2: pkt_type = 2: update checksum, set MF = 1 and offset = 0.
    // totalLen = pad + 20; assume the truncated packet has not corrected totalLen.
    action ac_type2_suceed(){
        hdr.ipv4.flags = 0b011;  // bits are 0, DM, MF=1
        hdr.ipv4.fragOffset = 0;
        hdr.ipv4.totalLen = hdr.meta.mirror_len + 20; // ip hdr len
        // checksum update in deparser
    }


    action ac_type3_suceed_tcp_8B16B(){ // fk pkt
        hdr.ipv4.ttl = 3;
        hdr.ipv4.totalLen = hdr.meta.mirror_len + 20; // ip hdr len
        // too short to have tcp checksum: already invalid
    }

    action ac_type3_suceed_tcp(){
        hdr.ipv4.ttl = 3;
        hdr.ipv4.totalLen = hdr.meta.mirror_len + 20;
        hdr.tcp.checksum = DUMMY_CHECKSUM;
    }

    action ac_type3_suceed_udp(){
        // UDP has an 8-byte header; our minimum is 8B, so the checksum is present.
        hdr.ipv4.ttl = 3;
        hdr.ipv4.totalLen = hdr.meta.mirror_len + 20;
        hdr.udp.udp_length = hdr.meta.mirror_len;
        hdr.udp.checksum = DUMMY_CHECKSUM;

    }

    action ac_type2_3_fail_tcp(){
        hdr.ipv4.ttl = 3;
        // hdr.ipv4.totalLen = hdr.meta.mirror_len + 20; // Failure means the cloned packet has the same length as the original packet.
        hdr.tcp.checksum = DUMMY_CHECKSUM;
    }

    action ac_type2_3_fail_udp(){
        // udp has 8-byte header
        hdr.ipv4.ttl = 3;
        // hdr.ipv4.totalLen = hdr.meta.mirror_len + 20; // Failure means the cloned packet has the same length as the original packet.
        hdr.udp.checksum = DUMMY_CHECKSUM;
    }


    table set_pkt_type_hdr{
        key = {
            hdr.meta.will_tuncat_suceed: exact; 
            hdr.meta.pkt_type:   exact; 
            hdr.meta.mirror_len: ternary;
            hdr.ipv4.protocol:   ternary;
        }
        actions = {
            ac_type1_suceed_pad8; ac_type1_suceed_pad16; ac_type1_suceed_pad24;
            ac_type1_suceed_pad32; ac_type1_suceed_pad40; ac_type1_suceed_pad48;
            ac_type1_suceed_pad56; ac_type1_suceed_pad64; ac_type1_suceed_pad72;
            ac_type1_suceed_pad80; ac_type1_suceed_pad88;
            ac_type2_suceed;
            ac_type3_suceed_tcp_8B16B; ac_type3_suceed_tcp; ac_type3_suceed_udp;
            ac_type2_3_fail_tcp; ac_type2_3_fail_udp;}

        // range means [1, 10] -> 1..10 : set_mytos();
        // In ternary matches only, underscore means * -> (0x06, _ ) : a_with_control_params(6);
        const entries = {
            //suceed, type1, 8/16/32/...88B
            (1, 1, 8&&&0xFFFF,  _)      : ac_type1_suceed_pad8();
            (1, 1, 16&&&0xFFFF,  _)     : ac_type1_suceed_pad16();
            (1, 1, 24&&&0xFFFF,  _)     : ac_type1_suceed_pad24();
            (1, 1, 32&&&0xFFFF,  _)     : ac_type1_suceed_pad32();
            (1, 1, 40&&&0xFFFF,  _)     : ac_type1_suceed_pad40();
            (1, 1, 48&&&0xFFFF,  _)     : ac_type1_suceed_pad48();
            (1, 1, 56&&&0xFFFF,  _)     : ac_type1_suceed_pad56();
            (1, 1, 64&&&0xFFFF,  _)     : ac_type1_suceed_pad64();
            (1, 1, 72&&&0xFFFF,  _)     : ac_type1_suceed_pad72();
            (1, 1, 80&&&0xFFFF,  _)     : ac_type1_suceed_pad80();
            (1, 1, 88&&&0xFFFF,  _)     : ac_type1_suceed_pad88();
            // type2
            (1, 2, _,  _)               : ac_type2_suceed();   
            (0, 2, _,  PROTO_TCP&&&0xFF): ac_type2_3_fail_tcp();
            (0, 2, _,  PROTO_UDP&&&0xFF): ac_type2_3_fail_udp();
            // type 3
            (1, 3, 8&&&0xFFFF, PROTO_TCP&&&0xFF) : ac_type3_suceed_tcp_8B16B();
            (1, 3, 16&&&0xFFFF, PROTO_TCP&&&0xFF): ac_type3_suceed_tcp_8B16B();
            (1, 3, _, PROTO_TCP&&&0xFF)  : ac_type3_suceed_tcp();
            (1, 3, _, PROTO_UDP&&&0xFF)  : ac_type3_suceed_udp();
            //
            (0, 3, _,  PROTO_TCP&&&0xFF) : ac_type2_3_fail_tcp();
            (0, 3, _,  PROTO_UDP&&&0xFF) : ac_type2_3_fail_udp();
        }
    }

    apply {
        if(eg_prsr_md.parser_err == PARSER_ERROR_NO_MATCH){ droppacket(); }

        if(hdr.meta.ingress_port == HIGHSPEED_TRAFFIC_PORT){
            hdr.ipv4.flags = 0b000;  // default value used to identify non-fragment pkts in our deobf exp
        }
        set_pkt_type_hdr.apply();
        hdr.meta.setInvalid();
    }
}

/********************* E G R E S S     D E P A R S E R  ************************/

control EgressDeparser(packet_out                   pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    Checksum() ipv4_checksum;

    apply {
        hdr.ipv4.hdrChecksum = ipv4_checksum.update(
            {hdr.ipv4.version,
             hdr.ipv4.ihl,
             hdr.ipv4.diffserv,
             hdr.ipv4.totalLen,
             hdr.ipv4.identification,
             hdr.ipv4.flags,
             hdr.ipv4.fragOffset,
             hdr.ipv4.ttl,
             hdr.ipv4.protocol,
             hdr.ipv4.srcAddr,
             hdr.ipv4.dstAddr});

        pkt.emit(hdr);
    }
}


/*************************************************************************
****************  F I N A L   P A C K A G E          *******************
*************************************************************************/

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
