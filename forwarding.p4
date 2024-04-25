/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const int N=350;
/*************************************************************************
*********************** R E G I S T E R S ********************************
*************************************************************************/

register<bit<32>>(1) t;
register<bit<64>>(32*N) bin;
register<bit<64>>(32*N) content;
register<bit<1>>(N) Y;
register<bit<32>>(1) src;
register<bit<32>>(1) dst;
register<bit<16>>(1) len;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
#14 bytes
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

#20 bytes
header ipv4_t {
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
#8 bytes
header data_t{
    bit<64> data;
}

struct metadata {
    /* empty */
}

/*struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}*/

struct headers {//the first 256 Bytes of packet after headers, in 32 chunks of 8 Bytes
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    data_t       d0;
    data_t       d1;
    data_t       d2;
    data_t       d3;
    data_t       d4;
    data_t       d5;
    data_t       d6;
    data_t       d7;
    data_t       d8;
    data_t       d9;
    data_t       d10;
    data_t       d11;
    data_t       d12;
    data_t       d13;
    data_t       d14;
    data_t       d15;
    data_t       d16;
    data_t       d17;
    data_t       d18;
    data_t       d19;
    data_t       d20;
    data_t       d21;
    data_t       d22;
    data_t       d23;
    data_t       d24;
    data_t       d25;
    data_t       d26;
    data_t       d27;
    data_t       d28;
    data_t       d29;
    data_t       d30;
    data_t       d31;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){

            TYPE_IPV4: ipv4;
            default: accept;

        }

    }

    state ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.totalLen){
            28 .. 35: retreive_data0;
            36 .. 43: retreive_data1;
            44 .. 51: retreive_data2;
            52 .. 59: retreive_data3;
            60 .. 67: retreive_data4;
            68 .. 75: retreive_data5;
            76 .. 83: retreive_data6;
            84 .. 91: retreive_data7;
            92 .. 99: retreive_data8;
            100 .. 107: retreive_data9;
            108 .. 115: retreive_data10;
            116 .. 123: retreive_data11;
            124 .. 131: retreive_data12;
            132 .. 139: retreive_data13;
            140 .. 147: retreive_data14;
            148 .. 155: retreive_data15;
            156 .. 163: retreive_data16;
            164 .. 171: retreive_data17;
            172 .. 179: retreive_data18;
            180 .. 187: retreive_data19;
            188 .. 195: retreive_data20;
            196 .. 203: retreive_data21;
            204 .. 211: retreive_data22;
            212 .. 219: retreive_data23;
            220 .. 227: retreive_data24;
            228 .. 235: retreive_data25;
            236 .. 243: retreive_data26;
            244 .. 251: retreive_data27;
            252 .. 259: retreive_data28;
            260 .. 267: retreive_data29;
            268 .. 275: retreive_data30;
            276 .. 65535: retreive_data31;
            default: accept;
        }
    }

    state retreive_data0{
        packet.extract(hdr.d0);
        transition accept;
    }

    state retreive_data1{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        transition accept;
    }

    state retreive_data2{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        transition accept;
    }

    state retreive_data3{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        transition accept;
    }

    state retreive_data4{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        transition accept;
    }

    state retreive_data5{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        transition accept;
    }

    state retreive_data6{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        transition accept;
    }

    state retreive_data7{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        transition accept;
    }

    state retreive_data8{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        transition accept;
    }

    state retreive_data9{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        transition accept;
    }
    
    state retreive_data10{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        transition accept;
    }
    
    state retreive_data11{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        transition accept;
    }
    
    state retreive_data12{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        transition accept;
    }
    
    state retreive_data13{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        transition accept;
    }
    
    state retreive_data14{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        transition accept;
    }
    
    state retreive_data15{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        transition accept;
    }
    
    state retreive_data16{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        transition accept;
    }
    
    state retreive_data17{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        transition accept;
    }
    
    state retreive_data18{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        transition accept;
    }
    
    state retreive_data19{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        transition accept;
    }
    
    state retreive_data20{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        transition accept;
    }
    
    state retreive_data21{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        transition accept;
    }
    
    state retreive_data22{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        transition accept;
    }
    
    state retreive_data23{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        packet.extract(hdr.d23);
        transition accept;
    }
    
    state retreive_data24{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        packet.extract(hdr.d23);
        packet.extract(hdr.d24);
        transition accept;
    }
    
    state retreive_data25{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        packet.extract(hdr.d23);
        packet.extract(hdr.d24);
        packet.extract(hdr.d25);
        transition accept;
    }
    
    state retreive_data26{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        packet.extract(hdr.d23);
        packet.extract(hdr.d24);
        packet.extract(hdr.d25);
        packet.extract(hdr.d26);
        transition accept;
    }
    
    state retreive_data27{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        packet.extract(hdr.d23);
        packet.extract(hdr.d24);
        packet.extract(hdr.d25);
        packet.extract(hdr.d26);
        packet.extract(hdr.d27);
        transition accept;
    }
    
    state retreive_data28{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        packet.extract(hdr.d23);
        packet.extract(hdr.d24);
        packet.extract(hdr.d25);
        packet.extract(hdr.d26);
        packet.extract(hdr.d27);
        packet.extract(hdr.d28);
        transition accept;
    }
    
    state retreive_data29{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        packet.extract(hdr.d23);
        packet.extract(hdr.d24);
        packet.extract(hdr.d25);
        packet.extract(hdr.d26);
        packet.extract(hdr.d27);
        packet.extract(hdr.d28);
        packet.extract(hdr.d29);
        transition accept;
    }
    
    state retreive_data30{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        packet.extract(hdr.d23);
        packet.extract(hdr.d24);
        packet.extract(hdr.d25);
        packet.extract(hdr.d26);
        packet.extract(hdr.d27);
        packet.extract(hdr.d28);
        packet.extract(hdr.d29);
        packet.extract(hdr.d30);
        transition accept;
    }
    
    state retreive_data31{
        packet.extract(hdr.d0);
        packet.extract(hdr.d1);
        packet.extract(hdr.d2);
        packet.extract(hdr.d3);
        packet.extract(hdr.d4);
        packet.extract(hdr.d5);
        packet.extract(hdr.d6);
        packet.extract(hdr.d7);
        packet.extract(hdr.d8);
        packet.extract(hdr.d9);
        packet.extract(hdr.d10);
        packet.extract(hdr.d11);
        packet.extract(hdr.d12);
        packet.extract(hdr.d13);
        packet.extract(hdr.d14);
        packet.extract(hdr.d15);
        packet.extract(hdr.d16);
        packet.extract(hdr.d17);
        packet.extract(hdr.d18);
        packet.extract(hdr.d19);
        packet.extract(hdr.d20);
        packet.extract(hdr.d21);
        packet.extract(hdr.d22);
        packet.extract(hdr.d23);
        packet.extract(hdr.d24);
        packet.extract(hdr.d25);
        packet.extract(hdr.d26);
        packet.extract(hdr.d27);
        packet.extract(hdr.d28);
        packet.extract(hdr.d29);
        packet.extract(hdr.d30);
        packet.extract(hdr.d31);
        transition accept;
    }
    

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        
        //ipv4 information
        src.write(0,hdr.ipv4.srcAddr);
        len.write(0,hdr.ipv4.totalLen);
        dst.write(0,hdr.ipv4.dstAddr);
        
        //set the src mac address as the previous dst
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

        //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;

    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    apply {

        bit<32> time;
        t.read(time,0);
        bit<32> index=32*time;
        content.write(index+0,hdr.d0.data);
        content.write(index+1,hdr.d1.data);
        content.write(index+2,hdr.d2.data);
        content.write(index+3,hdr.d3.data);
        content.write(index+4,hdr.d4.data);
        content.write(index+5,hdr.d5.data);
        content.write(index+6,hdr.d6.data);
        content.write(index+7,hdr.d7.data);
        content.write(index+8,hdr.d8.data);
        content.write(index+9,hdr.d9.data);
        content.write(index+10,hdr.d10.data);
        content.write(index+11,hdr.d11.data);
        content.write(index+12,hdr.d12.data);
        content.write(index+13,hdr.d13.data);
        content.write(index+14,hdr.d14.data);
        content.write(index+15,hdr.d15.data);
        content.write(index+16,hdr.d16.data);
        content.write(index+17,hdr.d17.data);
        content.write(index+18,hdr.d18.data);
        content.write(index+19,hdr.d19.data);
        content.write(index+20,hdr.d20.data);
        content.write(index+21,hdr.d21.data);
        content.write(index+22,hdr.d22.data);
        content.write(index+23,hdr.d23.data);
        content.write(index+24,hdr.d24.data);
        content.write(index+25,hdr.d25.data);
        content.write(index+26,hdr.d26.data);
        content.write(index+27,hdr.d27.data);
        content.write(index+28,hdr.d28.data);
        content.write(index+29,hdr.d29.data);
        content.write(index+30,hdr.d30.data);
        content.write(index+31,hdr.d31.data);
        
        bin.write(index+0,hdr.d0.data);
        bin.write(index+1,hdr.d1.data);
        bin.write(index+2,hdr.d2.data);
        bin.write(index+3,hdr.d3.data);
        bin.write(index+4,hdr.d4.data);
        bin.write(index+5,hdr.d5.data);
        bin.write(index+6,hdr.d6.data);
        bin.write(index+7,hdr.d7.data);
        bin.write(index+8,hdr.d8.data);
        bin.write(index+9,hdr.d9.data);
        bin.write(index+10,hdr.d10.data);
        bin.write(index+11,hdr.d11.data);
        bin.write(index+12,hdr.d12.data);
        bin.write(index+13,hdr.d13.data);
        bin.write(index+14,hdr.d14.data);
        bin.write(index+15,hdr.d15.data);
        bin.write(index+16,hdr.d16.data);
        bin.write(index+17,hdr.d17.data);
        bin.write(index+18,hdr.d18.data);
        bin.write(index+19,hdr.d19.data);
        bin.write(index+20,hdr.d20.data);
        bin.write(index+21,hdr.d21.data);
        bin.write(index+22,hdr.d22.data);
        bin.write(index+23,hdr.d23.data);
        bin.write(index+24,hdr.d24.data);
        bin.write(index+25,hdr.d25.data);
        bin.write(index+26,hdr.d26.data);
        bin.write(index+27,hdr.d27.data);
        bin.write(index+28,hdr.d28.data);
        bin.write(index+29,hdr.d29.data);
        bin.write(index+30,hdr.d30.data);
        bin.write(index+31,hdr.d31.data);
        
        bit<64> damping=4;
        bit<64> moisturizing=1;
        bit<64> hydration;
        bit<64> temp=0;
        
        //repeat for i in range(0,32-2):
        bin.read(hydration,index+2);//new
        hydration=hydration*2;
        bin.read(temp,index+1);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+3);//new
        bin.read(temp,index+2);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+4);//new
        bin.read(temp,index+3);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+5);//new
        bin.read(temp,index+4);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+6);//new
        bin.read(temp,index+5);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+7);//new
        bin.read(temp,index+6);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+8);//new
        bin.read(temp,index+7);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+9);//new
        bin.read(temp,index+8);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+10);//new
        bin.read(temp,index+9);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);
        
        bin.read(hydration,index+11);//new
        bin.read(temp,index+10);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+12);//new
        bin.read(temp,index+11);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+13);//new
        bin.read(temp,index+12);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+14);//new
        bin.read(temp,index+13);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);
        
        bin.read(hydration,index+15);//new
        bin.read(temp,index+14);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+16);//new
        bin.read(temp,index+15);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+17);//new
        bin.read(temp,index+16);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+18);//new
        bin.read(temp,index+17);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+19);//new
        bin.read(temp,index+18);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+20);//new
        bin.read(temp,index+19);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+21);//new
        bin.read(temp,index+20);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+22);//new
        bin.read(temp,index+21);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+20);
        temp=temp*damping;
        bin.write(index+20,temp+hydration);
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+23);//new
        bin.read(temp,index+22);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+21);
        temp=temp*damping;
        bin.write(index+21,temp+hydration);
        bin.read(temp,index+20);
        temp=temp*damping;
        bin.write(index+20,temp+hydration);
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+24);//new
        bin.read(temp,index+23);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+22);
        temp=temp*damping;
        bin.write(index+22,temp+hydration);
        bin.read(temp,index+21);
        temp=temp*damping;
        bin.write(index+21,temp+hydration);
        bin.read(temp,index+20);
        temp=temp*damping;
        bin.write(index+20,temp+hydration);
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+25);//new
        bin.read(temp,index+24);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+23);
        temp=temp*damping;
        bin.write(index+23,temp+hydration);
        bin.read(temp,index+22);
        temp=temp*damping;
        bin.write(index+22,temp+hydration);
        bin.read(temp,index+21);
        temp=temp*damping;
        bin.write(index+21,temp+hydration);
        bin.read(temp,index+20);
        temp=temp*damping;
        bin.write(index+20,temp+hydration);
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+26);//new
        bin.read(temp,index+25);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+24);
        temp=temp*damping;
        bin.write(index+24,temp+hydration);
        bin.read(temp,index+23);
        temp=temp*damping;
        bin.write(index+23,temp+hydration);
        bin.read(temp,index+22);
        temp=temp*damping;
        bin.write(index+22,temp+hydration);
        bin.read(temp,index+21);
        temp=temp*damping;
        bin.write(index+21,temp+hydration);
        bin.read(temp,index+20);
        temp=temp*damping;
        bin.write(index+20,temp+hydration);
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+27);//new
        bin.read(temp,index+26);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+25);
        temp=temp*damping;
        bin.write(index+25,temp+hydration);
        bin.read(temp,index+24);
        temp=temp*damping;
        bin.write(index+24,temp+hydration);
        bin.read(temp,index+23);
        temp=temp*damping;
        bin.write(index+23,temp+hydration);
        bin.read(temp,index+22);
        temp=temp*damping;
        bin.write(index+22,temp+hydration);
        bin.read(temp,index+21);
        temp=temp*damping;
        bin.write(index+21,temp+hydration);
        bin.read(temp,index+20);
        temp=temp*damping;
        bin.write(index+20,temp+hydration);
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+28);//new
        bin.read(temp,index+27);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+26);
        temp=temp*damping;
        bin.write(index+26,temp+hydration);
        bin.read(temp,index+25);
        temp=temp*damping;
        bin.write(index+25,temp+hydration);
        bin.read(temp,index+24);
        temp=temp*damping;
        bin.write(index+24,temp+hydration);
        bin.read(temp,index+23);
        temp=temp*damping;
        bin.write(index+23,temp+hydration);
        bin.read(temp,index+22);
        temp=temp*damping;
        bin.write(index+22,temp+hydration);
        bin.read(temp,index+21);
        temp=temp*damping;
        bin.write(index+21,temp+hydration);
        bin.read(temp,index+20);
        temp=temp*damping;
        bin.write(index+20,temp+hydration);
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+29);//new
        bin.read(temp,index+28);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+27);
        temp=temp*damping;
        bin.write(index+27,temp+hydration);
        bin.read(temp,index+26);
        temp=temp*damping;
        bin.write(index+26,temp+hydration);
        bin.read(temp,index+25);
        temp=temp*damping;
        bin.write(index+25,temp+hydration);
        bin.read(temp,index+24);
        temp=temp*damping;
        bin.write(index+24,temp+hydration);
        bin.read(temp,index+23);
        temp=temp*damping;
        bin.write(index+23,temp+hydration);
        bin.read(temp,index+22);
        temp=temp*damping;
        bin.write(index+22,temp+hydration);
        bin.read(temp,index+21);
        temp=temp*damping;
        bin.write(index+21,temp+hydration);
        bin.read(temp,index+20);
        temp=temp*damping;
        bin.write(index+20,temp+hydration);
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bin.read(hydration,index+30);//new
        bin.read(temp,index+29);//old
        temp=temp*moisturizing;
        hydration=hydration-temp;
        bin.read(temp,index+28);
        temp=temp*damping;
        bin.write(index+28,temp+hydration);
        bin.read(temp,index+27);
        temp=temp*damping;
        bin.write(index+27,temp+hydration);
        bin.read(temp,index+26);
        temp=temp*damping;
        bin.write(index+26,temp+hydration);
        bin.read(temp,index+25);
        temp=temp*damping;
        bin.write(index+25,temp+hydration);
        bin.read(temp,index+24);
        temp=temp*damping;
        bin.write(index+24,temp+hydration);
        bin.read(temp,index+23);
        temp=temp*damping;
        bin.write(index+23,temp+hydration);
        bin.read(temp,index+22);
        temp=temp*damping;
        bin.write(index+22,temp+hydration);
        bin.read(temp,index+21);
        temp=temp*damping;
        bin.write(index+21,temp+hydration);
        bin.read(temp,index+20);
        temp=temp*damping;
        bin.write(index+20,temp+hydration);
        bin.read(temp,index+19);
        temp=temp*damping;
        bin.write(index+19,temp+hydration);
        bin.read(temp,index+18);
        temp=temp*damping;
        bin.write(index+18,temp+hydration);
        bin.read(temp,index+17);
        temp=temp*damping;
        bin.write(index+17,temp+hydration);
        bin.read(temp,index+16);
        temp=temp*damping;
        bin.write(index+16,temp+hydration);
        bin.read(temp,index+15);
        temp=temp*damping;
        bin.write(index+15,temp+hydration);
        bin.read(temp,index+14);
        temp=temp*damping;
        bin.write(index+14,temp+hydration);
        bin.read(temp,index+13);
        temp=temp*damping;
        bin.write(index+13,temp+hydration);
        bin.read(temp,index+12);
        temp=temp*damping;
        bin.write(index+12,temp+hydration);
        bin.read(temp,index+11);
        temp=temp*damping;
        bin.write(index+11,temp+hydration);
        bin.read(temp,index+10);
        temp=temp*damping;
        bin.write(index+10,temp+hydration);
        bin.read(temp,index+9);
        temp=temp*damping;
        bin.write(index+9,temp+hydration);
        bin.read(temp,index+8);
        temp=temp*damping;
        bin.write(index+8,temp+hydration);
        bin.read(temp,index+7);
        temp=temp*damping;
        bin.write(index+7,temp+hydration);
        bin.read(temp,index+6);
        temp=temp*damping;
        bin.write(index+6,temp+hydration);
        bin.read(temp,index+5);
        temp=temp*damping;
        bin.write(index+5,temp+hydration);
        bin.read(temp,index+4);
        temp=temp*damping;
        bin.write(index+4,temp+hydration);
        bin.read(temp,index+3);
        temp=temp*damping;
        bin.write(index+3,temp+hydration);
        bin.read(temp,index+2);
        temp=temp*damping;
        bin.write(index+2,temp+hydration);
        bin.read(temp,index+1);
        temp=temp*damping;
        bin.write(index+1,temp+hydration);
        bin.read(temp,index+0);
        temp=temp*damping;
        bin.write(index+0,temp+hydration);

        bit<1> flag;
        bit<64>a;
        bit<64>b;        
        bit<1024> f1;
        bit<1024> f2;
        bit<1024> y;
        bit<1024> z;
        bit<1024> x;
        bin.read(a,index+14);
        bin.read(b,index+31);
        f1=(bit<1024>)a*8129636310000000000;
        f2=(bit<1024>)b*9029552770000000000;
        y=f1+f2;
        //if absolute value of y > 80000000000000000 drop else forward
        z=y-80000000000000000;
        x=80000000000000000-y;
        #'b25','b27','b28'

        if (z>=0 || x>=0){ //this logic should give us 55% accuracy dropping untrusted traffic with the current setup
            flag=1;
        }else{
            flag=0;
        }

        Y.write(time,flag);

        time=time+1;
        t.write(0,time);
        //only if IPV4 the rule is applied. Therefore other packets will not be forwarded.
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();
        }
        
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {

    apply {

        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.d0);
        packet.emit(hdr.d1);
        packet.emit(hdr.d2);
        packet.emit(hdr.d3);
        packet.emit(hdr.d4);
        packet.emit(hdr.d5);
        packet.emit(hdr.d6);
        packet.emit(hdr.d7);
        packet.emit(hdr.d8);
        packet.emit(hdr.d9);
        packet.emit(hdr.d10);
        packet.emit(hdr.d11);
        packet.emit(hdr.d12);
        packet.emit(hdr.d13);
        packet.emit(hdr.d14);
        packet.emit(hdr.d15);
        packet.emit(hdr.d16);
        packet.emit(hdr.d17);
        packet.emit(hdr.d18);
        packet.emit(hdr.d19);
        packet.emit(hdr.d20);
        packet.emit(hdr.d21);
        packet.emit(hdr.d22);
        packet.emit(hdr.d23);
        packet.emit(hdr.d24);
        packet.emit(hdr.d25);
        packet.emit(hdr.d26);
        packet.emit(hdr.d27);
        packet.emit(hdr.d28);
        packet.emit(hdr.d29);
        packet.emit(hdr.d30);
        packet.emit(hdr.d31);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
