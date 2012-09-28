(* 
 * Copyright (c) 2012 Charalampos Rotsos <cr409@cl.cam.ac.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Cstruct
open Printf

module Checksum = struct 
  let ones_complement data = 
    let rec add count data =
      bitmatch data with
        | {value:16:littleendian; data:-1:bitstring} ->
            (value + (add (count + 1) data)) 
        | { value:8 } -> 
            (value)
        | { _ } -> 0
    in 
    let res = add 1 data in 
      if (res > 0xffff) then (
        ((lnot ((res land 0xffff) + (res lsr 16))) land 0xffff)
      ) else (
        ((lnot res) land 0xffff)
      )
end

(*
 * TCP/IP header informations. 
 * *)

cstruct ethernet {
  uint8_t        dst[6];
  uint8_t        src[6];
  uint16_t       ethertype
} as big_endian

cstruct ipv4 {
  uint8_t        hlen_version;
  uint8_t        tos;
  uint16_t       len;
  uint16_t       id;
  uint16_t       off;
  uint8_t        ttl;
  uint8_t        proto;
  uint16_t       csum;
  uint32_t       src; 
  uint32_t       dst
} as big_endian

cstruct tcpv4 {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t sequence;
  uint32_t ack_number;
  uint8_t  dataoff;
  uint8_t  flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urg_ptr
} as big_endian

let get_fin buf = ((get_uint8 buf 13) land (1 lsl 0)) > 0
let get_syn buf = ((get_uint8 buf 13) land (1 lsl 1)) > 0
let get_rst buf = ((get_uint8 buf 13) land (1 lsl 2)) > 0
let get_psh buf = ((get_uint8 buf 13) land (1 lsl 3)) > 0
let get_ack buf = ((get_uint8 buf 13) land (1 lsl 4)) > 0
let get_urg buf = ((get_uint8 buf 13) land (1 lsl 5)) > 0
let get_ece buf = ((get_uint8 buf 13) land (1 lsl 6)) > 0
let get_cwr buf = ((get_uint8 buf 13) land (1 lsl 7)) > 0

cstruct pseudo_header {
  uint32_t src;
  uint32_t dst;
  uint8_t res;
  uint8_t proto;
  uint16_t len
} as big_endian 




type tcp_flags_struct = {
    urg:bool; ack: bool; 
    psh:bool; rst:bool; 
    syn:bool; fin:bool;}

let get_tcp_packet_payload bits =
  let bits = shift bits sizeof_ethernet in 
  let ip_len = ((get_ipv4_hlen_version bits) land 0xf0) lsl 4 in
  let bits = shift bits (ip_len * 8) in
  let tcp_len = ((get_tcpv4_dataoff bits) land 0xf0) lsl 4 in
    shift bits (tcp_len * 4)

let get_tcp_flags bits = 
  let bits = shift bits sizeof_ethernet in 
  let ip_len = ((get_ipv4_hlen_version bits) land 0xf0) lsl 4 in
  let bits = shift bits (ip_len * 8) in
    {urg=(get_urg bits); ack=(get_ack bits); psh=(get_psh bits); 
     rst=(get_rst bits); syn=(get_syn bits); fin=(get_fin bits);}

let get_tcp_sn bits = 
  let bits = shift bits sizeof_ethernet in 
  let ip_len = ((get_ipv4_hlen_version bits) land 0xf0) lsl 4 in
  let bits = shift bits (ip_len * 8) in
    get_tcpv4_sequence bits
  
let get_tcp_ack bits = 
  let bits = shift bits sizeof_ethernet in 
  let ip_len = ((get_ipv4_hlen_version bits) land 0xf0) lsl 4 in
  let bits = shift bits (ip_len * 8) in
    get_tcpv4_sequence bits
 
  
(*
 * generate a tcp syn packet
* *)
let gen_server_syn data new_isn local_mac gw_mac 
      local_ip gw_ip new_dst_port = 
    bitmatch data with 
      | {_:48:bitstring; _:48:bitstring; header:20:bitstring; 
         ihl:4;  tos:8; tlen:16; ipid:16; flags:3; fragoff:13;
         ttl:8; proto:8; _:16; nw_src:32; nw_dst:32;
         header2:(ihl-5)*32:bitstring;src_port:16; dst_port:16; isn:32; 
         header3:64:bitstring; checksum:16; tcp_body:-1:bitstring } ->
            let ip_chk = 
              Checksum.ones_complement 
                (BITSTRING {4:4; ihl:4; tos:8; tlen:16; ipid:16; 
                            flags:3; fragoff:13; ttl:8; proto:8; 0:16; 
                            gw_ip:32; local_ip:32}) in 
            let tcp_chk = 
                (Checksum.ones_complement 
                   (BITSTRING{gw_ip:32; local_ip:32; 0:8; 6:8; 
                      (((Bitstring.bitstring_length tcp_body)/8) + 18):16; 
                       src_port:16; new_dst_port:16; new_isn:32; 
                       header3:64:bitstring; 0:16;                     
                       tcp_body:(Bitstring.bitstring_length tcp_body):bitstring})) in
              BITSTRING{local_mac:48:string; gw_mac:48:string;
                        header:20:bitstring; ihl:4; tos:8; tlen:16; 
                        ipid:16; flags:3; fragoff:13; ttl:8; proto:8; 
                        ip_chk:16:littleendian; gw_ip:32; local_ip:32; 
                        header2:(ihl-5)*32:bitstring; src_port:16; new_dst_port:16; 
                        new_isn:32; header3:64:bitstring;  tcp_chk:16:littleendian;
                        tcp_body:(Bitstring.bitstring_length tcp_body):bitstring}
      | { _ } -> invalid_arg("gen_server_syn input packet is not TCP") 


(* 
 * generate an ack packet with any data
* *)
let gen_tcp_syn isn src_mac dst_mac src_ip dst_ip 
      src_port dst_port win =
  let eth_hdr = 
      BITSTRING{dst_mac:48:string; src_mac:48:string; 
                0x0800:16} in 
  let ip_chk = Checksum.ones_complement 
                 (BITSTRING{ 4:4; 5:4; 0:8; 40:16; 0:16; 0:3; 
                             0:13; 64:8; 6:8; 0:16; src_ip:32; 
                             dst_ip:32}) in
  let ipv4_hdr = 
    BITSTRING { 4:4; 5:4; 0:8; 40:16; 0:16; 0:3; 0:13; 64:8; 
                6:8; ip_chk:16:littleendian; src_ip:32; dst_ip:32} in
  let tcp_chk = 
    (Checksum.ones_complement (
      BITSTRING{src_ip:32; dst_ip:32; 0:8; 6:8; 20:16; src_port:16; 
                dst_port:16; isn:32;  0l:32; 5:4; 0:6; false:1; 
                false:1; false:1; false:1; true:1; false:1; win:16;
                0:16; 0:16})) in 
  let tcp_hdr = 
    BITSTRING {src_port:16; dst_port:16; isn:32; 0l:32; 5:4;
               0:6; false:1; false:1; false:1; false:1; true:1; 
               false:1; win:16; tcp_chk:16:littleendian;0:16} in  
    Bitstring.concat [eth_hdr; ipv4_hdr; tcp_hdr;] 


(* 
 * generate an ack packet with any data
* *)
let gen_server_ack isn ack local_mac gw_mac gw_ip local_ip 
      dst_port src_port win =
  let eth_hdr = 
      BITSTRING{local_mac:48:string; gw_mac:48:string; 
                0x0800:16} in 
  let ip_chk = Checksum.ones_complement 
                 (BITSTRING{ 4:4; 5:4; 0:8; 40:16; 0:16; 0:3; 
                             0:13; 64:8; 6:8; 0:16; gw_ip:32; 
                             local_ip:32}) in
  let ipv4_hdr = 
    BITSTRING { 4:4; 5:4; 0:8; 40:16; 0:16; 0:3; 0:13; 64:8; 
                6:8; ip_chk:16:littleendian; gw_ip:32; local_ip:32} in
  let tcp_chk = 
    (Checksum.ones_complement (
      BITSTRING{gw_ip:32; local_ip:32; 0:8; 6:8; 20:16; src_port:16; 
                dst_port:16; isn:32;  ack:32; 5:4; 0:6; false:1; 
                true:1; false:1; false:1; false:1; false:1; win:16;
                0:16; 0:16})) in 
  let tcp_hdr = 
    BITSTRING {src_port:16; dst_port:16; isn:32; ack:32; 5:4;
               0:6; false:1; true:1; false:1; false:1; false:1; 
               false:1; win:16; tcp_chk:16:littleendian;0:16} in  
    Bitstring.concat [eth_hdr; ipv4_hdr; tcp_hdr;] 


(* 
* Generate a syn+ack packet 
* *)
let gen_server_synack isn ack local_mac gw_mac src_ip local_ip 
      dst_port src_port =
  let window = 0xffff in 
  let eth_hdr = BITSTRING{local_mac:48:string; gw_mac:48:string; 0x0800:16} in 
  let ip_chk = Checksum.ones_complement (BITSTRING { 4:4; 5:4; 0:8; 40:16; 0:16; 0:3; 
        0:13; 64:8; 6:8; 0:16; src_ip:32; local_ip:32}) in
  let ipv4_hdr = BITSTRING { 4:4; 5:4; 0:8; 40:16; 0:16; 0:3; 0:13; 64:8; 6:8; 
                             ip_chk:16:littleendian; src_ip:32; local_ip:32} in
  let tcp_chk = 
    (Checksum.ones_complement (BITSTRING{src_ip:32; local_ip:32; 0:8; 6:8; 
        20:16; src_port:16; dst_port:16; isn:32;  ack:32; 5:4;
        0:6; false:1; true:1; false:1; false:1; true:1; false:1; window:16;0:16;
        0:16})) in 
  let tcp_hdr = BITSTRING {src_port:16; dst_port:16; isn:32; ack:32; 5:4;
        0:6; false:1; true:1; false:1; false:1; true:1; false:1; 
        window:16; tcp_chk:16:littleendian; 0:16 } in  
    Bitstring.concat [eth_hdr; ipv4_hdr; tcp_hdr;] 

(* 
* Generate a tcp packet with data 
* *)
let gen_tcp_data_pkt isn ack local_mac gw_mac gw_ip local_ip 
      dst_port src_port data =
  let eth_hdr = BITSTRING{local_mac:48:string; gw_mac:48:string; 0x0800:16} in 
  let ip_chk = Checksum.ones_complement (BITSTRING { 4:4; 5:4; 0:8; 
        (40 + ((Bitstring.bitstring_length data)/8)):16; 0:16; 0:3; 
        0:13; 64:8; 6:8; 0:16; gw_ip:32; local_ip:32}) in
  let ipv4_hdr = BITSTRING { 4:4; 5:4; 0:8; 
    (40 + ((Bitstring.bitstring_length data)/8)):16; 0:16; 0:3; 0:13; 
    64:8; 6:8; ip_chk:16:littleendian; gw_ip:32; local_ip:32} in
  let tcp_chk = 
    (Checksum.ones_complement (BITSTRING{gw_ip:32; local_ip:32; 0:8; 6:8; 
        (20+((Bitstring.bitstring_length data)/8)):16; 
        src_port:16; dst_port:16; isn:32;  ack:32; 5:4; 0:6; 
        false:1; true:1; false:1; false:1; false:1; false:1; 0xffff:16;0:16; 0:16; 
        data:(Bitstring.bitstring_length data):bitstring})) in 
  let tcp_hdr = BITSTRING {src_port:16; dst_port:16; isn:32; ack:32; 5:4;
        0:6; false:1; true:1; false:1; false:1; false:1; false:1; 
        0xffff:16; tcp_chk:16:littleendian; 0:16;
        data:(Bitstring.bitstring_length data):bitstring} in  
    Bitstring.concat [eth_hdr; ipv4_hdr; tcp_hdr;]

(* 
* Generate a udp packet with data 
* *)
let gen_udp_pkt src_mac dst_mac src_ip dst_ip 
      src_port dst_port data =
  let eth_hdr = BITSTRING{dst_mac:48:string;src_mac:48:string; 
                          0x0800:16} in 
  let ip_chk = Checksum.ones_complement (BITSTRING { 4:4; 5:4; 0:8; 
        (28 + ((Bitstring.bitstring_length data)/8)):16; 0:16; 0:3; 
        0:13; 64:8; 17:8; 0:16; src_ip:32; dst_ip:32}) in
  let ipv4_hdr = BITSTRING { 4:4; 5:4; 0:8; 
    (28 + ((Bitstring.bitstring_length data)/8)):16; 0:16; 0:3; 0:13; 
    64:8; 17:8; ip_chk:16:littleendian; src_ip:32; dst_ip:32} in
  let udp_hdr = BITSTRING {src_port:16; dst_port:16;
        (8+((Bitstring.bitstring_length data)/8)):16; 0:16;
        data:(Bitstring.bitstring_length data):bitstring} in  
    Bitstring.concat [eth_hdr; ipv4_hdr; udp_hdr;] 
