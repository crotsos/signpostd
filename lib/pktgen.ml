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
  let ones_complement bits offset len = 
    let rec add bits offset len =
      match len with
        | 1 -> get_uint8 bits offset
        | 2 -> LE.get_uint16 bits offset
        | _ -> 
            let value = LE.get_uint16 bits offset in 
              value + (add bits (offset + 2) (len -2) ) 
    in 
    let res = add bits offset len in 
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

let set_fin buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 0))
let set_syn buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 1))
let set_rst buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 2))
let set_psh buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 3))
let set_ack buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 4))
let set_urg buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 5))
let set_ece buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 6))
let set_cwr buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 7))

let get_fin buf = ((get_uint8 buf 13) land (1 lsl 0)) > 0
let get_syn buf = ((get_uint8 buf 13) land (1 lsl 1)) > 0
let get_rst buf = ((get_uint8 buf 13) land (1 lsl 2)) > 0
let get_psh buf = ((get_uint8 buf 13) land (1 lsl 3)) > 0
let get_ack buf = ((get_uint8 buf 13) land (1 lsl 4)) > 0
let get_urg buf = ((get_uint8 buf 13) land (1 lsl 5)) > 0
let get_ece buf = ((get_uint8 buf 13) land (1 lsl 6)) > 0
let get_cwr buf = ((get_uint8 buf 13) land (1 lsl 7)) > 0

cstruct udpv4 {
  uint16_t source_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum
} as big_endian

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
  let _ = set_ethernet_dst local_mac 0 data in 
  let _ = set_ethernet_src gw_mac 0 data in 
  let bits = shift data sizeof_ethernet in
  let ip_len = ((get_ipv4_hlen_version bits) land 0xf0) lsl 4 in 
  let _ = set_ipv4_src bits gw_ip in 
  let _ = set_ipv4_dst bits local_ip in 
  let _ = set_ipv4_csum bits 0 in 
  let _ = set_ipv4_csum bits 
            (Checksum.ones_complement bits 0 
               (ip_len * 4)) in 
  let bits = shift bits sizeof_ipv4 in
  let _ = set_tcpv4_sequence bits new_isn in 
  let _ = set_tcpv4_dst_port bits new_dst_port in 
  let _ = set_tcpv4_checksum bits 0 in 
  let tcp_csm_buf = Lwt_bytes.create 
                      (sizeof_pseudo_header + 
                       (Cstruct.len bits) ) in
  let _ = set_pseudo_header_src tcp_csm_buf gw_ip in 
  let _ = set_pseudo_header_dst tcp_csm_buf local_ip in 
  let _ = set_pseudo_header_res tcp_csm_buf 0 in 
  let _ = set_pseudo_header_proto tcp_csm_buf 6 in 
  let _ = set_pseudo_header_len tcp_csm_buf (Cstruct.len bits) in
  let _ = Cstruct.blit_buffer tcp_csm_buf sizeof_pseudo_header 
            bits 0 (Cstruct.len bits) in 
  let _ = set_tcpv4_checksum bits 
            (Checksum.ones_complement  tcp_csm_buf 
               0 (Cstruct.len tcp_csm_buf) ) in 
    data
(* 
 * generate an ack packet with any data
* *)
let gen_tcp_packet isn ack src_mac dst_mac src_ip dst_ip 
      src_port dst_port flags win data =
  let ret = Lwt_bytes.create 2048 in

  (* First create the tcp header in order to avoid allocating an 
  * additional buffer *)
  let tcp_csm_hdr = shift ret (sizeof_ethernet + sizeof_ipv4 - 
                         sizeof_pseudo_header + (Cstruct.len data)) in 
  let _ = set_pseudo_header_src tcp_csm_hdr src_ip in
  let _ = set_pseudo_header_dst tcp_csm_hdr dst_ip in 
  let _ = set_pseudo_header_res tcp_csm_hdr 0 in 
  let _ = set_pseudo_header_proto tcp_csm_hdr 6 in 
  let _ = set_pseudo_header_len tcp_csm_hdr 20 in 
  let bits = shift tcp_csm_hdr sizeof_pseudo_header in 
  let _ = set_tcpv4_src_port bits src_port in 
  let _ = set_tcpv4_dst_port bits dst_port in 
  let _ = set_tcpv4_sequence bits isn in 
  let _ = set_tcpv4_ack_number bits ack in 
  let _ = set_tcpv4_dataoff bits (5 lsl 4) in 
  let _ = set_tcpv4_flags bits 0 in 
  let _ = if(flags.urg) then set_urg bits in
  let _ = if(flags.ack) then set_ack bits in
  let _ = if(flags.psh) then set_psh bits in
  let _ = if(flags.rst) then set_rst bits in
  let _ = if(flags.syn) then set_syn bits in
  let _ = if(flags.fin) then set_fin bits in
  let _ = set_tcpv4_window bits win in
  let _ = set_tcpv4_urg_ptr bits 0 in 
  let _ = set_tcpv4_checksum bits 0 in
  let _ = Cstruct.blit_buffer data 0 tcp_csm_hdr sizeof_tcpv4 
            (Cstruct.len data) in 
  let _ = set_tcpv4_checksum bits 
            (Checksum.ones_complement tcp_csm_hdr 0 
            (sizeof_pseudo_header + sizeof_tcpv4 + 
            (Cstruct.len data) ) ) in 
  let bits = ret in 
  let _ = set_ethernet_dst dst_mac 0 bits in 
  let _ = set_ethernet_src src_mac 0 bits in 
  let _ = set_ethernet_ethertype bits 0x0800 in 
  let bits = shift bits sizeof_ethernet in 
  let _ = set_ipv4_hlen_version bits 0x45 in 
  let _ = set_ipv4_tos bits 0 in 
  let _ = set_ipv4_len bits 
  (sizeof_ipv4 + sizeof_tcpv4 + (Cstruct.len data)) in 
  let _ = set_ipv4_id bits 0 in 
  let _ = set_ipv4_off bits 0 in
  let _ = set_ipv4_ttl bits 64 in 
  let _ = set_ipv4_proto bits 6 in 
  let _ = set_ipv4_csum bits 0 in 
  let _ = set_ipv4_src bits src_ip in 
  let _ = set_ipv4_dst bits dst_ip in 
  let _ = set_ipv4_csum bits 
    (Checksum.ones_complement bits 0 sizeof_ipv4) in 
    sub ret 0 
      (sizeof_ethernet + sizeof_ipv4 + sizeof_tcpv4 + 
      (Cstruct.len data)) 

let gen_udp_pkt src_mac dst_mac src_ip dst_ip 
      src_port dst_port data =
  let ret = Lwt_bytes.create 2048 in
  let bits = ret in 
  let _ = set_ethernet_dst dst_mac 0 bits in 
  let _ = set_ethernet_src src_mac 0 bits in 
  let _ = set_ethernet_ethertype bits 0x0800 in 
  let bits = shift bits sizeof_ethernet in 
  let _ = set_ipv4_hlen_version bits 0x45 in 
  let _ = set_ipv4_tos bits 0 in 
  let _ = set_ipv4_len bits 
  (sizeof_ipv4 + sizeof_udpv4 + (Cstruct.len data)) in 
  let _ = set_ipv4_id bits 0 in 
  let _ = set_ipv4_off bits 0 in
  let _ = set_ipv4_ttl bits 64 in 
  let _ = set_ipv4_proto bits 6 in 
  let _ = set_ipv4_csum bits 0 in 
  let _ = set_ipv4_src bits src_ip in 
  let _ = set_ipv4_dst bits dst_ip in 
  let _ = set_ipv4_csum bits 
    (Checksum.ones_complement bits 0 sizeof_ipv4) in 
  let bits = shift bits sizeof_ipv4 in
  let _ = set_udpv4_source_port bits src_port in 
  let _ = set_udpv4_dest_port bits dst_port in 
  let _ = set_udpv4_length bits 
            (sizeof_udpv4 + (Cstruct.len data)) in
  let _ = set_udpv4_checksum bits 0 in 
  let bits = shift bits sizeof_udpv4 in 
  let _ = Cstruct.blit_buffer data 0 bits 0 (Cstruct.len data) in 
    Cstruct.sub ret 0 (sizeof_ethernet + sizeof_ipv4 + sizeof_udpv4 
                       + (Cstruct.len data)) 

let gen_tcp_syn isn src_mac dst_mac src_ip dst_ip 
      src_port dst_port win =
  gen_tcp_packet isn 0l src_mac dst_mac src_ip dst_ip 
    src_port dst_port {urg=false; ack=false; psh=false; 
      rst=false; syn=true; fin=false; } win  
    (Lwt_bytes.create 0) 


(* 
 * generate an ack packet with any data
* *)
let gen_server_ack isn ack local_mac gw_mac gw_ip local_ip 
      dst_port src_port win =
  gen_tcp_packet isn ack local_mac gw_mac gw_ip local_ip 
    src_port dst_port 
    {urg=false; ack=true; psh=false; 
     rst=false; syn=false; fin=false; } win 
    (Lwt_bytes.create 0) 

(*  let eth_hdr = 
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
 *)

(* 
* Generate a syn+ack packet 
* *)
let gen_server_synack isn ack local_mac gw_mac src_ip local_ip 
      dst_port src_port =
  gen_tcp_packet isn ack local_mac gw_mac src_ip local_ip 
    src_port dst_port {urg=false; ack=true; psh=false; 
                       rst=false; syn=false; fin=false; } 0xffff 
    (Lwt_bytes.create 0) 

(*  let window = 0xffff in 
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
    Bitstring.concat [eth_hdr; ipv4_hdr; tcp_hdr;] *)

(* 
* Generate a tcp packet with data 
* *)
let gen_tcp_data_pkt isn ack local_mac gw_mac gw_ip local_ip 
      dst_port src_port data =
  gen_tcp_packet isn ack local_mac gw_mac gw_ip local_ip 
    src_port dst_port {urg=false; ack=true; psh=false; 
                       rst=false; syn=false; fin=false; } 0xffff 
    data 

(*  let eth_hdr = BITSTRING{local_mac:48:string; gw_mac:48:string; 0x0800:16} in 
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
    Bitstring.concat [eth_hdr; ipv4_hdr; tcp_hdr;] *)

(* 
* Generate a udp packet with data 
* *)

