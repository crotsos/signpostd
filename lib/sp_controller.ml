(*
 * Copyright (c) 2005-2012 Anil Madhavapeddy <anil@recoil.org>
 *                         Charalampos Rotsos <cr409@cl.cam.ac.uk>
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


open Lwt
open Lwt_unix
open Printf


module OP = Openflow.Ofpacket
module OC = Openflow.Ofcontroller
module OE = OC.Event


(* TODO this the mapping is incorrect. the datapath must be moved to the key
 * of the hashtbl *)
type mac_switch = {
  addr: OP.eaddr; 
  switch: OP.datapath_id;
}

type pkt_in_cb_struct = {
  flow_match : OP.Match.t;
  cb: (state -> OP.datapath_id -> (OP.Port.t * int32 * Bitstring.t * OP.datapath_id) 
       -> unit Lwt.t);
}

type switch_state = {
(*   mutable mac_cache: (mac_switch, OP.Port.t) Hashtbl.t; *)
  mutable mac_cache: (OP.eaddr, OP.Port.t) Hashtbl.t; 
  mutable dpid: OP.datapath_id list;
  mutable of_ctrl: OC.t list;
  mutable pkt_in_cb_cache : pkt_in_cb_struct list;
  cb_register : (OP.Match.t, (OC.t -> OP.datapath_id -> 
                   OE.e -> unit Lwt.t) ) Hashtbl.t;
}

let resolve t = Lwt.on_success t (fun _ -> ())
let pp = Printf.printf
let sp = Printf.sprintf

let switch_data = { mac_cache = Hashtbl.create 0;
                    dpid = []; 
                    of_ctrl = [];
                    pkt_in_cb_cache = [];
                    cb_register = (Hashtbl.create 64);
                  } 

let preinstall_flows controller dpid port_id = 
  (* A few rules to reduce load on the control channel *)
  let flow_wild = OP.Wildcards.({
    in_port=false; dl_vlan=true; dl_src=true; dl_dst=false;
    dl_type=true; nw_proto=true; tp_dst=true; tp_src=true;
    nw_dst=(char_of_int 32); nw_src=(char_of_int 32);
    dl_vlan_pcp=true; nw_tos=true;}) in

  (* forward broadcast traffic to output port *)
  let flow = OP.Match.create_flow_match flow_wild 
               ~in_port:(OP.Port.int_of_port port_id)
               ~dl_dst:"\xff\xff\xff\xff\xff\xff" () in
  let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD ~priority:2 
              ~hard_timeout:0 ~idle_timeout:0 ~buffer_id:(-1) 
              [OP.Flow.Output(OP.Port.Local, 2000)] () in 
  let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
  lwt _ = OC.send_of_data controller dpid bs in

  (* forward incomming multicast dns to local port. *)
  let flow = OP.Match.create_flow_match flow_wild 
               ~in_port:(OP.Port.int_of_port port_id) 
               ~dl_dst:"\x01\x00\x5e\x00\x00\xfb" () in
  let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD ~priority:2
              ~hard_timeout:0 ~idle_timeout:0 ~buffer_id:(-1) 
              [OP.Flow.Output(OP.Port.Local, 2000)] () in 
  let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
  lwt _ = OC.send_of_data controller dpid bs in

  (* drop ipv6 traffic *)
  let flow_wild = OP.Wildcards.({
    in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
    dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
    nw_dst=(char_of_int 32); nw_src=(char_of_int 32);
    dl_vlan_pcp=true; nw_tos=true;}) in
  let flow = OP.Match.create_flow_match flow_wild 
               ~in_port:(OP.Port.int_of_port port_id)
               ~dl_type:0x86dd () in
  let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD ~priority:2
              ~hard_timeout:0 ~idle_timeout:0 ~buffer_id:(-1) 
(*               [OP.Flow.Output(OP.Port.No_port, 0)]  *)
              [] () in 
  let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
  lwt _ = OC.send_of_data controller dpid bs in

  (* forward multicast traffic to local port *)
  let flow_wild = OP.Wildcards.({
    in_port=false; dl_vlan=true; dl_src=true; dl_dst=false;
    dl_type=true; nw_proto=true; tp_dst=true; tp_src=true;
    nw_dst=(char_of_int 32); nw_src=(char_of_int 32);
    dl_vlan_pcp=true; nw_tos=true;}) in
  let flow = OP.Match.create_flow_match flow_wild 
               ~in_port:(OP.Port.int_of_port port_id)
               ~dl_dst:"\xd8\x5d\x4c\xf9\x8a\x9a" () in
  let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD ~priority:2
              ~idle_timeout:0 ~buffer_id:(-1) 
              [OP.Flow.Output(OP.Port.Local, 0)] () in 
  let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
  lwt _ = OC.send_of_data controller dpid bs in

  return ()

let preinstall_flows_eth0 controller dpid port_id = 
  let port = OP.Port.int_of_port port_id in 
  (* A few rules to reduce load on the control channel *)
  let flow_wild = OP.Wildcards.({
    in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
    dl_type=true; nw_proto=true; tp_dst=true; tp_src=true;
    nw_dst=(char_of_int 32); nw_src=(char_of_int 32);
    dl_vlan_pcp=true; nw_tos=true;}) in

  (* forward broadcast traffic to output port *)
  let flow = OP.Match.create_flow_match flow_wild ~in_port:port () in
  let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD ~priority:1
              ~hard_timeout:0 ~idle_timeout:0 ~buffer_id:(-1) 
              [OP.Flow.Output(OP.Port.Local, 2000)] () in 
  let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
  lwt _ = OC.send_of_data controller dpid bs in

  let flow = OP.Match.create_flow_match flow_wild 
               ~in_port:(OP.Port.int_of_port OP.Port.Local) () in
  let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD ~priority:1
              ~hard_timeout:0 ~idle_timeout:0 ~buffer_id:(-1) 
              [OP.Flow.Output(port_id, 2000)] () in 
  let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
  lwt _ = OC.send_of_data controller dpid bs in

  (* setup arp handling for 10.255.0.0/24 *)
    let arp_wild = OP.Wildcards.({
      in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 7); nw_src=(char_of_int 7);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let ip = Uri_IP.string_to_ipv4  "10.255.0.128" in
    let flow = OP.Match.create_flow_match arp_wild
                 ~in_port:(OP.Port.int_of_port OP.Port.Local) ~dl_type:0x0806
                 ~nw_src:ip ~nw_dst:ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:2 ~idle_timeout:0  ~hard_timeout:0
                ~buffer_id:(-1) [] () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in

    (* ARP handling *)
    let flow = OP.Match.create_flow_match arp_wild
                 ~in_port:(port) ~dl_type:0x0806
                 ~nw_src:ip ~nw_dst:ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:2 ~idle_timeout:0  ~hard_timeout:0
                ~buffer_id:(-1) [] () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in
      return ()


  let preinstall_flows_eth1 controller dpid port_id =
    let port = OP.Port.int_of_port port_id in 
    let ip = Uri_IP.string_to_ipv4 "10.255.0.0" in
    let flow_wild = OP.Wildcards.({
      in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 8); nw_src=(char_of_int 32);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match flow_wild 
                ~in_port:(OP.Port.int_of_port OP.Port.Local) 
                 ~dl_type:(0x0800) ~nw_dst:ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:2 ~idle_timeout:0 ~hard_timeout:0 
                ~buffer_id:(-1) [OP.Flow.Output(port_id, 2000);] () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
               (Lwt_bytes.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in

  (* setup arp handling for 10.255.0.0/24 *)
    let arp_wild = OP.Wildcards.({
      in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 8); nw_src=(char_of_int 8);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match arp_wild
                 ~in_port:(OP.Port.int_of_port OP.Port.Local) ~dl_type:0x0806
                 ~nw_src:ip ~nw_dst:ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:2 ~idle_timeout:0  ~hard_timeout:0
                ~buffer_id:(-1) [OP.Flow.Output(port_id,2000)] () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
               (Lwt_bytes.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in

    (* ARP handling *)
    let flow = OP.Match.create_flow_match arp_wild
                 ~in_port:(port) ~dl_type:0x0806
                 ~nw_src:ip ~nw_dst:ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:2 ~idle_timeout:0  ~hard_timeout:0
                ~buffer_id:(-1) [OP.Flow.Output(OP.Port.Local,2000)] () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
               (Lwt_bytes.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in
      return ()

let datapath_join_cb controller dpid evt =
  let (ports, dp) = 
    match evt with
      | OE.Datapath_join (c, ports) -> (ports, c)
      | _ -> invalid_arg "bogus datapath_join event match!" 
  in
    Printf.printf "[openflow] received %d ports\n%!" (List.length ports);
      (* I have the assumption that my initial setup contains only
      * local interfaces and not signpost *)
    List.iter ( 
      fun port -> 
        let _ = Net_cache.Port_cache.add_dev 
          port.OP.Port.name port.OP.Port.port_no in
          match port.OP.Port.port_no with
            | 0xfffe -> ()
            | _ ->
                Lwt.ignore_result (
                   preinstall_flows controller dpid 
                   (OP.Port.port_of_int port.OP.Port.port_no))
    ) ports;
    List.iter ( 
      fun port -> 
        let port_name = String.sub port.OP.Port.name 0 4 in 
          match port_name with
            | "eth0" ->
                printf "Port eth0 found \n";
                Lwt.ignore_result (preinstall_flows_eth0 controller
                dpid (OP.Port.port_of_int port.OP.Port.port_no))
            | "eth1" -> 
                printf "Port eth1 found \n";
                Lwt.ignore_result (preinstall_flows_eth1 controller
                dpid (OP.Port.port_of_int port.OP.Port.port_no))
            | _ -> ()
    ) ports;(*   lwt _ = preinstall_flows controller dpid OP.Port.Local ([]) in  *)
  switch_data.dpid <- switch_data.dpid @ [dp];
  return (pp "+ datapath:0x%012Lx\n%!" dp)

let port_status_cb controller dpid evt =
  let _ = 
    match evt with
      | OE.Port_status (OP.Port.ADD, port, _) -> 
          pp "[openflow] device added %s %d\n%!" 
            port.OP.Port.name port.OP.Port.port_no;
          lwt _ = preinstall_flows controller dpid 
             (OP.Port.port_of_int port.OP.Port.port_no) in
          Net_cache.Port_cache.add_dev port.OP.Port.name 
            port.OP.Port.port_no;
          return ()
      | OE.Port_status (OP.Port.DEL, port, _) -> 
          pp "[openflow] device removed %s %d\n%!" 
            port.OP.Port.name port.OP.Port.port_no;
          Net_cache.Port_cache.del_dev port.OP.Port.name;
          return ()
      | OE.Port_status (OP.Port.MOD, port, _) -> 
          pp "[openflow] device modilfied %s %d\n%!" 
            port.OP.Port.name port.OP.Port.port_no;
          return ()
      | _ -> invalid_arg "bogus datapath_join event match!" 
  in
    return ()

let req_count = (ref 0)

let register_handler flow cb =
  let controller = (List.hd switch_data.of_ctrl) in 
  let dpid = (List.hd switch_data.dpid)  in          
 let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
              ~idle_timeout:0 ~hard_timeout:0
             ~buffer_id:(-1) ~priority:100
              [OP.Flow.Output(OP.Port.Controller, 150)] () in 
 let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
            (Lwt_bytes.create 4096) in
 lwt _ = OC.send_of_data controller dpid bs in 
   return (Hashtbl.replace switch_data.cb_register flow cb)

let unregister_handler flow_def _ = 
(*   let pkt = OP.Flow_mod.create flow_def 0L OP.Flow_mod.DELETE_STRICT 
              ~buffer_id:(-1) ~priority:100
              [] () in 
  let controller = (List.hd switch_data.of_ctrl) in 
  let dpid = (List.hd switch_data.dpid)  in            
   let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
 lwt _ =  OC.send_of_data controller dpid bs in *)
  let lookup_flow flow _ =
    if (OP.Match.flow_match_compare flow_def flow
           flow.OP.Match.wildcards) then 
    Hashtbl.remove switch_data.cb_register flow
  in
    return (Hashtbl.iter lookup_flow switch_data.cb_register)


let add_entry_in_hashtbl mac_cache ix in_port = 
  if not (Hashtbl.mem mac_cache ix ) then
      Hashtbl.add mac_cache ix in_port
  else  
      Hashtbl.replace mac_cache ix in_port 

let switch_packet_in_cb controller dpid buffer_id m data in_port =
  (* save src mac address *)
  let ix = m.OP.Match.dl_src in
  let _ = match ix with
    | "\xff\xff\xff\xff\xff\xff" -> ()
    | _ -> (
        add_entry_in_hashtbl switch_data.mac_cache ix in_port;
        Net_cache.Port_cache.add_mac ix (OP.Port.int_of_port in_port)
      ) in 
    let (_, gw, _) = Net_cache.Routing.get_next_hop m.OP.Match.nw_src in
    let _ =
      (* Add only local devices *)
      if (gw = 0l) then 
        Net_cache.Arp_cache.add_mapping m.OP.Match.dl_src m.OP.Match.nw_src;
    in
      (* TODO need to write an arp parser in case an arp cache exists in the
      * network *)

  (* check if I know the output port in order to define what type of message
   * we need to send *)
    let ix = m.OP.Match.dl_dst in
      if ( (ix = "\xff\xff\xff\xff\xff\xff")
        || (not (Hashtbl.mem switch_data.mac_cache ix)) ) 
      then (
        let pkt = 
              OP.Packet_out.create ~buffer_id:buffer_id 
                ~actions:[ OP.(Flow.Output(Port.All , 2000))] 
                ~data:data ~in_port:in_port () 
        in
        let bs = OP.marshal_and_sub (OP.Packet_out.marshal_packet_out pkt) 
                   (Lwt_bytes.create 4096) in
          OC.send_of_data controller dpid bs
      ) else (
        let out_port = (Hashtbl.find switch_data.mac_cache ix) in
        let actions = [OP.Flow.Output(out_port, 2000)] in
        let pkt = OP.Flow_mod.create m 0_L OP.Flow_mod.ADD 
                    ~buffer_id:(Int32.to_int buffer_id)
                    actions () in 
        let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
                   (Lwt_bytes.create 4096) in
          OC.send_of_data controller dpid bs
      )

let lookup_flow of_match =
  (* Check the wilcard card table *)
  let ret_lst = ref [] in 
  let lookup_flow flow entry =
    if (OP.Match.flow_match_compare of_match flow
          flow.OP.Match.wildcards) then (
            ret_lst := (!ret_lst) @ [entry]
          )
  in
    Hashtbl.iter lookup_flow switch_data.cb_register;
    if (List.length (!ret_lst) == 0) then 
      None
    else ( 
(*
      Printf.printf "[openflow] Found callback for %s\n%!"
        (OP.Match.match_to_string of_match);
 *)
      Some(List.hd (!ret_lst))
    )

let packet_in_cb controller dpid evt =
  incr req_count;
  let (in_port, buffer_id, data, _) = 
    match evt with
      | OE.Packet_in (inp, buf, dat, dp) -> (inp, buf, dat, dp)
      | _ -> invalid_arg "bogus datapath_join event match!"
  in
  (* Parse Ethernet header *)
  let m = OP.Match.raw_packet_to_match in_port data in 
    match (lookup_flow m) with
      | Some (cb) -> cb controller dpid evt
      | None -> switch_packet_in_cb controller dpid  buffer_id m data in_port

let init controller = 
  if (not (List.mem controller switch_data.of_ctrl)) then
    switch_data.of_ctrl <- (([controller] @ switch_data.of_ctrl));
  OC.register_cb controller OE.DATAPATH_JOIN datapath_join_cb;
  OC.register_cb controller OE.PACKET_IN packet_in_cb;
  OC.register_cb controller OE.PORT_STATUS_CHANGE port_status_cb

let add_dev dev ip netmask =
  lwt _ = Lwt_unix.system ("ovs-vsctl add-port br0 " ^ dev) in 
  lwt _ = Lwt_unix.system (sp "ip addr add %s/%s dev br0" ip netmask) in
  return ()

let del_dev dev ip netmask =
  lwt _ = Lwt_unix.system ("ovs-vsctl del-port br0 " ^ dev) in 
  lwt _ = Lwt_unix.system (sp "ip addr del %s/%s dev br0" ip netmask) in
  return ()

let listen ?(port = 6633) mgr =
  let _ = pp "[openflow] Starting switch...\n%!" in 
    OC.listen mgr (None, port) init
