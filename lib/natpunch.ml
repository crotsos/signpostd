(*
 * Copyright (c) 2012 Charalampos Rotsos <cr409@cl.cam.ac.uk>
 *
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
open Lwt_list
open Printf

module OP = Openflow.Packet
module OC = Openflow.Controller

let resolve t = Lwt.on_success t (fun _ -> ())
let pp = Printf.printf
let sp = Printf.sprintf
let ep = Printf.eprintf

let tactic_priority = 5

module Manager = struct
  exception NatpunchError of string
  exception MissingNatpunchArgumentError

  (*********************************************************
   *                  Tactic state
   *********************************************************)
  (* local state of the tactic*)
  type conn_type = {
    name: string;
    public_ip: int32;
    sp_ip: int32;
    conn_id: int;
  }

  (*
   * State requireed to map appropriately signpost ip and ports to 
   * natpancj state  *)
  type natpanch_state_type = {
    (* Map an outging port to an outgoing ip? *)
    map_port_ip : (int, int32) Hashtbl.t;
    (* storing with whom I am connected *)
    conns : (string, conn_type) Hashtbl.t;
  }

  let natpanch_state = {
    map_port_ip=(Hashtbl.create 1000);
    conns = (Hashtbl.create 64);
  }

  let node_of_sp_ip sp_ip = 
    let res = 
      Hashtbl.fold (fun name st ret -> 
                      if (st.sp_ip = sp_ip) then 
                        Some(name)
                      else 
                        ret ) natpanch_state.conns None 
    in
      match (res) with
        |Some(name) -> name
        |None -> raise Not_found
  let node_of_public_ip public_ip = 
    let res = 
      Hashtbl.fold (fun name st ret -> 
                      if (st.public_ip = public_ip) then 
                        Some(name)
                      else 
                        ret ) natpanch_state.conns None 
    in
      match (res) with
        |Some(name) -> name
        |None -> raise Not_found


  (**********************************************************
   *                  Init methods
   **********************************************************)

  (*
   * TODO: this event should be implemented at some point in order to clear any
   * pending state in the system os. 
   * *)
  let init_module () = 
    return ()

  let destroy_module () = 
    init_module ()

(*
 * Openflow message control
 * *)

  let filter_incoming_rst_packet controller dpid evt =
    try_lwt
      let (pkt, port, buffer_id) = match evt with 
        | OC.Event.Packet_in(port, buffer_id, pkt, _) ->
                (pkt,port,buffer_id)
        | _ -> ep "Unknown event";failwith "Invalid of action"
      in
      let m = OP.Match.parse_from_raw_packet port pkt in
        (* Ignore rst packets generated by nat if forwarding is not 
        * setup yet *)
      let flags = Tcp.get_tcp_flags pkt in
        match flags.Tcp.rst with 
          | true -> return ()
          | false -> (
              printf "[natpunch] Received an incomin non rst packet\n%!";
              let node = Hashtbl.find natpanch_state.conns 
                           (node_of_public_ip m.OP.Match.nw_src) in 
(*
           let actions = [OP.Flow.Set_dl_src("\xfe\xff\xff\xff\xff\xff");
                         OP.Flow.Set_nw_dst(local_sp_ip);
                         OP.Flow.Set_nw_src(remote_sp_ip);
                         OP.Flow.Output((OP.Port.Local), 2000);] in
          let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD
                      ~buffer_id:(-1) actions () in
          let bs = OP.Flow_mod.flow_mod_to_bitstring pkt in
          lwt _ = OC.send_of_data controller dpid bs in
 *)
              let actions = [
                OP.Flow.Set_dl_src("\xfe\xff\xff\xff\xff\xff");
                OP.Flow.Set_nw_dst((Nodes.get_local_sp_ip ())); 
                OP.Flow.Set_nw_src(node.sp_ip);
                OP.Flow.Output(OP.Port.Local, 2000);] in
              let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD ~priority:110 
                          ~buffer_id:(Int32.to_int buffer_id) actions () in 
              let bs = OP.Flow_mod.flow_mod_to_bitstring pkt in
                OC.send_of_data controller dpid bs)
    with exn ->
      ep "[natpanch] Error: %s\n%!" (Printexc.to_string exn);
      return ()

  let rec filter_outgoing_tcp_packet controller dpid evt =
    try_lwt
      let (pkt, port, buffer_id) = match evt with 
        | OC.Event.Packet_in(port, buffer_id, pkt, _) ->
                (pkt,port,buffer_id)
        | _ -> ep "Unknown event";failwith "Invalid of action"
      in
      let m = OP.Match.parse_from_raw_packet port pkt in
        (* Ignore rst packets generated by nat if forwarding is not 
        * setup yet *)
      let flow = OP.Match.parse_from_raw_packet port pkt in
      let isn = Tcp.get_tcp_sn pkt in
      let ack = Tcp.get_tcp_ack pkt in
      let flags = Tcp.get_tcp_flags pkt in

      (* TODO: dest port should be discovered from state *)
      let Some(port) = Net_cache.Port_cache.dev_to_port_id 
                         Config.net_intf in  
      let port = OP.Port.port_of_int port in
        match (flags.Tcp.rst, flags.Tcp.syn, flags.Tcp.ack) with 
          (* Not sure if this is required *)
          | (true, _, _) -> return ()
          (* On the client side filter syn+ack packet to avoid the NAT
          * terminating my state *)
          | (false, true, true) -> begin
              printf "[natpanch] Got synack packet\n%!";

              (* map to remote ip address. If no ip address was found simply
               * disregard the packet *)
              let node = Hashtbl.find natpanch_state.conns 
                           (node_of_sp_ip flow.OP.Match.nw_dst) in 
              let local_ip = Net_cache.Routing.get_next_hop_local_ip node.public_ip in 
              let Some(local_mac) = (Net_cache.Arp_cache.mac_of_ip local_ip) in 
              let Some(gw_mac) = (Net_cache.Arp_cache.get_next_hop_mac node.public_ip) in 

              let actions = [
                OP.Flow.Set_nw_src(local_ip);
                OP.Flow.Set_dl_dst(gw_mac);
                OP.Flow.Set_nw_dst(node.public_ip);
                OP.Flow.Output(port, 2000);] in
              let wild = OP.Wildcards.({in_port=false; dl_vlan=true; dl_src=true; 
                      dl_dst=true; dl_type=false; nw_proto=false; 
                      tp_src=false; tp_dst=false; nw_src=(char_of_int 0); 
                      nw_dst=(char_of_int 0); dl_vlan_pcp=true; nw_tos=true;}) in
              let m = OP.Match.(
                {wildcards=wild; in_port=OP.Port.Local;
                 dl_dst="\xfe\xff\xff\xff\xff\xff"; dl_src=local_mac;
                 dl_vlan=0xffff;dl_vlan_pcp=(char_of_int 0);dl_type=0x0800; 
                 nw_src=(Nodes.get_local_sp_ip ()); nw_dst=node.sp_ip;
                 nw_tos=(char_of_int 0); nw_proto=(char_of_int 6);
                 tp_src=flow.OP.Match.tp_src; tp_dst=flow.OP.Match.tp_dst;}) in
(*              lwt _ = Sp_controller.unregister_handler m filter_outgoing_tcp_packet in 
              let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD
                      ~buffer_id:(-1) actions () in
              let bs = OP.Flow_mod.flow_mod_to_bitstring pkt in
              lwt _ = OC.send_of_data controller dpid bs in *)

              (* Notify the signpost server in order to spoof packets *)
              let rpc =
                (Rpc.create_tactic_notification "natpanch" Rpc.CONNECT 
                   "client_connect" 
                   [(Nodes.get_local_name ());node.name;
                    (string_of_int m.OP.Match.tp_src); 
                    (string_of_int m.OP.Match.tp_dst);
                    (Int32.to_string isn);(Int32.to_string ack);]) in
                Nodes.send_to_server rpc          
            end
      (* This should execute on the tcp client. capture the syn packet isn and
      * send to the cloud  *)
      |(false, true, false) -> 
          (* map to remote ip address. If no ip address was found simply
           * disregard the packet *)
          printf "Got a syn packet\n%!";
          let node = Hashtbl.find natpanch_state.conns 
                       (node_of_sp_ip flow.OP.Match.nw_dst) in  
          (*
           * setup icoming flow before any packets arrive
           * *)
          let nw_dst = node.public_ip in
          let local_ip = Net_cache.Routing.get_next_hop_local_ip node.public_ip in 
          let Some(local_mac) = (Net_cache.Arp_cache.mac_of_ip local_ip) in 
          let Some(gw_mac) = (Net_cache.Arp_cache.get_next_hop_mac node.public_ip) in 

          (* setup flow from the internet to the local host.  
          * *)
          let wild = OP.Wildcards.({in_port=false; dl_vlan=true; dl_src=true; 
                      dl_dst=true; dl_type=false; nw_proto=false; 
                      tp_src=false; tp_dst=false; nw_src=(char_of_int 0); 
                      nw_dst=(char_of_int 0); dl_vlan_pcp=true; nw_tos=true;}) in
          let m = OP.Match.(
            {wildcards=wild; in_port=port; 
             dl_vlan=0xffff; dl_vlan_pcp=(char_of_int 0); dl_type=0x0800; 
             nw_tos=(char_of_int 0); dl_src=gw_mac; dl_dst=local_mac;
             nw_src=nw_dst; nw_dst=local_ip; tp_src=flow.OP.Match.tp_dst;
             tp_dst=flow.OP.Match.tp_src; nw_proto=(char_of_int 6); }) in

          let actions = [
            OP.Flow.Set_dl_src("\xfe\xff\xff\xff\xff\xff");
            OP.Flow.Set_nw_src(flow.OP.Match.nw_dst);
            OP.Flow.Set_nw_dst(flow.OP.Match.nw_src); 
            OP.Flow.Output(OP.Port.Local, 2000);] in     
          let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD 
                      ~priority:200 
                      ~buffer_id:(-1) actions () in 

          let bs = OP.Flow_mod.flow_mod_to_bitstring pkt in
          lwt _ = OC.send_of_data controller dpid bs in 
        (* Store the local ip so we know to whom it belongs when we receive
            * a packet
            * TODO: do I really need this state? *)
            Hashtbl.replace natpanch_state.map_port_ip flow.OP.Match.tp_src 
              flow.OP.Match.nw_dst;
           (* setup flow from the local node to the internet  *)
           let wild = OP.Wildcards.({in_port=false; dl_vlan=true; dl_src=true; 
                      dl_dst=true; dl_type=false; nw_proto=false; 
                      tp_src=false; tp_dst=false; nw_src=(char_of_int 0); 
                      nw_dst=(char_of_int 0); dl_vlan_pcp=true; nw_tos=true;}) in
          let m = OP.Match.(
            {wildcards=wild; in_port=flow.OP.Match.in_port; 
             dl_vlan=flow.OP.Match.dl_vlan; dl_vlan_pcp=flow.OP.Match.dl_vlan_pcp; 
             dl_type=flow.OP.Match.dl_type; 
             nw_tos=flow.OP.Match.nw_tos; dl_src=flow.OP.Match.dl_src; 
             dl_dst=flow.OP.Match.dl_dst;
             nw_src=flow.OP.Match.nw_src; nw_dst=flow.OP.Match.nw_dst; 
             tp_src=flow.OP.Match.tp_src;
             tp_dst=flow.OP.Match.tp_dst; nw_proto=flow.OP.Match.nw_proto; }) in

         let actions = [
            OP.Flow.Set_dl_dst(gw_mac);
            OP.Flow.Set_nw_src(local_ip);
            OP.Flow.Set_nw_dst(node.public_ip); 
            OP.Flow.Output( port, 2000);] in
          let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD ~priority:200 
                      ~buffer_id:(Int32.to_int buffer_id) actions () in 
          let bs = OP.Flow_mod.flow_mod_to_bitstring pkt in
          lwt _ = OC.send_of_data controller dpid bs in
(*           lwt _ = Lwt.sleep 0.1 in       *)

            (*Inform the cloud server in order to propagate it over the control
            * channel *)
            let rpc =
              (Rpc.create_tactic_notification "natpanch" Rpc.CONNECT 
                 "server_connect" 
                 [node.name;(Nodes.get_local_name ()); 
                  (Uri_IP.ipv4_to_string m.OP.Match.nw_src);
                  (string_of_int m.OP.Match.tp_dst); 
                  (string_of_int m.OP.Match.tp_src); (string_of_int node.conn_id);
                  (Int32.to_string isn);(Int32.to_string ack);]) in
              Nodes.send_to_server rpc

          (* This is better , but the fucking armel doesn't respect buffer_id*)
(*           lwt _ = Sp_controller.register_handler m filter_incoming_rst_packet
 *           in *)
      | (false, false, _) -> 
          printf "Got non rst non syn packet\n%!";
          (* map to remote ip address. If no ip address was found simply
           * disregard the packet *)
          let node = Hashtbl.find natpanch_state.conns 
                       (node_of_sp_ip flow.OP.Match.nw_dst) in  
          (*
           * setup icoming flow before any packets arrive
           * *)
          let nw_dst = node.public_ip in
          let local_ip = Net_cache.Routing.get_next_hop_local_ip node.public_ip in 
          let Some(local_mac) = (Net_cache.Arp_cache.mac_of_ip local_ip) in 
          let Some(gw_mac) = (Net_cache.Arp_cache.get_next_hop_mac node.public_ip) in 

          (* setup flow from the local node to the internet  *)
           let wild = OP.Wildcards.({in_port=false; dl_vlan=true; dl_src=true; 
                      dl_dst=true; dl_type=false; nw_proto=false; 
                      tp_src=false; tp_dst=false; nw_src=(char_of_int 0); 
                      nw_dst=(char_of_int 0); dl_vlan_pcp=true; nw_tos=true;}) in
          let m = OP.Match.(
            {wildcards=wild; in_port=flow.OP.Match.in_port; 
             dl_vlan=flow.OP.Match.dl_vlan; dl_vlan_pcp=flow.OP.Match.dl_vlan_pcp; 
             dl_type=flow.OP.Match.dl_type; 
             nw_tos=flow.OP.Match.nw_tos; dl_src=flow.OP.Match.dl_src; 
             dl_dst=flow.OP.Match.dl_dst;
             nw_src=flow.OP.Match.nw_src; nw_dst=flow.OP.Match.nw_dst; 
             tp_src=flow.OP.Match.tp_src;
             tp_dst=flow.OP.Match.tp_dst; nw_proto=flow.OP.Match.nw_proto; }) in

         let actions = [
            OP.Flow.Set_dl_dst(gw_mac);
            OP.Flow.Set_nw_src(local_ip);
            OP.Flow.Set_nw_dst(node.public_ip); 
            OP.Flow.Output( port, 2000);] in
          let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD ~priority:200 
                      ~buffer_id:(Int32.to_int buffer_id) actions () in 
          let bs = OP.Flow_mod.flow_mod_to_bitstring pkt in
          lwt _ = OC.send_of_data controller dpid bs in
(*           lwt _ = Sp_controller.unregister_handler flow
 *           filter_outgoing_tcp_packet in *)
            return ()
          

      | (_, _, _) -> return ()
    with exn ->
      ep "[natpanch] Error: %s\n%!" (Printexc.to_string exn);
      return ()



(*********************************************************
*       Testing methods
*********************************************************)
(* stun-like client *)
  let connect_client ip port =
    try_lwt 
      let client_sock = socket PF_INET SOCK_STREAM 0 in
      let hentry = Unix.inet_addr_of_string ip in
      lwt _ = 
         (Lwt_unix.sleep 4.0 >|= (fun _ -> failwith("Can't connect")) ) <?> 
              Lwt_unix.connect client_sock(ADDR_INET(hentry, port)) in 
      let ADDR_INET(loc_ip,loc_port) = Lwt_unix.getsockname client_sock in
      let pkt_bitstring = BITSTRING {
          (Uri_IP.string_to_ipv4 (Unix.string_of_inet_addr loc_ip)):32;
          loc_port:16; (String.length (Nodes.get_local_name ())):16;
          (Nodes.get_local_name ()):-1:string} in 
      let pkt = Bitstring.string_of_bitstring pkt_bitstring in 
      lwt _ = Lwt_unix.send client_sock pkt 0 (String.length pkt) [] in
      let rcv_buf = String.create 2048 in 
      lwt recvlen = Lwt_unix.recv client_sock rcv_buf 0 1048 [] in

          Lwt_unix.shutdown client_sock SHUTDOWN_ALL; 
          return true
    with exn ->
      ep "[natpanch] tcp client error:%s\n%!" (Printexc.to_string exn);
      return false

  let register_dst a public_ip sp_ip conn_id =
    Hashtbl.replace natpanch_state.conns a {name=a; public_ip; sp_ip;conn_id;};
    let flow_wild = OP.Wildcards.({
      in_port=true; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=false; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 0); nw_src=(char_of_int 32);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match flow_wild ~dl_type:(0x0800)
                 ~nw_proto:(char_of_int 6)  
                ~nw_dst:(sp_ip) () in
      Sp_controller.register_handler flow filter_outgoing_tcp_packet 

  let unregister_dst a _ sp_ip =
    let _ = Hashtbl.remove natpanch_state.conns a in
      let flow_wild = OP.Wildcards.({
        in_port=true; dl_vlan=true; dl_src=true; dl_dst=true;
        dl_type=false; nw_proto=false; tp_dst=true; tp_src=true;
        nw_dst=(char_of_int 0); nw_src=(char_of_int 32);
        dl_vlan_pcp=true; nw_tos=true;}) in
      let flow = OP.Match.create_flow_match flow_wild ~dl_type:(0x0800)
                   ~nw_proto:(char_of_int 6)  ~nw_dst:sp_ip () in
        Sp_controller.unregister_handler flow filter_outgoing_tcp_packet 

  let test kind args =
    match kind with 
      | "client_test" -> (
        try_lwt
          let ip :: port :: node :: sp_ip ::  _ = args in
          let ip = Uri_IP.string_to_ipv4 ip in
          let sp_ip = Uri_IP.string_to_ipv4 sp_ip in
          let port = int_of_string port in
          lwt _ = register_dst node ip sp_ip  0 in 
          lwt res = connect_client (Uri_IP.ipv4_to_string sp_ip) port in
(*           let _ = unregister_dst node ip sp_ip in   *)
            return(string_of_bool res)
        with exn ->
          raise (NatpunchError((sprintf "[natpanch] error %s" (Printexc.to_string exn))) )
        )
      | _ ->
          raise (NatpunchError((sprintf "[natpanch] invalid test action %s" kind)) )

(*
 * Connect methods
 * *)
  let connect kind args =
    match kind with
      | "server_connect" ->(
        try_lwt
          (* gathering all the important header fields *)
          let node::dst_ip :: dst_port :: src_port :: local_sp_ip :: 
              remote_sp_ip:: conn_id :: isn :: _ = args in 
         let dst_ip = Uri_IP.string_to_ipv4 dst_ip in 
          let dst_port = int_of_string dst_port in 
          let src_port = int_of_string src_port in
          let local_sp_ip = Uri_IP.string_to_ipv4 local_sp_ip in
          let remote_sp_ip = Uri_IP.string_to_ipv4 remote_sp_ip in
            Hashtbl.replace natpanch_state.conns  node
              {name=node;public_ip=dst_ip; sp_ip=remote_sp_ip; conn_id=0;};
          let isn = Int32.of_string isn in
          let controller = (List.hd 
                  Sp_controller.switch_data.Sp_controller.of_ctrl) in 
          let dpid = (List.hd 
                  Sp_controller.switch_data.Sp_controller.dpid)  in          
          
          let local_ip = Net_cache.Routing.get_next_hop_local_ip dst_ip in 
          let Some(local_mac) = (Net_cache.Arp_cache.mac_of_ip local_ip) in 
          let Some(gw_mac) = (Net_cache.Arp_cache.get_next_hop_mac dst_ip) in 

          let Some(port) = (Net_cache.Port_cache.dev_to_port_id Config.net_intf) in
          let port = OP.Port.port_of_int port in

          (* Setup the incoming flow from the internet to the local node  
          * *)

          let wild = OP.Wildcards.({in_port=false; dl_vlan=true; dl_src=true; 
                      dl_dst=true; dl_type=false; nw_proto=false; 
                      tp_src=false; tp_dst=false; nw_src=(char_of_int 0); 
                      nw_dst=(char_of_int 0); dl_vlan_pcp=true; nw_tos=true;}) in
          let m = OP.Match.(
            {wildcards=wild; in_port=port;
             dl_src=gw_mac; dl_dst=local_mac; dl_vlan=0xffff;
             dl_vlan_pcp=(char_of_int 0);dl_type=0x0800; nw_src=dst_ip; nw_dst=local_ip;
             nw_tos=(char_of_int 0); nw_proto=(char_of_int 6);
             tp_src=src_port; tp_dst=dst_port;}) in          
(*
           lwt _ = Sp_controller.register_handler m
           filter_incoming_rst_packet in  
          
 *)
          let actions = [OP.Flow.Set_dl_src("\xfe\xff\xff\xff\xff\xff");
                         OP.Flow.Set_nw_dst(local_sp_ip);
                         OP.Flow.Set_nw_src(remote_sp_ip);
                         OP.Flow.Output((OP.Port.Local), 2000);] in
          let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD ~priority:200
                      ~buffer_id:(-1) actions () in
          let bs = OP.Flow_mod.flow_mod_to_bitstring pkt in
          lwt _ = OC.send_of_data controller dpid bs in
          
          (* create syn packet and send it over the openflow control
           * channelto the local node  *)
          let pkt = Tcp.gen_tcp_syn isn "\xfe\xff\xff\xff\xff\xff" local_mac remote_sp_ip 
                      local_sp_ip src_port dst_port 0x3000 in 
          let bs = (OP.Packet_out.packet_out_to_bitstring 
                      (OP.Packet_out.create ~buffer_id:(-1l)
                      ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))]
                      ~data:pkt ~in_port:(OP.Port.No_port) () )) in  
          lwt _ = OC.send_of_data controller dpid bs in

          (*
           * send a syn packet also out to the internet in order to open state
           * in the nat
           * *)
          let pkt = Tcp.gen_tcp_syn isn local_mac gw_mac local_ip dst_ip
                      dst_port src_port 0x3000 in 
          let bs = (OP.Packet_out.packet_out_to_bitstring 
                      (OP.Packet_out.create ~buffer_id:(-1l)
                      ~actions:[OP.(Flow.Output(port , 2000))]
                      ~data:pkt ~in_port:(OP.Port.No_port) () )) in  
          lwt _ = OC.send_of_data controller dpid bs in

(*
          let pkt = Tcp.gen_tcp_syn isn local_mac gw_mac local_ip dst_ip
                      dst_port src_port 0x3000 in 
          let bs = (OP.Packet_out.packet_out_to_bitstring 
                      (OP.Packet_out.create ~buffer_id:(-1l)
                      ~actions:[OP.(Flow.Output(port , 2000))]
                      ~data:pkt ~in_port:(OP.Port.No_port) () )) in  
          lwt _ = OC.send_of_data controller dpid bs in
       
 *)

          (* Setup the outgoing flow from the local node to the internet 
          * *)
          let actions = [
            OP.Flow.Set_nw_src(local_ip);
            OP.Flow.Set_dl_dst(gw_mac);
            OP.Flow.Set_nw_dst(dst_ip);
            OP.Flow.Output(port, 2000);] in
          let m = OP.Match.(
            {wildcards=(OP.Wildcards.exact_match); in_port=OP.Port.Local;
             dl_dst="\xfe\xff\xff\xff\xff\xff"; dl_src=local_mac;
             dl_vlan=0xffff;dl_vlan_pcp=(char_of_int 0);dl_type=0x0800; 
             nw_src=local_sp_ip; nw_dst=remote_sp_ip;
             nw_tos=(char_of_int 0); nw_proto=(char_of_int 6);
             tp_src=dst_port; tp_dst=src_port;}) in
           lwt _ = Sp_controller.register_handler m
           filter_outgoing_tcp_packet in  
(*
           lwt _ = Sp_controller.register_handler m
           handle_outgoing_syn_packet in 
 *)
            return ("true")
        with exn ->
          let err = Printexc.to_string exn in
          pp "[natpunch] error %s\n%!" err;
          raise (NatpunchError(err)))      
      | _ -> raise (NatpunchError((sprintf "unsupported connect method %s" kind))) 

  let enable kind args =
    match kind with
      | "register_host" ->
          (try_lwt
            let node::public_ip::sp_ip::conn_id::_ = args in
            let public_ip = Uri_IP.string_to_ipv4 public_ip in
            let sp_ip = Uri_IP.string_to_ipv4 sp_ip in
              Hashtbl.replace natpanch_state.conns  node
                {name=node;public_ip; sp_ip; conn_id=(int_of_string conn_id);};
              let _ = register_dst node public_ip sp_ip (int_of_string conn_id) in
              return ("true")
          with  exn ->
            pp "[natpunch] error %s\n%!" (Printexc.to_string exn);
            return ("127.0.0.1"))

     | _ -> raise (NatpunchError((sprintf "unsupported %s" kind))) 


  (*
   *             TEARDOWN methods of tactic
   ************************************************************************)

  let teardown _ _ =
    return "true"

  let disable _ _ = 
    return "true"

  let pkt_in_cb _ _ _ = 
    return ()

end
