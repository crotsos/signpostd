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

open Pktgen
open Lwt
open Lwt_list
open Lwt_process
open Lwt_unix

open Config

open Printf

module OP = Openflow.Ofpacket
module OC = Openflow.Ofcontroller
module OE = OC.Event

module Manager = struct
  exception TorError of string
  exception SocksError of string
  exception MissingSocksArgumentError


  (********************************************************************
   *       Tactic state 
   ********************************************************************)

  type socks_state_type =
    | SSL_SERVER_INIT
    | SSL_CLIENT_INIT
    | SSL_COMPLETE
  type conn_type = {
    src_mac: string;
    dst_mac: string;
    src_ip: int32;
    dst_ip : int32;
    dst_port : int; 
    mutable ssl_state : socks_state_type;
    mutable src_isn : int32;
    mutable dst_isn : int32;
    data: Cstruct.buf;
  }

  type conn_db_type = {
    http_conns : (int, conn_type) Hashtbl.t;
    mutable process : process_none option;
    hosts : (int32, string) Hashtbl.t; 
  }

  let conn_db = 
    {http_conns=(Hashtbl.create 0);process=None;hosts=(Hashtbl.create 32); }


  let tor_port = 9050

  let restart_tor () = 
    let pid = 
      match (conn_db.process) with
        | None -> 
            let pid = open_process_none 
                        (dir ^ "client_tactics/tor/tor.sh", 
                         [|dir ^ "/client_tactics/tor/tor.sh"; 
                           dir;|]) in 
            let _ = conn_db.process <- Some (pid) in 
              pid
        | Some pid -> pid
    in
      pid#pid

  let load_socks_sockets pid = 
    let fd_dir = (Printf.sprintf "/proc/%d/fd/" pid) in 
      let files = Sys.readdir fd_dir in 
      let sock_array = Array.map (fun dir -> 
                      let file_path = Printf.sprintf "%s/%s" fd_dir dir in
                      let file_stat = Unix.stat file_path in 
                        match file_stat.Unix.st_kind with
                          | Unix.S_SOCK -> file_stat.Unix.st_ino
                          | _ -> 0
        ) files in 
        List.filter (fun fd -> (fd <> 0)) (Array.to_list sock_array) 
          

(*
 *  openflow comtrol methods
 * *)
  let is_tor_conn ip port = 
    let pid = restart_tor () in

    let socket_ids = load_socks_sockets pid in 
(*     List.iter (fun fd -> Printf.printf "%d\n%!" fd ) socket_ids; *)
    let found = ref false in
    let lookup_string = 
      sprintf "%s:%04X" 
        (Net_cache.Routing.string_rev (sprintf "%08lX" ip)) 
        port in 
    let tcp_conn = open_in "/proc/net/tcp" in 

      let rec parse_tcp_conn tcp_conn = 
        try 
          let conn = input_line tcp_conn in
          let det = Re_str.split (Re_str.regexp "[ ]+") conn in 
(*             Printf.printf "Looking sock %d\n%!" (int_of_string (List.nth det
 *             9)); *)
            if( (List.mem  (int_of_string (List.nth det 9)) socket_ids) &&
              ((List.nth det 1) = lookup_string) ) then (
              Printf.printf "%s %s\n%!" (List.nth det 1) lookup_string;
              found := true
            ) else (
              parse_tcp_conn tcp_conn
            )
        with End_of_file -> () 
      in
      let _ = input_line tcp_conn in 
        let _ = parse_tcp_conn tcp_conn in  
          close_in tcp_conn;
          return (!found)  



  let ssl_send_conect_req controller dpid conn m dst_port = 
    let (_, gw, _) = Net_cache.Routing.get_next_hop conn.dst_ip in
  (* SYNACK the client in order to establish the
     * connection *)
    let pkt = 
      gen_server_synack
        (* TODO Add a counter for the domain name *)
        (Int32.add conn.dst_isn 8l ) (* 68 bytes for http reply *)
        (Int32.add conn.src_isn 1l)
        conn.dst_mac conn.src_mac 
        conn.dst_ip conn.src_ip
        dst_port conn.dst_port in 
    lwt _ = 
      OC.send_of_data controller dpid
        (OP.marshal_and_sub 
           (OP.Packet_out.marshal_packet_out
              (OP.Packet_out.create ~buffer_id:(-1l)
                 ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))] 
                 ~data:pkt ~in_port:(OP.Port.No_port) () )) 
           (Lwt_bytes.create 4096)) in  

  (* Send an http request to setup the persistent connection to the ssl server *)
  let pkt = 
    gen_tcp_data_pkt 
      (Int32.sub conn.src_isn
         (Int32.of_int ((Cstruct.len conn.data) - 1)))
      (Int32.add conn.dst_isn 1l)
      conn.dst_mac conn.src_mac
      gw conn.src_ip
      m.OP.Match.tp_src dst_port conn.data in 
    OC.send_of_data controller dpid
      (OP.marshal_and_sub 
         (OP.Packet_out.marshal_packet_out 
            (OP.Packet_out.create ~buffer_id:(-1l)
               ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))] 
               ~data:pkt ~in_port:(OP.Port.No_port) () )) 
         (Lwt_bytes.create 4096))

  let ssl_complete_flow controller dpid conn m dst_port = 
    let (_, gw, _) = Net_cache.Routing.get_next_hop conn.dst_ip in
    
    (* ack the socks connect http reply *)
    let pkt = 
      gen_server_ack 
        (Int32.add conn.src_isn 1l)
        (Int32.add conn.dst_isn 9l) 
        conn.src_mac conn.dst_mac
        gw conn.src_ip
        m.OP.Match.tp_src dst_port 0xffff in 
    lwt _ = 
      OC.send_of_data controller dpid
        (OP.marshal_and_sub
           (OP.Packet_out.marshal_packet_out
              (OP.Packet_out.create ~buffer_id:(-1l)
                 ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))]
                 ~data:pkt ~in_port:(OP.Port.No_port) () )) 
        (Lwt_bytes.create 4096)) in  

    let pkt = gen_server_ack 
                (Int32.add conn.dst_isn 8l ) (* 68 bytes for http reply *)
                (Int32.add conn.src_isn 1l)
                conn.src_mac conn.dst_mac 
                conn.dst_ip conn.src_ip
                dst_port conn.dst_port 0xffff in 
    let bs = 
      OC.send_of_data controller dpid
        (OP.marshal_and_sub
           (OP.Packet_out.marshal_packet_out
              (OP.Packet_out.create ~buffer_id:(-1l)
                 ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))]
                 ~data:pkt ~in_port:(OP.Port.No_port) () )) 
           (Lwt_bytes.create 4096)) in  
    
  (* Setup the appropriate flows in the openflow flow table *)
  let actions = [
    OP.Flow.Set_dl_src(conn.dst_mac);
    OP.Flow.Set_dl_dst(conn.src_mac);
    OP.Flow.Set_nw_src(conn.dst_ip);
    OP.Flow.Set_nw_dst(conn.src_ip);
    OP.Flow.Set_tp_src(conn.dst_port);
    OP.Flow.Output((OP.Port.Local), 2000);] in
  let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD 
              ~buffer_id:(-1) actions () in 
  let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
             (Lwt_bytes.create 4096) in
  lwt _ = OC.send_of_data controller dpid bs in 

  let m = OP.Match.({wildcards=(OP.Wildcards.exact_match);
                     in_port=OP.Port.Local; dl_src=conn.src_mac;
                     dl_dst=conn.dst_mac; dl_vlan=0xffff;
                     dl_vlan_pcp=(char_of_int 0); dl_type=0x0800;
                     nw_src=conn.src_ip; nw_dst=conn.dst_ip;
                     nw_tos=(char_of_int 0); nw_proto=(char_of_int 6);
                     tp_src=dst_port; tp_dst=conn.dst_port}) in 
  let actions = [
    OP.Flow.Set_dl_src(conn.dst_mac);
    OP.Flow.Set_dl_dst(conn.src_mac);
    OP.Flow.Set_nw_src(gw);
    OP.Flow.Set_nw_dst(conn.src_ip);
    OP.Flow.Set_tp_dst(tor_port);
    OP.Flow.Output((OP.Port.Local), 2000);] in
  let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD 
              ~buffer_id:(-1) actions () in 
  let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt)
             (Lwt_bytes.create 4096) in
    OC.send_of_data controller dpid bs 

  let init_tcp_connection controller dpid m src_port dst_port data =
    let (_, gw, _) = 
      Net_cache.Routing.get_next_hop
        m.OP.Match.nw_dst in 
    let name = Hashtbl.find conn_db.hosts m.OP.Match.nw_dst in 
    let _ = 
      printf "[socks] non-socks coonection on port %d\n%!" 
        src_port in
    let isn = get_tcp_sn data in
    let req = Lwt_bytes.create 1024 in 
    let _ = Cstruct.set_uint8 req 0 4 in 
    let _ = Cstruct.set_uint8 req 1 1 in 
    let _ = Cstruct.BE.set_uint16 req 2 dst_port in 
    let _ = Cstruct.BE.set_uint32 req 4 1l in 
    let _ = Cstruct.set_uint8 req 8 0 in
    let name = name ^ "\000" in
    let _ = Cstruct.set_buffer name 0 req 9  (String.length name) in 
    let req = Cstruct.sub req 0 (9 + (String.length name)) in 
    let mapping = 
      {src_mac=m.OP.Match.dl_src; dst_mac=m.OP.Match.dl_dst; 
       src_ip=m.OP.Match.nw_src; dst_ip = m.OP.Match.nw_dst;
       dst_port=dst_port; ssl_state=SSL_SERVER_INIT;
       src_isn=isn;dst_isn=0l; data=req;} in
    let _ = Hashtbl.replace conn_db.http_conns src_port mapping in 
    (* establishing connection with socks socket *)
    let pkt = 
      gen_server_syn data
        (Int32.sub isn (Int32.of_int ((Cstruct.len mapping.data))))
        mapping.src_mac mapping.dst_mac
        mapping.src_ip gw tor_port in 
    let _ = printf "XXXXXXXXX done with tcp request\n%!" in 
      
      OC.send_of_data controller dpid  
        (OP.marshal_and_sub
           (OP.Packet_out.marshal_packet_out 
              (OP.Packet_out.create ~buffer_id:(-1l)
                 ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))] 
                 ~data:pkt ~in_port:(OP.Port.No_port) () )) 
           (Lwt_bytes.create 4096))

  let handle_tor_incoming_pkt controller dpid m dst_port data = 
    try_lwt 
      let conn = Hashtbl.find conn_db.http_conns dst_port in
        match conn.ssl_state with
          | SSL_SERVER_INIT -> 
              let isn = get_tcp_sn data in 
              let _ = conn.dst_isn <- isn in
              let _ = conn.ssl_state <- SSL_CLIENT_INIT in 
                ssl_send_conect_req controller dpid conn m dst_port 
          | SSL_CLIENT_INIT -> 
              let payload_len = 
                Cstruct.len (get_tcp_packet_payload data) in
                if (payload_len > 0) then (
                  let _ = conn.ssl_state <- SSL_COMPLETE in 
                    ssl_complete_flow controller dpid conn m dst_port 
                ) else (
                  return (Printf.printf "[socks] Ignoring ACK packet\n%!")
                )
          | SSL_COMPLETE -> 
              return (Printf.printf "[socks] Connection completed, ignoring pkt\n%!");
          | _ ->
              let _ = Printf.printf "state not implemented\n%!" in 
                return ()
    with Not_found ->
      return(eprintf "[openflow] dropping packet. for port %d %d\n%!" tor_port dst_port) 
  
  let http_pkt_in_cb controller dpid evt = 
    let (in_port, buffer_id, data, _) = 
      match evt with
        | OE.Packet_in (inp, buf, dat, dp) -> (inp, buf, dat, dp)
        | _ -> invalid_arg "bogus datapath_join event match!"
    in
    let m = OP.Match.raw_packet_to_match in_port data in
      match (m.OP.Match.tp_src, m.OP.Match.tp_dst) with
        | (9050, dst_port) -> 
            handle_tor_incoming_pkt controller dpid m dst_port data
        | (src_port, dst_port) -> begin
            lwt is_tor = is_tor_conn m.OP.Match.nw_src src_port in 
            let state_found = (Hashtbl.mem conn_db.http_conns src_port) in 
              match (is_tor, state_found) with
                | (true, _) ->
                    let port_id = 
                      match (Net_cache.Port_cache.port_id_of_mac 
                               m.OP.Match.dl_dst) with
                        | Some(port_id) -> OP.Port.port_of_int port_id
                        | None -> OP.Port.All
                    in
                    let pkt = 
                      OP.Flow_mod.create m 0_L OP.Flow_mod.ADD 
                        ~buffer_id:(Int32.to_int buffer_id)
                        [OP.Flow.Output(port_id, 2000);]  () in 
                      OC.send_of_data controller dpid
                        (OP.marshal_and_sub 
                           (OP.Flow_mod.marshal_flow_mod pkt)
                           (Lwt_bytes.create 4096))
                | (false, true) -> 
                    return (printf "[socks] non-socks established  %d\n%!" src_port)
                | (_, false) ->
                    let _ = printf "[tor] new conn rcved...\n%!" in 
                    init_tcp_connection controller dpid m src_port 
                      dst_port data
          end

  (*********************************************************************
   * testing code
   * TODO: do we need any tests?
   *********************************************************************)
   let run_client port ip =
     let buf = String.create 1500 in
     let sock = Lwt_unix.socket Lwt_unix.PF_INET SOCK_STREAM 0 in   
     let ipaddr = Unix.inet_addr_of_string (Uri_IP.ipv4_to_string ip) in
     printf "[tor] trying to connect...\n%!";
     lwt _ = Lwt_unix.connect sock (ADDR_INET(ipaddr, port)) in 
     printf "[tor] connected...\n%!";
     let portaddr = Unix.ADDR_INET (ipaddr, port) in
     let pkt_bitstring = BITSTRING {
       ip:32:int;port:16; (String.length (Nodes.get_local_name ())):16;
       (Nodes.get_local_name ()):-1:string} in 
     let pkt = Bitstring.string_of_bitstring pkt_bitstring in 
     lwt _ = Lwt_unix.send sock pkt 0 
                  (String.length pkt) [] in 
     printf "[tor] send data...\n%!";
     try_lwt 
       lwt len = Lwt_unix.recv sock buf 0 1500 [] in
     printf "[tor] received data...\n%!";
         return (len > 0)
     with err -> 
       eprintf "[tor] client test error: %s\n%!" 
         (Printexc.to_string err);
        raise (TorError(Printexc.to_string err))
 
  let test kind args =
    try_lwt 
    match kind with
      | "server_start" -> begin
          let _ = restart_tor () in 
          let fd = open_in (tmp_dir ^ "/tor/hostname") in 
          let name = input_line fd in 
          let _ = close_in fd in 
            return name
        end
      | "connect" ->
          let ip , domain, port = 
            match args with
              | ip::domain::port::_ ->
                  ((Uri_IP.string_to_ipv4 ip), domain, (int_of_string port))
              | _ -> raise (TorError "Insufficient args")
          in
          let _ = Hashtbl.replace conn_db.hosts ip domain in
          lwt _ = 
            Sp_controller.register_handler_new
              ~dl_type:(Some 0x0800) ~nw_proto:(Some(char_of_int 6)) 
              ~nw_dst:(Some ip) ~nw_dst_len:(0) ~tp_dst:(Some port)
              http_pkt_in_cb in 
          lwt _ = 
            Sp_controller.register_handler_new
              ~dl_type:(Some 0x0800) ~nw_proto:(Some(char_of_int 6)) 
              ~tp_src:(Some 9050) http_pkt_in_cb in 
           lwt ret = run_client port ip in 
            return (string_of_bool ret)
    | _ -> raise(TorError(sprintf "Unsupported action %s" kind))
    with exn -> raise(TorError(Printexc.to_string exn))


  (*********************************************************************
   * Connection code
   **********************************************************************)
   
  let connect kind _ =
    match kind with 
      | "start" -> begin
(*          (lwt _ = match conn_db.process with
            | None -> restart_tor () 
            | Some(pid) -> return (pid)
          in*)
          let _ = restart_tor () in 
          return ("OK")
        end
      | "forward" ->
          Printf.printf "[socks] forwarding started\n%!";
          let flow_wild = OP.Wildcards.({
                in_port=true; dl_vlan=true;
                dl_src=true; dl_dst=true;
                dl_type=false; nw_proto=false;
                tp_dst=false; tp_src=true;
                nw_src=(char_of_int 32); nw_dst=(char_of_int 32);
                dl_vlan_pcp=true; nw_tos=true;}) in 
          let flow = OP.Match.create_flow_match flow_wild ~dl_type:(0x0800)
                       ~nw_proto:(char_of_int 6) ~tp_dst:80 () in 
          Sp_controller.register_handler flow http_pkt_in_cb;
          let flow_wild = OP.Wildcards.({
                in_port=true; dl_vlan=true;
                dl_src=true; dl_dst=true;
                dl_type=false; nw_proto=false;
                tp_dst=false; tp_src=true;
                nw_src=(char_of_int 32); nw_dst=(char_of_int 32);
                dl_vlan_pcp=true; nw_tos=true;}) in 
          let flow = OP.Match.create_flow_match flow_wild ~dl_type:(0x0800)
                       ~nw_proto:(char_of_int 6) ~tp_dst:443 () in 
          Sp_controller.register_handler flow http_pkt_in_cb;          
          let flow_wild = OP.Wildcards.({
                in_port=true; dl_vlan=true;
                dl_src=true; dl_dst=true;
                dl_type=false; nw_proto=false;
                tp_dst=true; tp_src=false;
                nw_src=(char_of_int 32); nw_dst=(char_of_int 32);
                dl_vlan_pcp=true; nw_tos=true;}) in 
          let flow = OP.Match.create_flow_match flow_wild ~dl_type:(0x0800)
                       ~nw_proto:(char_of_int 6) ~tp_src:tor_port () in 
          Sp_controller.register_handler flow http_pkt_in_cb;
          return ("OK")
      | _ -> 
          Printf.eprintf "[socks] Invalid connection kind %s \n%!" kind;
          raise (SocksError "Invalid connection kind")
 
(**
  * enable event
  * *)
  let enable _ _ = 
    return "true"

(*
 * disable tactic
 * *)

  let disable _ _ = 
    return "true"

  (************************************************************************
   *         Tearing down connection code
   ************************************************************************)
  let teardown _ _ =
    return "true"


end
