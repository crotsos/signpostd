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
    data: Cstruct.t;
  }

  type conn_db_type = {
    http_conns : (int, conn_type) Hashtbl.t;
    mutable process : process_none option;
    mutable monitor_wait : unit t option;
    mutable monitor_return : unit u option;
    mutable tor_ctrl : Tor_ctl.tor_ctl_state option;
    mutable server_list : int list;
    hosts : (int32, string) Hashtbl.t; 
  }

  let conn_db = 
    {http_conns=(Hashtbl.create 0);process=None;
    hosts=(Hashtbl.create 32); monitor_wait=None; 
    monitor_return=None; tor_ctrl=None;server_list=[]}


  let tor_port = 9050
  let tor_ctl_port = 9051

  let is_connected_socket flow ip port = 
    try 
      let str = Printf.sprintf "%s:%d" (Uri_IP.ipv4_to_string ip) 
                  port in 
      let _ = Re_str.search_forward (Re_str.regexp str) flow 0 in 
        true
    with Not_found -> false

  let is_listening_socket flow = 
    try 
     let _ = Re_str.search_forward (Re_str.regexp "->") flow 0 in 
        false
    with Not_found -> true

 let read_servers () =
    let lsof = ("lsof", [|"lsof"; "-i"; "4TCP"; "-n";"-P";|]) in 
    let proc = open_process_in lsof in
    lwt _ = Lwt_io.read_line proc#stdout in 
    let rec read_flows stream = 
      try_lwt 
        lwt line = Lwt_io.read_line stream in 
        let fields = Re_str.split (Re_str.regexp "[\ \t]+") line in 
        let flow_pid = int_of_string (List.nth fields 1) in 
        let flow = List.nth fields 8 in
        let service =
          try 
          if (is_listening_socket flow) then
            match (Re_str.split (Re_str.regexp ":") flow) with
            | ip::port::_ -> [(int_of_string port)]
            | _ -> []
          else
            []
          with exn -> []
        in
        lwt rest = read_flows stream in 
          return (service @ rest)
      with End_of_file -> 
        return []
  in
    read_flows proc#stdout

  let monitor_socket st t = 
    nchoose 
    [ t; 
    (while_lwt true do 
      lwt servers = read_servers () in 
      let new_servers = 
        List.filter 
        (fun port ->
          not (List.mem port conn_db.server_list) ) servers in
      lwt _ = 
        if (List.length new_servers > 0) then 
          let _ = conn_db.server_list <- 
            conn_db.server_list @ new_servers in 
            lwt _ = Tor_ctl.expose_service st (tmp_dir ^ "/tor/")
                      conn_db.server_list in
              return ()
        else
          return () 
      in 
      lwt _ = Lwt_unix.sleep 10.0 in 
        return ()
    done)]

 
  let restart_tor () = 
    lwt pid = 
      match (conn_db.process) with
        | None -> 
            let pid = 
              open_process_none 
                (dir ^ "client_tactics/tor/tor.sh", 
                 [|dir ^ "/client_tactics/tor/tor.sh"; 
                   dir;|]) in 
            let _ = conn_db.process <- Some (pid) in 
            lwt _ = Lwt_unix.sleep 1.0 in 
            lwt st = Tor_ctl.init_tor_ctl "127.0.0.1" tor_ctl_port in 
            let _ = conn_db.tor_ctrl <- Some(st) in  
            let (t, u) = task () in
            let _ = conn_db.monitor_wait <- Some(t) in 
            let _ = conn_db.monitor_return <- Some(u) in 
            let _ = ignore_result (monitor_socket st t) in  
            lwt _ = Lwt_unix.sleep 1.0 in 
              return pid
        | Some pid -> return pid
    in
      return pid#pid

  let is_tor_conn ip port = 
    lwt pid = restart_tor () in
    let lsof = ("lsof", [|"lsof"; "-i"; "4TCP"; "-n";"-P";|]) in 
    let proc = open_process_in lsof in
    lwt _ = Lwt_io.read_line proc#stdout in 
    let rec read_flows stream = 
      try_lwt 
        lwt line = Lwt_io.read_line stream in 
        let fields = Re_str.split (Re_str.regexp "[\ \t]+") line in 
        let flow_pid = int_of_string (List.nth fields 1) in 
        let flow = List.nth fields 8 in 

          if ((pid = flow_pid) && 
              (is_connected_socket flow ip port) ) then
            return true
          else (read_flows stream)
      with End_of_file -> return false
  in
    read_flows proc#stdout

 
(*
 *  openflow comtrol methods
 * *)
  let ssl_send_conect_req controller dpid conn m dst_port = 
(*    let (_, gw, _) = Net_cache.Routing.get_next_hop conn.dst_ip in *)
 (* SYNACK the client in order to establish the
     * connection *)
     let pkt = 
      gen_server_synack
        (* TODO Add a counter for the domain name *)
        (Int32.add conn.dst_isn 8l ) (* 68 bytes for http reply *)
        (Int32.add conn.src_isn 1l)
        conn.dst_mac conn.src_mac 
        conn.dst_ip conn.src_ip
        dst_port conn.dst_port 0x0 in 
    lwt _ = 
      OC.send_of_data controller dpid
        (OP.marshal_and_sub 
           (OP.Packet_out.marshal_packet_out
              (OP.Packet_out.create ~buffer_id:(-1l)
                 ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))] 
                 ~data:pkt ~in_port:(OP.Port.No_port) () )) 
           (Cstruct.create 4096)) in  

  (* Send an http request to setup the persistent connection to the ssl server *)
  let pkt = 
    gen_tcp_data_pkt 
      (Int32.sub conn.src_isn
         (Int32.of_int ((Cstruct.len conn.data) - 1)))
      (Int32.add conn.dst_isn 1l)
      conn.dst_mac conn.src_mac
      conn.dst_ip conn.src_ip
      m.OP.Match.tp_src dst_port 0xffff conn.data in 
    OC.send_of_data controller dpid
      (OP.marshal_and_sub 
         (OP.Packet_out.marshal_packet_out 
            (OP.Packet_out.create ~buffer_id:(-1l)
               ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))] 
               ~data:pkt ~in_port:(OP.Port.No_port) () )) 
         (Cstruct.create 4096))

  let ssl_complete_flow controller dpid conn m dst_port = 
(* Setup the appropriate flows in the openflow flow table *)
    let actions = [
      OP.Flow.Set_dl_src(conn.dst_mac);
      OP.Flow.Set_dl_dst(conn.src_mac);
      OP.Flow.Set_nw_src(conn.dst_ip);
      OP.Flow.Set_nw_dst(conn.src_ip);
      OP.Flow.Set_tp_src(conn.dst_port);
      OP.Flow.Output((OP.Port.In_port), 2000);] in
    let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD 
                ~buffer_id:(-1) ~idle_timeout:600 actions () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
      (Cstruct.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in 

    let m = OP.Match.({wildcards=(OP.Wildcards.exact_match ());
                     in_port=OP.Port.Local; dl_src=conn.src_mac;
                     dl_dst=conn.dst_mac; dl_vlan=0xffff;
                     dl_vlan_pcp=(char_of_int 0); dl_type=0x0800;
                     nw_src=conn.src_ip; nw_dst=conn.dst_ip;
                     nw_tos=(char_of_int 0); nw_proto=(char_of_int 6);
                     tp_src=dst_port; tp_dst=conn.dst_port}) in 
    let actions = [
      OP.Flow.Set_dl_src(conn.dst_mac);
      OP.Flow.Set_dl_dst(conn.src_mac);
      OP.Flow.Set_nw_src(conn.dst_ip);
      OP.Flow.Set_nw_dst(conn.src_ip);
      OP.Flow.Set_tp_dst(tor_port);
      OP.Flow.Output((OP.Port.In_port), 2000);] in
    let pkt = OP.Flow_mod.create m 0L OP.Flow_mod.ADD 
              ~buffer_id:(-1) ~idle_timeout:600 actions () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt)
              (Cstruct.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in 

     
    (* ack the socks connect http reply *)
    let pkt = 
      gen_server_ack 
        (Int32.add conn.src_isn 1l)
        (Int32.add conn.dst_isn 9l) 
        conn.dst_mac conn.src_mac
        conn.dst_ip conn.src_ip
        tor_port m.OP.Match.tp_src (* dst_port *) 0xffff in 
    lwt _ = 
      OC.send_of_data controller dpid
        (OP.marshal_and_sub
           (OP.Packet_out.marshal_packet_out
              (OP.Packet_out.create ~buffer_id:(-1l)
                 ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))]
                 ~data:pkt ~in_port:(OP.Port.No_port) () )) 
        (Cstruct.create 4096)) in  

    let pkt = 
      gen_server_ack 
        (Int32.add conn.dst_isn 9l ) (* 68 bytes for http reply *)
        (Int32.add conn.src_isn 1l)
        conn.dst_mac conn.src_mac 
        conn.dst_ip conn.src_ip
        dst_port conn.dst_port 0xffff in 
    let _ = 
      OC.send_of_data controller dpid
        (OP.marshal_and_sub
           (OP.Packet_out.marshal_packet_out
              (OP.Packet_out.create ~buffer_id:(-1l)
                 ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))]
                 ~data:pkt ~in_port:(OP.Port.No_port) () )) 
           (Cstruct.create 4096)) in  
    
    let pkt = 
      gen_server_ack
        (* TODO Add a counter for the domain name *)
        (Int32.add conn.dst_isn 8l ) (* 68 bytes for http reply *)
        (Int32.add conn.src_isn 1l)
        conn.dst_mac conn.src_mac 
        conn.dst_ip conn.src_ip
        dst_port conn.dst_port 0xffff in 
    lwt _ = 
      OC.send_of_data controller dpid
        (OP.marshal_and_sub 
           (OP.Packet_out.marshal_packet_out
              (OP.Packet_out.create ~buffer_id:(-1l)
                 ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))] 
                 ~data:pkt ~in_port:(OP.Port.No_port) () )) 
           (Cstruct.create 4096)) in 
      return ()

  let init_tcp_connection controller dpid m src_port dst_port data =
    let name = Hashtbl.find conn_db.hosts m.OP.Match.nw_dst in 
    let _ = 
      printf "[socks] non-socks coonection on port %d\n%!" 
        src_port in
    let isn = get_tcp_sn data in
    let req = Cstruct.create 1024 in 
    let _ = Cstruct.set_uint8 req 0 4 in 
    let _ = Cstruct.set_uint8 req 1 1 in 
    let _ = Cstruct.BE.set_uint16 req 2 dst_port in 
    let _ = Cstruct.BE.set_uint32 req 4 1l in 
    let _ = Cstruct.set_uint8 req 8 0 in
    let name = name ^ "\000" in
    let _ = Cstruct.blit_from_string name 0 req 9  (String.length name) in 
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
        mapping.src_ip mapping.dst_ip tor_port in 
    let _ = printf "XXXXXXXXX done with tcp request\n%!" in 
      
      OC.send_of_data controller dpid  
        (OP.marshal_and_sub
           (OP.Packet_out.marshal_packet_out 
              (OP.Packet_out.create ~buffer_id:(-1l)
                 ~actions:[OP.(Flow.Output(OP.Port.Local , 2000))] 
                 ~data:pkt ~in_port:(OP.Port.No_port) () )) 
           (Cstruct.create 4096))

  let handle_tor_incoming_pkt controller dpid m dst_port data = 
    try_lwt 
      let _ = printf "[tor] received packet in...\n%!" in 
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
        | (a, dst_port) when (a = tor_port) -> 
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
                        ~idle_timeout:600
                        ~buffer_id:(Int32.to_int buffer_id)
                        [OP.Flow.Output(port_id, 2000);]  () in 
                      OC.send_of_data controller dpid
                        (OP.marshal_and_sub 
                           (OP.Flow_mod.marshal_flow_mod pkt)
                           (Cstruct.create 4096))
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
     let _ = printf "[tor] connected...\n%!" in 
     let buf = Cstruct.create 1024 in 
     let _ = Cstruct.BE.set_uint32 buf 0  ip in 
     let _ = Cstruct.BE.set_uint16 buf 4 port in 
     let name = Nodes.get_local_name () in 
     let name_len = String.length name in 
     let _ = Cstruct.BE.set_uint16 buf 6 name_len in
     let _ = Cstruct.blit_from_string name 0 buf 8 name_len in 
     let buf = Cstruct.sub buf 0 (8+name_len) in 
     let pkt = Cstruct.to_string buf in 
     lwt _ = Lwt_unix.send sock pkt 0 
                  (String.length pkt) [] in 
     printf "[tor] send data...\n%!";
     let pkt = String.create 1500 in 
     try_lwt 
       lwt len = Lwt_unix.recv sock pkt 0 1500 [] in
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
          lwt _ = restart_tor () in 
          let fd = open_in (tmp_dir ^ "/tor/hostname") in 
          let name = input_line fd in
          let rec wait_for_service () = 
            match conn_db.tor_ctrl with
              | Some ctl -> 
                  let wait = ref true in 
                  while_lwt !wait do 
                    lwt _ = Lwt_unix.sleep 1.0 in 
                    let _ = printf "checking service...\n%!" in 
                    lwt res = Tor_ctl.is_service_established ctl in
                      return (wait := (not res))
                      
                  done 
              | None -> failwith "Tor ctrl channel unestablished"
          in
          lwt _ = wait_for_service () in
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
              ~tp_src:(Some tor_port) http_pkt_in_cb in 
           lwt ret = run_client port ip in 
            return (string_of_bool ret)
    | _ -> raise(TorError(sprintf "Unsupported action %s" kind))
    with exn -> raise(TorError(Printexc.to_string exn))


  (*********************************************************************
   * Connection code
   **********************************************************************)
 let connect kind _ =
    try_lwt
      match kind with 
        | "listen" -> begin
            lwt _ = restart_tor () in 
              return ("true")
          end
       | _ -> 
            Printf.eprintf "[socks] Invalid connection kind %s \n%!" kind;
            raise (SocksError "Invalid connection kind")
    with exn ->
      let _ = eprintf "[tor] enable error %s\n%!" (Printexc.to_string exn) in 
        raise (SocksError (Printexc.to_string exn))
 
(**
  * enable event
  * *)
  let enable kind args = 
    try_lwt
    match kind with
    | "forward" ->
        lwt _ = restart_tor () in 
        let domain, ip = 
          match args with
            | _::domain::ip::_ ->
                domain, (Uri_IP.string_to_ipv4 ip)
            | _ -> 
                raise (SocksError "Insufficient parameters")
      in
      let _ = Hashtbl.replace conn_db.hosts ip domain in 
      lwt _ = 
        Sp_controller.register_handler_new
          ~dl_type:(Some 0x0800) ~nw_proto:(Some(char_of_int 6)) 
          ~nw_dst:(Some ip) ~nw_dst_len:(0) http_pkt_in_cb in 
      lwt _ = 
        Sp_controller.register_handler_new
          ~dl_type:(Some 0x0800) ~nw_proto:(Some(char_of_int 6)) 
          ~tp_src:(Some tor_port) http_pkt_in_cb in 
        return "true"
        | _ -> raise (SocksError "invalid enable action")
    with exn -> 
      let _ = eprintf "[tor] enable error: %s\n%!" 
      (Printexc.to_string exn) in 
      raise (SocksError (sprintf "enable error: %s" 
      (Printexc.to_string exn)))
  
(*
 * disable tactic
 * *)

  let disable kind args = (* return "true" *)
    try_lwt 
      match kind with 
        | "disable" ->
            let _, ip = 
              match args with
                | _::domain::ip::_ ->
                    domain, (Uri_IP.string_to_ipv4 ip)
                | _ -> 
                    raise (SocksError "Insufficient parameters")
            in
            lwt _ = 
              Sp_controller.unregister_handler_new
                ~dl_type:(Some 0x0800) ~nw_proto:(Some(char_of_int 6)) 
                ~nw_dst:(Some ip) ~nw_dst_len:(0) () in 
            lwt _ = 
              Sp_controller.unregister_handler_new
                ~dl_type:(Some 0x0800) ~nw_proto:(Some(char_of_int 6)) 
                ~tp_src:(Some tor_port) () in
            let _ = 
              Hashtbl.remove conn_db.hosts ip in 
            (* need to delete also the existing exact match rules *)
              return ("true")
      with exn -> 
      let _ = eprintf "[tor] disable error: %s\n%!" 
                (Printexc.to_string exn) in 
      raise (SocksError (sprintf "enable error: %s" (Printexc.to_string exn)))
 
 
  (************************************************************************
   *         Tearing down connection code
   ************************************************************************)
  let teardown kind _ =
    try_lwt 
      match kind with
      | "teardown" -> begin
          lwt _ = 
            match conn_db.tor_ctrl with
              | Some ctl -> 
                  lwt _ = Tor_ctl.close_tor_ctl ctl in  
                  let _ = conn_db.tor_ctrl <- None in 
                   return ()
              | None -> return () 
          in
          lwt _ = 
            match conn_db.process with
            | Some pid ->
                let _ = pid#terminate in 
                let _ = conn_db.process <- None in 
                  return ()
            | None -> return ()
          in
            return "true"
      end
      | _ -> 
          let _ = eprintf "[tor] Invalid teardown action %s\n%!" kind in
            raise (SocksError (sprintf "invalid teardown action %s" kind))
    with exn -> 
      let _ = eprintf "[tor] teardown error %s\n%!" (Printexc.to_string exn) in 
        raise (SocksError (Printexc.to_string exn))


end
