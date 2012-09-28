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

module OP = Openflow.Ofpacket
module OC = Openflow.Ofcontroller

module Manager = struct
  exception OpenVpnError of string
  exception MissingOpenVPNArgumentError

  let tactic_priority = 4
  
  
  (* local state of the tactic*)
  type conn_type = {
    ip: string;    (* tunnel node ip address *)
    port: int;     (* port number of the openvpn server*)
    pid: int;      (* pid of the process *)
    dev_id:int;    (* tun tap device id *)
    conn_id:int32; (* an id to map state with cloud state *)
    rem_node:string; 
    (* list of nodes participating in the tunnel *)
    mutable nodes: string list;
  }

  type conn_db_type = {
    (* connection details for a specific domain *)
    conns : (string, conn_type) Hashtbl.t;
    (* an lwt thread with the udp server *)
    mutable can: unit Lwt.t option;
    (* a file descriptor for the udp server *)
    mutable fd: file_descr option;
  }

  let conn_db = {conns=(Hashtbl.create 0); can=None;fd=None;}


  (*
   * a helper function that waits until a newly installed dev
   * becomes available on openflow.
  * *)
  let rec get_port dev = 
    return (Net_cache.Port_cache.dev_to_port_id dev)
(*      return (port)
      | None -> raise (OpenVpnError((Printf.sprintf "Invalid port %s" dev))) *)
(*           lwt _ = Lwt_unix.sleep 1.0 in (get_port dev) *)
(*******************************************************
 *             Testing code 
 *******************************************************)

(*
 * setup an echo udp listening socket. 
 *
 * *)
  let run_server port =
    Printf.printf "[openvpn] Starting udp server\n%!";
    let buf = String.create 1500 in
    let sock =Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM
              (Unix.getprotobyname "udp").Unix.p_proto in
    let _ = 
      try
        (Lwt_unix.bind sock (Lwt_unix.ADDR_INET (Unix.inet_addr_any,
        port)));
        Lwt_unix.setsockopt sock Unix.SO_REUSEADDR true
      with Unix.Unix_error (e, _, _) ->
        printf "[openvpn] error: %s\n%!" (Unix.error_message e);
        raise (OpenVpnError("Couldn't be a udp server"))
    in
    (* save socket fd so that we can terminate it *)
    conn_db.fd <- Some(sock);

    (* start background echo udp server to test connectivity*)
    conn_db.can <- Some(while_lwt true do
        lwt (len, ip) = Lwt_unix.recvfrom sock buf 0 1500 [] in
        lwt _ = Lwt_unix.sendto sock 
                  (String.sub buf 0 len) 0 len [] ip in
            return ( )
        done)

(*
 * a udp client to send data. 
 * *)
  let run_client port ips =
    let buf = String.create 1500 in
    let sock = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM
              (Unix.getprotobyname "udp").Unix.p_proto in   
    let send_pkt_to port ip =
      let ipaddr = (Unix.gethostbyname ip).Unix.h_addr_list.(0) in
      let portaddr = Unix.ADDR_INET (ipaddr, port) in
        lwt _ = Lwt_unix.sendto sock ip 0 
                  (String.length ip) [] portaddr in 
          return ()
    in
    lwt _ = Lwt_list.iter_p (send_pkt_to port) ips in
     try_lwt 
       let ret = ref None in 
       let recv = 
         (lwt (len, _) = Lwt_unix.recvfrom sock buf 0 1500 [] in
         ret := Some(String.sub buf 0 len);
         return ()) in
       lwt _ = (Lwt_unix.sleep 1.0) <?> recv in 
       lwt _ = Lwt_unix.close sock in
         match (!ret) with
           | None -> raise (OpenVpnError("Unreachable server"))
           | Some(ip) -> return (ip)
     with err -> 
       eprintf "[openvpn] client test error: %s\n%!" 
         (Printexc.to_string err);
        raise (OpenVpnError(Printexc.to_string err))

  let test kind args =
    match kind with
      (* start udp server *)
      | "server_start" -> (
          let port = (int_of_string (List.hd args)) in 
          let _ = run_server port in
            return ("OK"))
      (* code to stop the udp echo server*)
      | "server_stop" -> begin
            match conn_db.can with
              | Some t -> begin
                  let _ = cancel t in 
                  let _ = conn_db.can <- None in
                  let _ = 
                    match conn_db.fd with
                      | Some(fd) ->  begin
                          let _ = Lwt_unix.close fd in
                            conn_db.fd <- None
                        end
                      | None -> ()
                  in
                  return ("OK")
                end
              | _ -> return ("OK")
        end
      (* code to send udp packets to the destination*)
      | "client" -> (
          let port :: ips = args in 
            lwt ip = run_client (int_of_string port) ips in
              (printf "[openvpn] Received a reply from ip %s \n%!" ip);
              return (ip))
      | _ -> (
          printf "[openvpn] Action %s not supported in test" kind;
          return ("OK"))

  (***************************************************************
   * Connection code 
   * ************************************************************)
  let setup_flows dev mac_addr local_ip rem_ip local_sp_ip 
        remote_sp_ip = 
    let controller = 
      (List.hd Sp_controller.switch_data.Sp_controller.of_ctrl) in 
    let dpid = 
      (List.hd Sp_controller.switch_data.Sp_controller.dpid)  in

    (* outgoing flow configuration *)

      (* Note: use constant and specific priority values for 
       * tactic flow entries in order to be able to descriminate 
       * tactics flow when two tactics cover the same tupple space 
       * *)
    let flow_wild = OP.Wildcards.({
      in_port=true; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 0); nw_src=(char_of_int 32);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match flow_wild 
                 ~dl_type:(0x0800) ~nw_dst:remote_sp_ip () in
    lwt port = get_port dev in 
    (*     let Some(port) = Net_cache.Port_cache.dev_to_port_id dev in *)
    let actions = [ OP.Flow.Set_nw_src(local_ip);
                    OP.Flow.Set_nw_dst(rem_ip);
                    OP.Flow.Set_dl_dst(
                      (Net_cache.Arp_cache.mac_of_string mac_addr));
                    OP.Flow.Output((OP.Port.port_of_int port), 
                                   2000);] in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:tactic_priority ~idle_timeout:0 ~hard_timeout:0 
                ~buffer_id:(-1) actions () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt)
               (Lwt_bytes.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in


    (* setup arp handling for 10.3.0.0/24 *)
    let arp_wild = OP.Wildcards.({
      in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 8); nw_src=(char_of_int 8);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match arp_wild
                 ~in_port:(OP.Port.int_of_port OP.Port.Local) ~dl_type:0x0806
                 ~nw_src:local_ip ~nw_dst:rem_ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:tactic_priority ~idle_timeout:0  ~hard_timeout:0
                ~buffer_id:(-1) [OP.Flow.Output((OP.Port.port_of_int port),2000)] () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
               (Lwt_bytes.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in
    let flow = OP.Match.create_flow_match arp_wild
                 ~in_port:(port) ~dl_type:0x0806
                 ~nw_src:local_ip ~nw_dst:rem_ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:tactic_priority ~idle_timeout:0  ~hard_timeout:0
                ~buffer_id:(-1) [OP.Flow.Output(OP.Port.Local,2000)] () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
               (Lwt_bytes.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in


    (* get local mac address *)
    let ip_stream = 
      (Unix.open_process_in
         (Config.dir^"/client_tactics/get_local_device br0")) in
    let ips = Re_str.split (Re_str.regexp " ") 
                (input_line ip_stream) in 
    let _::mac::_ = ips in
    let mac = Net_cache.Arp_cache.mac_of_string mac in 
    
    (* Setup incoming flow *)
    let flow_wild = OP.Wildcards.({
      in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 0); nw_src=(char_of_int 32);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match flow_wild 
                 ~in_port:port ~dl_type:(0x0800) 
                 ~nw_dst:local_ip () in
    let actions = [ OP.Flow.Set_nw_dst(local_sp_ip);
                     OP.Flow.Set_nw_src(remote_sp_ip); 
                    OP.Flow.Set_dl_dst(mac);
                    OP.Flow.Output(OP.Port.Local, 2000);] in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:tactic_priority ~idle_timeout:0  
                ~buffer_id:(-1) actions () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt)
               (Lwt_bytes.create 4096) in
      OC.send_of_data controller dpid bs

      
  let start_openvpn_daemon server_ip port node domain typ conn_id = 
    (* Generate conf directories and keys *)
    let cmd = Config.dir ^ 
              "/client_tactics/openvpn/openvpn_tactic.sh" in
    let exec_cmd = 
      if ((Nodes.get_local_name ()) = "unknown" ) then
        sprintf "%s %s %d %s d%d %s %s %s %s %s "
          cmd port conn_id Config.domain Config.signpost_number
          node server_ip domain Config.conf_dir Config.tmp_dir
      else
        sprintf "%s %s %d %s %s.d%d %s %s %s %s %s "
          cmd port conn_id Config.domain (Nodes.get_local_name ())
          Config.signpost_number node server_ip domain 
          Config.conf_dir Config.tmp_dir in
      printf "[openvpn] executing %s\n%!" exec_cmd;
    lwt _ = Lwt_unix.system exec_cmd in 
    let _ = Unix.create_process "openvpn" 
            [|""; "--config"; 
              (Config.tmp_dir^"/"^domain^"/" ^ typ ^ ".conf") |] 
            Unix.stdin Unix.stdout Unix.stderr in
    lwt _ = Lwt_unix.sleep 1.0 in      
      return (conn_id)
 
  (* start server *)
  let server_append_dev node domain =
    let cmd = Config.dir ^ 
              "/client_tactics/openvpn/openvpn_append_device.sh" in
    let exec_cmd =  
      (* nusty hack to know if you are running on a server or a client *)
      if ((Nodes.get_local_name ()) = "unknown" ) then
        sprintf "%s d%d %s %s %s %s %s"
          cmd Config.signpost_number node Config.domain 
          domain Config.conf_dir Config.tmp_dir  
      else
        sprintf "%s %s.d%d %s %s %s %s %s"
          cmd  (Nodes.get_local_name ()) Config.signpost_number 
          node Config.domain domain Config.conf_dir 
          Config.tmp_dir in
      printf "[openvpn] executing %s\n%!" exec_cmd;
      Lwt_unix.system exec_cmd  
        
  let read_pid_from_file filename = 
    let fd = open_in filename in
    let pid = int_of_string (input_line fd) in 
      close_in fd;
      printf "[openvpn] process (pid %d) ...\n%!" pid;
      pid

  (* This method will check if a server listening for a specific 
  * domain is running or not, and handle certificates appropriately. *)
  let get_domain_dev_id node domain port ip conn_id rem_node = 
    if Hashtbl.mem conn_db.conns domain then  (
      let conn = Hashtbl.find conn_db.conns domain in
        if (List.mem (node^"."^Config.domain) conn.nodes) then (
          (* A connection already exists *)
          printf "[openvpn] node %s is already added\n%!" node;
          return (conn.dev_id)
        ) else (
          (* Add domain to server and restart service *)
          printf "[openvpn] adding device %s\n%!" node;
          let _ = server_append_dev node domain in
            conn.nodes <- conn.nodes@[(node^"."^Config.domain)];
            (* restart server *)
            Unix.kill conn.pid Sys.sigusr1;
            Lwt_unix.sleep 4.0 >> return (conn.dev_id))
      ) else (
        (* if domain seen for the first time, setup conf dir 
         * and start server *)
        let _ = printf "[openvpn] start serv add device %s\n%!" node in
        let dev_id = Tap.get_new_dev_ip () in 
        lwt _ = Tap.setup_dev dev_id ip in
        lwt dev_id = start_openvpn_daemon "0.0.0.0" port 
                       node domain "server" dev_id in 
        lwt _ = Lwt_unix.sleep 1.0 in 
        let pid = read_pid_from_file (Config.tmp_dir ^ "/" ^ 
                                      domain ^"/server.pid") in 
          Hashtbl.add conn_db.conns (domain) 
            {ip=ip;port=(int_of_string port);pid;
             dev_id;nodes=[node ^ "." ^ Config.domain]; conn_id;rem_node;};
          return(dev_id) ) 
 
  let setup_flows dev mac_addr local_ip rem_ip local_sp_ip 
        remote_sp_ip = 
    let controller = 
      (List.hd Sp_controller.switch_data.Sp_controller.of_ctrl) in 
    let dpid = 
      (List.hd Sp_controller.switch_data.Sp_controller.dpid)  in

    lwt port = get_port dev in
(*     let Some(port) = Net_cache.Port_cache.dev_to_port_id dev in *)
    (* outgoing flow configuration *)

      (* Note: use constant and specific priority values for 
       * tactic flow entries in order to be able to descriminate 
       * tactics flow when two tactics cover the same tupple space 
       * *)
    let flow_wild = OP.Wildcards.({
      in_port=true; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 0); nw_src=(char_of_int 32);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match flow_wild 
                 ~dl_type:(0x0800) ~nw_dst:remote_sp_ip () in
    let actions = [ OP.Flow.Set_nw_src(local_ip);
                    OP.Flow.Set_nw_dst(rem_ip);
                    OP.Flow.Set_dl_dst(
                      (Net_cache.Arp_cache.mac_of_string mac_addr));
                    OP.Flow.Output((OP.Port.port_of_int port), 
                                   2000);] in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:tactic_priority ~idle_timeout:0 
                ~buffer_id:(-1) actions () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
               (Lwt_bytes.create 4096) in
    lwt _ = OC.send_of_data controller dpid bs in
    (* setup arp handling for 10.3.0.0/24 *)
    let arp_wild = OP.Wildcards.({ 
      in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 8); nw_src=(char_of_int 8);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match arp_wild
                 ~in_port:(OP.Port.int_of_port OP.Port.Local) ~dl_type:0x0806
                             ~nw_src:local_ip ~nw_dst:rem_ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD
                ~priority:tactic_priority ~idle_timeout:0
                ~buffer_id:(-1) [OP.Flow.Output((OP.Port.port_of_int port),2000)] () in
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
               (Lwt_bytes.create 4096) in
      lwt _ = OC.send_of_data controller dpid bs in
      let flow = OP.Match.create_flow_match arp_wild
                   ~in_port:(port) ~dl_type:0x0806
                               ~nw_src:local_ip ~nw_dst:rem_ip () in
      let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD
                  ~priority:tactic_priority ~idle_timeout:0
                  ~buffer_id:(-1) [OP.Flow.Output(OP.Port.Local,2000)] () in
      let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
                 (Lwt_bytes.create 4096) in
        lwt _ = OC.send_of_data controller dpid bs in

    (* get local mac address *)
    let ip_stream = 
      (Unix.open_process_in
         (Config.dir^"/client_tactics/get_local_device br0")) in
    let ips = Re_str.split (Re_str.regexp " ") 
                (input_line ip_stream) in 
    let _::mac::_ = ips in
    let mac = Net_cache.Arp_cache.mac_of_string mac in 
    
    (* Setup incoming flow *)
    let flow_wild = OP.Wildcards.({
      in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 0); nw_src=(char_of_int 32);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match flow_wild 
                 ~in_port:port ~dl_type:(0x0800) 
                 ~nw_dst:local_ip () in
    let actions = [ OP.Flow.Set_nw_dst(local_sp_ip);
                     OP.Flow.Set_nw_src(remote_sp_ip); 
                    OP.Flow.Set_dl_dst(mac);
                    OP.Flow.Output(OP.Port.Local, 2000);] in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.ADD 
                ~priority:tactic_priority ~idle_timeout:0  
                ~buffer_id:(-1) actions () in 
    let bs = OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
               (Lwt_bytes.create 4096) in
      OC.send_of_data controller dpid bs

  cstruct arp {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa
  } as big_endian

  let create_gratituous_arp dl_src nw_src bits =
    let _ = set_arp_dst "\xff\xff\xff\xff\xff\xff" 0 bits in
    let _ = set_arp_src dl_src 0 bits in 
    let _ = set_arp_ethertype bits 0x0806 in 
    let _ = set_arp_htype bits 1 in 
    let _ = set_arp_ptype bits 0x0800 in 
    let _ = set_arp_hlen bits 6 in 
    let _ = set_arp_plen bits 4 in 
    let _ = set_arp_op bits 1 in 
    let _ = set_arp_sha dl_src 0 bits in 
    let _ = set_arp_spa bits nw_src in 
    let _ = set_arp_tha "\x00\x00\x00\x00\x00\x00" 0 bits in 
    let _ = set_arp_tpa bits nw_src in
      sizeof_arp
 

  let send_gratuitous_arp local_ip = 
    let controller = 
      (List.hd Sp_controller.switch_data.Sp_controller.of_ctrl) in 
    let dpid = 
      (List.hd Sp_controller.switch_data.Sp_controller.dpid)  in
    let nw_src = Uri_IP.string_to_ipv4 local_ip in
    let ip_stream = (Unix.open_process_in
                       (Config.dir ^ 
                        "/client_tactics/get_local_device br0")) in
    let test = Re_str.split (Re_str.regexp " ") 
                 (input_line ip_stream) in 
    let _::dl_src::_ = test in
    let dl_src = Net_cache.Arp_cache.mac_of_string dl_src in
    let data = OP.marshal_and_sub (create_gratituous_arp dl_src nw_src) 
                 (Lwt_bytes.create 512) in
    let pkt = 
          OP.Packet_out.create ~buffer_id:(-1l) 
            ~actions:[ OP.(Flow.Output(Port.All , 2000))] 
            ~data:data ~in_port:OP.Port.No_port () 
    in
    let bs = OP.marshal_and_sub (OP.Packet_out.marshal_packet_out pkt) 
               (Lwt_bytes.create 4096)  in 
      OC.send_of_data controller dpid bs
       
  let connect kind args =
    match kind with
    | "server" ->(
      try_lwt
        let port::node::rem_node::domain::conn_id::local_ip::_ = args in
        let conn_id = Int32.of_string conn_id in 
        lwt _ = get_domain_dev_id node domain port local_ip conn_id rem_node in
        lwt _ = send_gratuitous_arp local_ip in 
          return ("true")
      with e -> 
        eprintf "[openvpn] server error: %s\n%!" (Printexc.to_string e); 
        raise (OpenVpnError((Printexc.to_string e)))
    )
    | "client" -> (
      try_lwt
        let ip::port::node::rem_node::domain::conn_id::local_ip::_ = args in
        let conn_id = Int32.of_string conn_id in 
        let dev_id = Tap.get_new_dev_ip () in
        lwt _ = Tap.setup_dev dev_id local_ip in
        lwt _ = start_openvpn_daemon ip port node domain 
                  "client" dev_id in
        let pid = read_pid_from_file (Config.tmp_dir ^ "/" ^ 
                                      domain ^"/client.pid") in 
        let _ = Hashtbl.add conn_db.conns (domain) 
            {ip=ip;port=(int_of_string port);pid;
             dev_id;nodes=[node ^ "." ^ Config.domain]; conn_id;rem_node;} in
        lwt _ = send_gratuitous_arp local_ip in 
          return ("true")
      with ex ->
        Printf.printf "[opevpn] client error: %s\n%!" (Printexc.to_string ex);
        raise(OpenVpnError(Printexc.to_string ex)))
    | _ -> raise(OpenVpnError(
        (Printf.sprintf "[openvpn] invalid invalid action %s" kind)))

  let enable kind args =
    match kind with
    | "enable" ->(
      try_lwt
        let conn_id::mac_addr::local_ip::remote_ip::
            local_sp_ip::remote_sp_ip::_ = args in
        let conn_id = Int32.of_string conn_id in
        let [local_ip; remote_ip; local_sp_ip; remote_sp_ip;] = 
          List.map Uri_IP.string_to_ipv4 
            [local_ip; remote_ip; local_sp_ip; remote_sp_ip;] in 
        let dev_id = ref None in 
        let Some(conn) = 
          Hashtbl.fold 
            (fun _ conn -> function
               | None -> 
                   if (conn.conn_id = conn_id) then (
                     dev_id := Some(conn.dev_id);
                     Some(conn)
                   ) else (
                     None
                   )
               | Some(r) -> Some(r)
            ) conn_db.conns None in 
          match (!dev_id) with
            | None -> raise (OpenVpnError(("openvpn enable invalid conn_id")))
            | Some (dev) ->
                lwt _ = setup_flows (sprintf "tap%d" dev) mac_addr 
                          local_ip remote_ip local_sp_ip remote_sp_ip in
                lwt _ = Lwt_unix.sleep 1.0 in
                lwt _ = send_gratuitous_arp (Uri_IP.ipv4_to_string local_ip) in 
                let _ = Monitor.add_dst (Uri_IP.ipv4_to_string remote_sp_ip) 
                          conn.rem_node "openvpn" in
                  return true
      with e -> 
        eprintf "[openvpn] server error: %s\n%!" (Printexc.to_string e); 
        raise (OpenVpnError((Printexc.to_string e)))
    )    
    | _ -> raise(OpenVpnError(
        (Printf.sprintf "[openvpn] invalid invalid action %s" kind)))

  (* tearing down the flow that push traffic over the tunnel 
   * *)
  let unset_flows dev local_tun_ip remote_sp_ip = 
    let controller = 
      (List.hd Sp_controller.switch_data.Sp_controller.of_ctrl) in 
    let dpid = 
      (List.hd Sp_controller.switch_data.Sp_controller.dpid)  in

    lwt port = get_port dev in 
(*     let Some(port) = Net_cache.Port_cache.dev_to_port_id dev in *)

    (* outgoing flow removal *)
    let flow_wild = OP.Wildcards.({
      in_port=true; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 0); nw_src=(char_of_int 32);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match flow_wild 
                 ~dl_type:(0x0800) ~nw_dst:remote_sp_ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.DELETE_STRICT 
                ~priority:tactic_priority ~idle_timeout:0 
                ~buffer_id:(-1) [] () in 
    lwt _ = OC.send_of_data controller dpid
      (OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
          (Lwt_bytes.create 4096)) in
      
    (* Setup incoming flow *)
(*     let Some(port) = Net_cache.Port_cache.dev_to_port_id dev in *)
    let flow_wild = OP.Wildcards.({
      in_port=false; dl_vlan=true; dl_src=true; dl_dst=true;
      dl_type=false; nw_proto=true; tp_dst=true; tp_src=true;
      nw_dst=(char_of_int 0); nw_src=(char_of_int 32);
      dl_vlan_pcp=true; nw_tos=true;}) in
    let flow = OP.Match.create_flow_match flow_wild 
                 ~in_port:port ~dl_type:(0x0800) 
                 ~nw_dst:local_tun_ip () in
    let pkt = OP.Flow_mod.create flow 0L OP.Flow_mod.DELETE_STRICT
                ~priority:tactic_priority ~idle_timeout:0  
                ~buffer_id:(-1) [] () in 
      OC.send_of_data controller dpid 
        (OP.marshal_and_sub (OP.Flow_mod.marshal_flow_mod pkt) 
           (Lwt_bytes.create 4096))

  let teardown kind args = 
    match kind with
      | "teardown" ->
        let conn_id = Int32.of_string (List.hd args) in 
        let state = ref None in 
        let _ = 
          Hashtbl.iter 
            (fun _ conn -> 
               if (conn.conn_id = conn_id) then
                 state := Some(conn)) conn_db.conns in 
          match (!state) with
            | None -> raise (OpenVpnError(("disconnect invalid conn_id")))
            | Some (state) ->
                let _ = 
                  if ((List.length state.nodes) == 0) then
                    Unix.kill state.pid Sys.sigkill
                in 
                  return ("true")
      | _ -> (
          printf "[openvpn] disconnect action %s not supported in test" kind;
          return ("false"))

  let disable kind  args =
    match kind with 
      | "disable" ->
        try_lwt 
          let conn_id::local_tun_ip::remote_sp_ip::_ = args in
          let conn_id = Int32.of_string conn_id in
          let [local_tun_ip; remote_sp_ip;] = 
            List.map Uri_IP.string_to_ipv4 
              [local_tun_ip; remote_sp_ip;] in 
          let dev_id = ref None in 
          let _ = 
            Hashtbl.iter 
              (fun _ conn -> 
                 if (conn.conn_id = conn_id) then
                   dev_id := Some(conn.dev_id)) conn_db.conns in 
            match (!dev_id) with
              | None -> raise (OpenVpnError("teardown invalid conn_id"))
              | Some (dev) ->
                  (* disable required openflow flows *)
                lwt _ = unset_flows (sprintf "tap%d" dev) local_tun_ip 
                          remote_sp_ip in
                let _ = Monitor.del_dst (Uri_IP.ipv4_to_string remote_sp_ip) "openvpn" in
                   return ("true")
        with exn ->
          raise (OpenVpnError((Printexc.to_string exn)))
      | _ -> (
          printf "[openvpn] teardown action %s not supported in test" kind;
          return ("false"))
end
