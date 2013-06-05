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
open Lwt_process
open Printf

module OP = Openflow.Ofpacket

let openvpn_hello = "\x38\xca\xd4\x91\xc6\xb0\x0c\x4b\xfe\x00\x00\x00\x00\x00"

module Manager = struct
  exception OpenVpnError of string
  exception MissingOpenVPNArgumentError

  let tactic_priority = 4
  
  (* local state of the tactic*)
  type conn_type = {
    ip: int32;     (* tunnel node ip address *)
    port: int;     (* port number of the openvpn server*)
    pid: process_none;      (* pid of the process *)
    dev_id:int;    (* tun tap device id *)
    conn_id:int32; (* an id to map state with cloud state *)
    rem_node:string; 
    (* list of nodes participating in the tunnel *)
    mutable nodes: string list;
  }

  type conn_db_type = {
    (* connection details for a specific domain *)
    conns : (string, conn_type) Hashtbl.t;
    (* connected clients on server *)
    mutable server : process_none option;
    mutable clients: (string * int32) list;
    mutable server_dev_id : int;
  }

  let conn_db = 
    {conns=(Hashtbl.create 0); server=None;
     clients=[];server_dev_id=0;}

  (*
   * a helper function that waits until a newly installed dev
   * becomes available on openflow.
  * *)
  let rec get_port dev = 
    return (Net_cache.Port_cache.dev_to_port_id dev)

(*******************************************************
 *             Testing code 
 *******************************************************)

  let start_openvpn_client ip port rem_node dev_id = 
    (* Generate conf directories and keys *)
      let cmd = Config.dir ^ 
                "/client_tactics/openvpn/openvpn_client.sh" in
      let local_node = sprintf "%s.d%d.%s" (Nodes.get_local_name ())
                    Config.signpost_number Config.domain in 
      let exec_cmd = 
          sprintf "%s %d %d %s %s %s %s %s %s %d"
            cmd port dev_id local_node rem_node (Uri_IP.ipv4_to_string ip)
            Config.conf_dir Config.tmp_dir
            Config.iodine_node_ip Config.dns_port in
       printf "[openvpn] executing %s\n%!" exec_cmd;
      lwt _ = Lwt_unix.system exec_cmd in 
      let pid = 
        open_process_none 
          ("openvpn", 
            [|"--config"; 
            (Config.tmp_dir^"/"^rem_node^"/client.conf") ;|]) in 

      lwt _ = Lwt_unix.sleep 4.0 in      
       return (pid)
 
   let start_openvpn_daemon port = 
    (* Generate conf directories and keys *)
    match conn_db.server with
    | None -> 
      let cmd = Config.dir ^ 
                "/client_tactics/openvpn/openvpn_tactic.sh" in
      let dev_id = Tap.get_new_dev_ip () in 
      let _ = conn_db.server_dev_id <- dev_id in 
      let domain = sprintf "%s.d%d.%s" (Nodes.get_local_name ())
                    Config.signpost_number Config.domain in 
      let exec_cmd = 
        if ((Nodes.get_local_name ()) = "unknown" ) then
          sprintf "%s %d %d %s d%d %s %s"
            cmd port dev_id Config.domain Config.signpost_number
            Config.conf_dir Config.tmp_dir
        else
          sprintf "%s %d %d %s %s.d%d %s %s"
            cmd port dev_id Config.domain (Nodes.get_local_name ())
            Config.signpost_number Config.conf_dir Config.tmp_dir in
        printf "[openvpn] executing %s\n%!" exec_cmd;
      lwt _ = Lwt_unix.system exec_cmd in 
      let pid = 
        open_process_none 
          ("openvpn", 
            [|"--config"; 
              (Config.tmp_dir^"/"^domain^"/server.conf") ;|]) in 
   
      lwt _ = Lwt_unix.sleep 1.0 in      
      let _ = conn_db.server <- Some pid in 
        return (pid)
    | Some pid -> return (pid) 

(*
 * a udp client to send data. 
 * *)
  let run_client port ips =
    let buf = String.create 1500 in
    let sock = socket PF_INET SOCK_DGRAM 0 in   
    let send_pkt_to port ip =
      let ipaddr = (Unix.gethostbyname ip).Unix.h_addr_list.(0) in
      let portaddr = Unix.ADDR_INET (ipaddr, port) in
        lwt _ = Lwt_unix.sendto sock  openvpn_hello 0 
                  (String.length openvpn_hello) [] portaddr in 
          return ()
    in
    let _ = 
      try
        (* Lwt_unix.bind sock (Lwt_unix.ADDR_INET (Unix.inet_addr_any, port)));
        *)
        Lwt_unix.setsockopt sock Unix.SO_REUSEADDR true
      with Unix.Unix_error (e, _, _) ->
        printf "[openvpn] error: %s\n%!" (Unix.error_message e);
        raise (OpenVpnError("Couldn't bind udp client fd"))
    in
    lwt _ = Lwt_list.iter_p (send_pkt_to port) ips in
     try_lwt 
       let ret = ref None in 
       let recv = 
         (lwt (_, addr) = Lwt_unix.recvfrom sock buf 0 1500 [] in
       let _ = 
         match addr with 
         | ADDR_INET(ip, _) -> ret := Some(Unix.string_of_inet_addr ip )
         | _ -> failwith "[openvpn] run_client failed with a bad response addr"
       in
         return ()) in
       lwt _ = (Lwt_unix.sleep 4.0) <?> recv in 
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
          let port = 
            match args with 
            | port::_  -> int_of_string port
            | _ -> failwith "Insufficient args"
          in
          lwt _ = start_openvpn_daemon port in  
           return ("OK"))
     (* code to send udp packets to the destination*)
      | "client" -> (
          let port, ips = 
            match args with 
            | port :: ips -> (int_of_string port, ips) 
            | _ -> failwith "Insufficient args"
          in 
          lwt ip = run_client port ips in
          let _ = printf "[openvpn] Reply from %s \n%!" ip in
            return (ip))
      | _ -> (
          printf "[openvpn] Action %s not supported in test" kind;
          return ("OK"))

  (***************************************************************
   * Connection code 
   * ************************************************************)
  let setup_flows dev mac_addr local_ip rem_ip local_sp_ip 
        remote_sp_ip = 
    (* outgoing flow configuration *)
    lwt port = get_port dev in 
    (*     let Some(port) = Net_cache.Port_cache.dev_to_port_id dev in *)
    let actions = [ OP.Flow.Set_nw_src(local_ip);
                    OP.Flow.Set_nw_dst(rem_ip);
                    OP.Flow.Set_dl_dst(
                      (Net_cache.mac_of_string mac_addr));
                    OP.Flow.Output((OP.Port.port_of_int port), 
                                   2000);] in
    lwt _ = Sp_controller.setup_flow ~dl_type:(Some(0x0800)) ~nw_dst_len:0 
                 ~nw_dst:(Some(remote_sp_ip)) ~priority:tactic_priority 
                 ~idle_timeout:0 ~hard_timeout:0 actions in    
    
    (* setup arp handling for 10.3.0.0/24 *)
    lwt _ = Sp_controller.setup_flow ~dl_type:(Some(0x0806)) 
              ~in_port:(Some(port)) ~nw_dst_len:8 ~nw_dst:((Some(rem_ip))) 
              ~nw_src_len:8 ~nw_src:(Some(local_ip)) 
              ~priority:tactic_priority ~idle_timeout:0 ~hard_timeout:0
              [OP.Flow.Output(OP.Port.Local,2000)] in

    (* get local mac address *)
    let ip_stream = 
      (Unix.open_process_in
         (Config.dir^"/client_tactics/get_local_device " ^ 
         Config.bridge_intf )) in
    let ips = Re_str.split (Re_str.regexp " ") 
                (input_line ip_stream) in 
    let mac = Net_cache.mac_of_string (List.nth ips 1) in
    
    (* Setup incoming flow *)
    let actions = [ OP.Flow.Set_nw_dst(local_sp_ip);
                     OP.Flow.Set_nw_src(remote_sp_ip); 
                    OP.Flow.Set_dl_dst(mac);
                    OP.Flow.Output(OP.Port.Local, 2000);] in
    lwt _ = Sp_controller.setup_flow ~in_port:(Some(port))
              ~dl_type:(Some(0x0800)) ~nw_dst_len:0 
                 ~nw_dst:(Some(local_ip)) ~priority:tactic_priority 
                 ~idle_timeout:0 ~hard_timeout:0 actions in    
      return ()

      
 (* start server *)
  let server_append_dev rem_node =
    let cmd = Config.dir ^ 
              "/client_tactics/openvpn/openvpn_append_device.sh" in
    let exec_cmd =  
      (* nusty hack to know if you are running on a server or a client *)
      if ((Nodes.get_local_name ()) = "unknown" ) then
        sprintf "%s d%d.%s %s %s %s %s %d"
          cmd Config.signpost_number Config.domain rem_node 
          Config.conf_dir Config.tmp_dir 
          Config.external_dns 5354  
      else
        sprintf "%s %s.d%d.%s %s %s %s %s %d"
          cmd  (Nodes.get_local_name ()) Config.signpost_number 
          Config.domain rem_node Config.conf_dir 
          Config.tmp_dir Config.external_dns 5354
    in
    let _ = printf "[openvpn] executing %s\n%!" exec_cmd in 
      Lwt_unix.system exec_cmd  
  
 (* This method will check if a server listening for a specific 
  * domain is running or not, and handle certificates appropriately. *)
 let get_domain_dev_id port ip rem_node conn_id = 
   lwt pid = start_openvpn_daemon port in 
    if (List.mem (rem_node, conn_id) conn_db.clients) then (
      (* A connection already exists *)
      let _ = printf "[openvpn] node %s is already added\n%!" rem_node in
      return (conn_db.server_dev_id)
    ) else (
      (* Add domain to server and restart service *)
      let _ = printf "[openvpn] adding device %s\n%!" rem_node in 
      let _ = server_append_dev rem_node in
      let _ = conn_db.clients <- 
        conn_db.clients @ [(rem_node, conn_id)] in
        (* restart server *)
      let _ = Unix.kill (pid#pid) Sys.sighup in 
      lwt _ = Lwt_unix.sleep 2.0 in
      lwt _ = Tap.setup_dev conn_db.server_dev_id
              (Uri_IP.ipv4_to_string ip) in
        return (conn_db.server_dev_id))

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
 

  let send_gratuitous_arp nw_src = 
    let ip_stream = (Unix.open_process_in
                       (Config.dir ^ 
                        "/client_tactics/get_local_device " ^
                        Config.bridge_intf)) in
    let test = Re_str.split (Re_str.regexp " ") 
                 (input_line ip_stream) in 
    let dl_src = Net_cache.mac_of_string (List.nth test 1) in
    let data = OP.marshal_and_sub (create_gratituous_arp dl_src nw_src) 
                 (Cstruct.create 512) in
    lwt _ = Sp_controller.send_packet data [ OP.(Flow.Output(Port.All , 2000))] in
      return ()

  let connect kind args =
    match kind with
    | "server" ->(
      try_lwt
        let (port, rem_node, conn_id, local_ip) =
          match args with 
          | port::rem_node::conn_id::local_ip::_ ->
              (int_of_string port, rem_node, Int32.of_string conn_id,
              Uri_IP.string_to_ipv4 local_ip)
          | _ -> failwith "Insufficient args"
        in
        lwt _ = get_domain_dev_id port local_ip rem_node conn_id in
        lwt _ = send_gratuitous_arp local_ip in 
          return ("true")
      with e -> 
        eprintf "[openvpn] server error: %s\n%!" (Printexc.to_string e); 
        raise (OpenVpnError((Printexc.to_string e)))
    )
    | "client" -> (
      try_lwt
        let (ip, port, rem_node, conn_id, local_ip) =
          match args with
          | ip::port::rem_node::conn_id::local_ip::_ ->
              (Uri_IP.string_to_ipv4 ip, int_of_string port, 
              rem_node, Int32.of_string conn_id, 
              Uri_IP.string_to_ipv4 local_ip)
          | _ -> failwith "Insufficient args"
        in
        let dev_id = Tap.get_new_dev_ip () in
        lwt proc = start_openvpn_client ip port rem_node dev_id in 
        lwt _ = Tap.setup_dev dev_id  
                  (Uri_IP.ipv4_to_string local_ip) in
        let _ = Hashtbl.replace conn_db.conns rem_node 
            {ip;port;pid=proc;dev_id;nodes=[rem_node];
            conn_id;rem_node;} in
        lwt _ = send_gratuitous_arp local_ip in 
          return ("true")
      with ex ->
        Printf.printf "[opevpn] client error: %s\n%!" (Printexc.to_string ex);
        raise(OpenVpnError(Printexc.to_string ex)))
    | _ -> raise(OpenVpnError(
        (Printf.sprintf "[openvpn] invalid invalid action %s" kind)))

  let map_conn_id conn_id = 
    let conn = 
      List.fold_right (
        fun (node, id) r -> 
          if (id = conn_id) then Some(conn_db.server_dev_id, node)
          else r ) conn_db.clients None in 
      Hashtbl.fold 
            (fun _ conn r -> 
               if (conn.conn_id = conn_id) then 
                 Some(conn.dev_id, conn.rem_node)
               else r ) conn_db.conns conn 
 
  let enable kind args =
    match kind with
    | "enable" ->(
      try_lwt
        let (conn_id, mac_addr, local_ip, remote_ip, 
        local_sp_ip, remote_sp_ip) = 
          match args with
          | conn_id::mac_addr::local_ip::remote_ip::
            local_sp_ip::remote_sp_ip::_ -> 
              (Int32.of_string conn_id, mac_addr, 
              Uri_IP.string_to_ipv4 local_ip, 
              Uri_IP.string_to_ipv4 remote_ip,
              Uri_IP.string_to_ipv4 local_sp_ip, 
              Uri_IP.string_to_ipv4 remote_sp_ip)
          | _ -> failwith "Insufficient args"
        in
         match (map_conn_id conn_id) with
            | None -> 
                raise (OpenVpnError(("openvpn enable invalid conn_id")))
            | Some (dev_id, rem_node) ->
                lwt _ = setup_flows (sprintf "tap%d" dev_id) 
                          mac_addr local_ip remote_ip local_sp_ip 
                          remote_sp_ip in
                lwt _ = Lwt_unix.sleep 1.0 in
                lwt _ = send_gratuitous_arp local_ip in 
                let _ = Monitor.add_dst (Uri_IP.ipv4_to_string remote_sp_ip) 
                          rem_node "openvpn" in
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
    lwt port = get_port dev in 
(*     let Some(port) = Net_cache.Port_cache.dev_to_port_id dev in *)

    (* outgoing flow removal *)
    lwt _ = Sp_controller.delete_flow ~dl_type:(Some(0x0800))
             ~nw_dst_len:0 ~nw_dst:(Some(remote_sp_ip)) ~priority:tactic_priority 
             () in  
    (* Setup incoming flow *)
(*     let Some(port) = Net_cache.Port_cache.dev_to_port_id dev in *)
    lwt _ = Sp_controller.delete_flow ~in_port:(Some(port)) ~dl_type:(Some(0x0800))
             ~nw_dst_len:0 ~nw_dst:(Some(local_tun_ip)) ~priority:tactic_priority () in  
      return ()
  let teardown kind args = 
    match kind with
      | "teardown" -> begin
        let conn_id = Int32.of_string (List.hd args) in
        let _ = 
          conn_db.clients <- 
            List.filter 
            ( fun (_, id) -> not (id = conn_id) ) conn_db.clients in 
        let conn = 
          Hashtbl.fold (fun n c r -> 
            if (c.conn_id = conn_id) then (Some (n, c) ) 
            else r ) conn_db.conns None in  
        match conn with
            | None -> raise (OpenVpnError(("disconnect invalid conn_id")))
            | Some (node, conn) ->
                let _ = Hashtbl.remove conn_db.conns node in 
                let _ = 
                  if ((List.length conn.nodes) == 0) then
                    conn.pid#terminate
                in 
                  return ("true")
      end
      | _ -> (
          printf "[openvpn] disconnect action %s not supported in test" kind;
          return ("false"))

  let disable kind  args =
    match kind with 
      | "disable" -> begin
        try_lwt 
          let (conn_id, local_tun_ip, remote_sp_ip) =
            match args with 
            | conn_id::local_tun_ip::remote_sp_ip::_ ->
                (Int32.of_string conn_id, Uri_IP.string_to_ipv4 local_tun_ip, 
                Uri_IP.string_to_ipv4 remote_sp_ip)
            | _ -> failwith "Insufficient args"
          in
          match (map_conn_id conn_id) with
              | None -> raise (OpenVpnError("teardown invalid conn_id"))
              | Some (_, dev) ->
                  (* disable required openflow flows *)
                lwt _ = unset_flows (sprintf "tap%s" dev) local_tun_ip 
                          remote_sp_ip in
                let _ = Monitor.del_dst (Uri_IP.ipv4_to_string remote_sp_ip) "openvpn" in
                   return ("true")
        with exn ->
          raise (OpenVpnError((Printexc.to_string exn)))
      end
      | _ -> (
          printf "[openvpn] teardown action %s not supported in test" kind;
          return ("false"))
end
