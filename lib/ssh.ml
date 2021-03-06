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

let ssh_port = 10000
let tactic_priority = 5 

module OP = Openflow.Ofpacket
module OC = Openflow.Ofcontroller

module Manager = struct
  exception SshError of string
  exception MissingSshArgumentError

  let get_port_id dev = 
    let rec get_port_id_inner dev = function
      | 0 -> raise Not_found
      | c -> 
          try_lwt 
            let port = Net_cache.Port_cache.dev_to_port_id dev in
              return port
          with Not_found -> 
            lwt _ = Lwt_unix.sleep 1.0 in 
              get_port_id_inner dev (c-1)
    in
      get_port_id_inner dev 5


  (**************************************************
   *         Tactic state
   **************************************************)

  type conn_type =
    | SSH_SERVER
    | SSH_CLIENT

 (* storing all required informations to rebuild 
   * authorized_keys file and destroy the connection *)
  type client_det = {
    key: string;
    ip: int32;
    port : int;
    conn_id: int32;
    dev_id : int;
    mutable pid : int;
    conn_tp : conn_type;
    rem_node: string; 
  }

  type conn_db_type = {
    conns: (string, client_det) Hashtbl.t;
    mutable server_pid: int option;
  }

  let conn_db = {conns=(Hashtbl.create 32); 
                 server_pid=None;}

(**********************************************************
 *  Init methods
 * *)

  let init_module () = 
   (* TODO: 
    * - Remove all tap* devices.
    * - kill previous sshd server. 
    * *)
    return ()
  let destroy_module () = 
  init_module ()

  (*********************************************************
   *       Testing methods
   *********************************************************)

  (* start the sshd server *)
  let run_server () =
    (* TODO: Check if pid is still running *)
    match conn_db.server_pid with
    | None -> begin
      try
        let cmd = Config.dir ^ "/client_tactics/ssh/server" in
        printf "%s %s\n%!" cmd Config.conf_dir;
        let _ = Unix.create_process cmd [| cmd; Config.conf_dir |] 
        Unix.stdin Unix.stdout Unix.stderr in
        lwt _ = Lwt_unix.sleep 2.0 in 
        let fd = open_in "/tmp/signpost_sshd.pid" in
        let buf = input_line fd in
        let _ = close_in fd in 
        let _ = conn_db.server_pid <- Some(int_of_string buf) in
        let _ = Printf.printf "[ssh] server pid %s...\n" buf in 
          return("OK")
      with err ->
        let _ = Printf.eprintf "[ssh] error : %s\n%!" (Printexc.to_string err) in
          failwith  (Printexc.to_string err)
      end
      | Some(_) -> 
          let _ = Printf.printf "[ssh] server running...\n%!" in
            return("OK")

  (*TODO:
   * - timeout connect 
   * - if all tests fail how do I notify the server? 
   * - remove ips that match local ips *)
  let run_client port ips =
    let ret = ref None in 
    (* check if I can connect to ssh port on a remote ip *)
    let send_pkt_to wakener port ip = 
      try_lwt 
        let buf = String.create 1500 in
        let sock = (Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM
                      ((Unix.getprotobyname "tcp").Unix.p_proto)) in        
        let ipaddr = (Unix.gethostbyname ip).Unix.h_addr_list.(0) in
        let portaddr = Unix.ADDR_INET (ipaddr, port) in
          (* TODO: Need to get a better timeout mechanism in connect phase 
           * otherwise we will wiat for 2 min *)
        lwt _ = Lwt_unix.connect sock portaddr in 
        (* If no data received in 2 seconds, fail the thread. *)
        let _ = setsockopt_float sock SO_RCVTIMEO 2.0 in 
        lwt len = Lwt_unix.recv sock buf 0 1500 [] in  
          Printf.printf "[ssh] Received (%s) from ipaddr %s\n%!" 
            (String.sub buf 0 len) ip;
          lwt _ = Lwt_unix.close sock in
            ret := Some(ip);
            let _ = Lwt.wakeup wakener () in 
              return () 
      with
          ex ->
            Printf.eprintf "[ssh] error in client test %s\n%!" (Printexc.to_string ex);
            return ()
    in
    (* Run client test for all remote ips and return the ip that reasponded
    * first *)
    let listener, wakener = Lwt.task () in 
(*     lwt _ = Lwt.choose [(Lwt_list.iter_p (send_pkt_to wakener port) ips);
 *     sleeper] in  *)
     Lwt.ignore_result(Lwt_list.iter_p (send_pkt_to wakener port) ips);
     lwt _ = (Lwt_unix.sleep 2.0) <?> listener in 
       match (!ret) with
         | None -> raise (SshError("Error"))
         | Some(ip) -> return (ip)

  let test kind args =
    match kind with
      (* start ssh server *)
      | "server_start" -> 
          run_server ()
      (* test tcp connectivity *)
      | "client" -> (
          try_lwt
            let ssh_port, ips = 
              match args with 
                | ssh_port :: ip -> ssh_port, ip
                | _ -> raise (SshError("insufficient client params"))
            in 
            let ssh_port = int_of_string ssh_port in
            lwt ip = ((lwt _ = Lwt_unix.sleep 2.0 in 
                         failwith("client can't connect") ) 
                        <?> (run_client ssh_port ips)) in
              return (ip)
          with ex ->
            Printf.printf "[ssh] failed to start client: %s\n%!" 
              (Printexc.to_string ex);
            raise(SshError(Printexc.to_string ex)) )
      | _ -> (
          Printf.printf "Action %s not supported in test" kind;
          return ("OK"))

  (*******************************************************************
   *    connection functions     
   *******************************************************************)

  let server_add_client conn_id domain rem_extern_ip loc_dev_id 
        rem_node = 
    Printf.printf "[ssh] Adding new key from domain %s\n%!" domain;
    lwt _ = run_server () in 
    (* Dump keys in authorized_key file *)
    let update_authorized_keys () = 
      let file = 
        open_out 
          (sprintf "%s/.ssh/signpost_tunnel" Config.root_dir) in 
        Hashtbl.iter (fun _ client ->
                        if (client.conn_tp = SSH_CLIENT) then
                             output_string file (client.key ^ "\n") 
        ) conn_db.conns; 
        close_out file
    in
      (* if the domain is not in the cache, add it and update 
       * the authorized key file *)
    lwt _ = 
      if(Hashtbl.mem conn_db.conns domain) then (
        eprintf "[ssh] connection already exists\n%!";
        return ()
      ) else (
        lwt key = Key.ssh_pub_key_of_domain 
                    ~server:(Config.iodine_node_ip) 
                    ~port:5354 domain in
          match key with 
            | Some(key) -> 
                Hashtbl.add conn_db.conns domain 
                  {key=(List.hd key);ip=rem_extern_ip;
                   port=0; conn_id; dev_id=(loc_dev_id);
                   pid=0;  conn_tp=SSH_CLIENT; rem_node;};
                return (update_authorized_keys ())
            | None ->
                return (Printf.printf 
                          "[ssh] Couldn't find dnskey record\n%!")
        )
      in
        return ("OK")

  let client_add_server conn_id node ip port dev_id rem_node = 
    Printf.printf "[ssh] Adding know_host domain %s\n%!" node;
    let domain = sprintf "%s.%s" node Config.domain in
    (* Dump keys in authorized_key file *)
    let update_known_hosts () = 
      let file = open_out (Config.conf_dir ^ "/known_hosts") in 
      let _ = 
        Hashtbl.iter 
          (fun _ server ->
             if (server.conn_tp = SSH_SERVER) then
                 output_string file (sprintf "[%s]:%d %s\n" 
                                       (Uri_IP.ipv4_to_string server.ip)
                                       server.port server.key)) 
          conn_db.conns 
      in
        close_out file
    in
      (* if the domain is not in the cache, add it and update the authorized
       * key file *)    
    lwt _ = 
      if(Hashtbl.mem conn_db.conns domain) then (
        Printf.eprintf "[ssh] A connection already exists\n%!";
        return ()
      ) else (
        lwt key = Key.ssh_pub_key_of_domain 
                    ~server:(Config.iodine_node_ip) ~port:5354 domain in
          match key with 
            | Some(key) -> 
(*                 let domain = sprintf "%s.%s" node Config.domain in *)
                Hashtbl.add conn_db.conns domain 
                  {key=(List.hd key);port;ip; conn_id;dev_id;pid=0;
                  conn_tp=SSH_SERVER; rem_node;};
                return (update_known_hosts ())
            | None ->
                return (Printf.printf "[ssh] no valid dnskey record\n%!")
      )
    in
      return ("OK")

  let client_connect server_ip server_port local_dev remote_dev = 
    let cmd = Unix.getcwd () ^ "/client_tactics/ssh/client" in
    (* TODO: add pid in client state. *)
    let pid = Unix.create_process cmd [|cmd; Config.conf_dir; server_ip;
                                        (string_of_int server_port);
                                        (string_of_int local_dev);
                                        (string_of_int remote_dev); |] 
              Unix.stdin Unix.stdout Unix.stderr in
      return (pid)

  let setup_flows dev mac_addr local_ip rem_ip local_sp_ip 
        remote_sp_ip =
          let _ = printf "looking for %s\n%!" dev in 
    lwt port = get_port_id dev in
          let _ = printf "found %s\n%!" dev in 
    let actions = [ OP.Flow.Set_nw_src(local_ip);
                    OP.Flow.Set_nw_dst(rem_ip);
                    OP.Flow.Set_dl_dst(
                      (Net_cache.mac_of_string mac_addr));                    
                    OP.Flow.Output((OP.Port.port_of_int port), 
                                   2000);] in
    lwt _ = Sp_controller.setup_flow ~dl_type:(Some(0x0800)) 
                 ~nw_dst_len:0 ~nw_dst:(Some(remote_sp_ip))
                 ~priority:tactic_priority  ~idle_timeout:0 
                ~hard_timeout:0 actions in 

    (* get local mac address *)
    let ip_stream = (Unix.open_process_in
                       (Config.dir ^ 
                        "/client_tactics/get_local_device br0")) in
    let ips = Re_str.split (Re_str.regexp " ") (input_line ip_stream) in 
    let mac = Net_cache.mac_of_string (List.nth ips 1) in

    (* setup incoming flow *)
    let actions = [ OP.Flow.Set_nw_dst(local_sp_ip);
                     OP.Flow.Set_nw_src(remote_sp_ip); 
                    OP.Flow.Set_dl_dst(mac);
                    OP.Flow.Output(OP.Port.Local, 2000);] in
      Sp_controller.setup_flow ~dl_type:(Some(0x0800)) 
        ~nw_dst_len:0 ~nw_dst:(Some(local_ip))
        ~in_port:(Some(port)) ~priority:tactic_priority 
        ~idle_timeout:0 ~hard_timeout:0 actions

  let connect kind args =
    try_lwt
      match kind with
          | "start_server" -> begin
               let rem_domain,rem_node,conn_id,rem_sp_ip,loc_tun_ip = 
                match args with 
                  | rem_domain::rem_node::conn_id::rem_sp_ip::loc_tun_ip::_ -> 
                    (rem_domain, rem_node, (Int32.of_string conn_id), 
                   (Uri_IP.string_to_ipv4 rem_sp_ip), loc_tun_ip)
                  | _ -> raise(SshError("connect Insufficient params"))
               in 
               let dev_id = Tap.get_new_dev_ip () in 
               (* Adding remote node public key in authorized keys file *)
               let q_rem_domain = sprintf "%s.%s" rem_domain Config.domain in
               let _ = server_add_client conn_id q_rem_domain rem_sp_ip dev_id rem_node in
                 return (string_of_int dev_id)
          end
          | "connect_server" -> begin
          let rem_domain,rem_node,conn_id,rem_sp_ip,loc_tun_ip,dev_id = 
            match args with 
            | rem_domain::rem_node::conn_id::rem_sp_ip::loc_tun_ip::dev_id::_ -> 
              (rem_domain, rem_node, (Int32.of_string conn_id), 
               (Uri_IP.string_to_ipv4 rem_sp_ip), loc_tun_ip, 
               (int_of_string dev_id) )
            | _ -> raise (SshError("connect Insufficient params"))
          in 
  
          (* Setup tunel tun tap device *)
          lwt _ = Tap.setup_dev dev_id loc_tun_ip in 

           return(string_of_int dev_id)
          end
        | "client" ->
          let (server_ip, ssh_port, rem_domain, rem_node, 
              conn_id, loc_tun_ip, rem_dev) =
                match args with
                | server_ip::ssh_port::rem_domain::rem_node::conn_id::
                  loc_tun_ip::rem_dev:: _ -> 
                (Uri_IP.string_to_ipv4 server_ip, int_of_string ssh_port, 
                rem_domain, rem_node,
                Int32.of_string conn_id, loc_tun_ip, int_of_string rem_dev)
                | _ ->  failwith "Insufficient args" 
          in
          let loc_dev = Tap.get_new_dev_ip () in 
          lwt _ = client_add_server conn_id rem_domain
                    server_ip ssh_port loc_dev rem_node in
          lwt pid = 
            client_connect (Uri_IP.ipv4_to_string server_ip) 
            ssh_port loc_dev rem_dev in
          lwt _ = Lwt_unix.sleep 2.0 in 
          lwt _ = Tap.setup_dev loc_dev loc_tun_ip in
          (* update pid from client state *)
          let domain = sprintf "%s.%s" rem_domain Config.domain in
          let conn = Hashtbl.find conn_db.conns domain in 
          let _ = conn.pid <- pid in 
            return (string_of_int loc_dev)
        | _ -> 
            Printf.eprintf "[ssh] Invalid connect kind %s\n%!" kind;
            raise (SshError("Invalid connect kind"))
      with exn ->
        Printf.eprintf "[ssh]Error:%s\n%!" (Printexc.to_string exn);
        raise (SshError(Printexc.to_string exn))
(*
 * tunnel enabling code
 * *)
  let setup_flows dev mac_addr local_ip rem_ip local_sp_ip 
        remote_sp_ip = 
    
    let _ = printf "looking for dev %s\n%!" dev in 
    let port = Net_cache.Port_cache.dev_to_port_id dev in
    let _ = printf "found dev %s\n%!" dev in 
    let actions = [ OP.Flow.Set_nw_src(local_ip);
                    OP.Flow.Set_nw_dst(rem_ip);
                    OP.Flow.Set_dl_dst(
                      (Net_cache.mac_of_string mac_addr));                    
                    OP.Flow.Output((OP.Port.port_of_int port), 
                                   2000);] in
    lwt _ = Sp_controller.setup_flow ~dl_type:(Some(0x0800)) 
                 ~nw_dst_len:0 ~nw_dst:(Some(remote_sp_ip))
                 ~priority:tactic_priority  ~idle_timeout:0 
                ~hard_timeout:0 actions in 
    
    (* get local mac address *)
    let ip_stream = (Unix.open_process_in
                       (Config.dir ^ 
                        "/client_tactics/get_local_device "
                        ^ Config.bridge_intf)) in
    let ips = Re_str.split (Re_str.regexp " ") (input_line ip_stream) in 
    let mac = Net_cache.mac_of_string (List.nth ips 1) in

    (* setup incoming flow *)
    let actions = [ OP.Flow.Set_nw_dst(local_sp_ip);
                     OP.Flow.Set_nw_src(remote_sp_ip); 
                    OP.Flow.Set_dl_dst(mac);
                    OP.Flow.Output(OP.Port.Local, 2000);] in
      Sp_controller.setup_flow ~dl_type:(Some(0x0800)) 
        ~nw_dst_len:0 ~nw_dst:(Some(local_ip))
        ~in_port:(Some(port)) ~priority:tactic_priority 
        ~idle_timeout:0 ~hard_timeout:0 actions

  let enable kind args =
    try_lwt
      match kind with
        | "enable" -> begin
          let (conn_id,mac_addr,local_ip,remote_ip,local_sp_ip,remote_sp_ip) =
            match args with
            | conn_id::mac_addr::local_ip::remote_ip::local_sp_ip::remote_sp_ip::_ ->
              (Int32.of_string conn_id, mac_addr, 
              Uri_IP.string_to_ipv4 local_ip,
              Uri_IP.string_to_ipv4 remote_ip,
              Uri_IP.string_to_ipv4 local_sp_ip,
              Uri_IP.string_to_ipv4 remote_sp_ip)
            | _ -> failwith "Insufficient args" in
          let _ = printf "looking for id %ld\n%!" conn_id in 
          let conn = 
            Hashtbl.fold 
              (fun _ conn r -> 
                if (conn.conn_id = conn_id) then 
                  Some(conn)
                      else r ) conn_db.conns None in 
          let _ = printf "finished looking for id %ld\n%!" conn_id in 
          lwt _ = match conn with
              | None -> 
                  raise (SshError(("openvpn enable invalid conn_id")))
              | Some conn ->
                  lwt _ = setup_flows (sprintf "tap%d" conn.dev_id) mac_addr 
                            local_ip remote_ip local_sp_ip remote_sp_ip in
                  let _ = Monitor.add_dst (Uri_IP.ipv4_to_string remote_sp_ip) 
                            conn.rem_node "ssh" in
                  return ()
 
          in
           return ("true")
          end
        | _ -> 
            raise (SshError(sprintf "[openvpn] invalid enable action %s" kind))
      with exn ->
        let _ = eprintf "[ssh]Error:%s\n%!" (Printexc.to_string exn) in 
        raise (SshError(Printexc.to_string exn))

(*
 * tunnel disabling code
 * *)
  let unset_flows dev local_tun_ip remote_sp_ip = 
    lwt _ = Sp_controller.delete_flow ~dl_type:(Some(0x0800)) 
              ~nw_dst_len:0 ~nw_dst:(Some(remote_sp_ip)) 
              ~priority:tactic_priority () in
    
    (* setup incoming flow *)
    let port = Net_cache.Port_cache.dev_to_port_id dev in

      Sp_controller.delete_flow ~dl_type:(Some(0x0800)) 
        ~in_port:(Some(port)) ~nw_dst_len:0 ~nw_dst:(Some(local_tun_ip)) 
        ~priority:tactic_priority () 

  let disable kind args =
    try_lwt
      match kind with
        | "disable" -> begin
          let (conn_id, local_tun_ip, remote_sp_ip) = 
            match args with 
            | conn_id::local_tun_ip::remote_sp_ip::_ ->
                (Int32.of_string conn_id, Uri_IP.string_to_ipv4 local_tun_ip,
                Uri_IP.string_to_ipv4 remote_sp_ip) 
            | _ -> failwith "Insufficient args"
          in
          let dev_id = 
            Hashtbl.fold 
              (fun _ conn r -> 
                 if (conn.conn_id = conn_id) then
                   Some(conn.dev_id)
                 else r ) conn_db.conns None in 
           let _ = Monitor.del_dst (Uri_IP.ipv4_to_string remote_sp_ip) "ssh" in
             match dev_id with
              | None -> 
                  raise (SshError(("openvpn disable invalid conn_id")))
              | Some (dev) ->
                  (lwt _ = unset_flows (sprintf "tap%d" dev)  
                            local_tun_ip remote_sp_ip in
                    return "true")
          end
        | _ -> 
            raise (SshError(sprintf "[ssh] unknown disable action %s" kind))
      with exn ->
        Printf.eprintf "[ssh]Error:%s\n%!" (Printexc.to_string exn);
        raise (SshError(Printexc.to_string exn))

  (*************************************************************************
   *             TEARDOWN methods of tactic
   * ***********************************************************************)

  let teardown kind args =
    try_lwt
      match kind with
        | "teardown" -> begin
          let (conn_id, local_tun_ip) = 
            match args with
              | conn_id::local_tun_ip::_ ->
                  Int32.of_string conn_id, local_tun_ip
              | _ -> failwith "Insufficient args"
          in
          let domain = 
            Hashtbl.fold
                (fun dom conn r -> 
                   if (conn.conn_id = conn_id) then
                     Some(dom)
                   else r) conn_db.conns None in 
            match domain with
              | None -> 
                  raise (SshError(("ssh.teardown invalid conn_id")))
              | Some (domain) -> begin
                  (* 1. delete link from local state *)
                  let conn = Hashtbl.find conn_db.conns domain in 
                  let _ = Hashtbl.remove conn_db.conns domain in 
                  
                  (* 2. kill process if required*)
                  let _ = 
                    if (conn.conn_tp = SSH_SERVER) then
                      Unix.kill conn.pid Sys.sigkill
                  in
                  (* 3. release tap device  and any possible ip allocation *)
                    Tap.unset_dev conn.dev_id local_tun_ip >> 
                    return "true"
                end
          end
        | _ -> 
            eprintf "[ssh] Invalid kind %s for action teardown\n%!" kind; 
            return "false"
    with ex ->
      eprintf "[ssh] Teardown error: %s\n%!" (Printexc.to_string ex);
      raise (SshError(Printexc.to_string ex))

  let pkt_in_cb _ _ _ = return ()

end
