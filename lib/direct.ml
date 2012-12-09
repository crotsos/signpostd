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
  exception DirectError of string
  exception MissingDirectArgumentError

  let tactic_priority = 6
  
  
  (* local state of the tactic*)
  type conn_type = {
    ip: string;    (* tunnel node ip address *)
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
(*******************************************************
 *             Testing code 
 *******************************************************)

(*
 * setup an echo udp listening socket. 
 *
 * *)
  let run_server port =
    Printf.printf "[direct] Starting udp server\n%!";
    let buf = String.create 1500 in
    let sock =Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_DGRAM
              (Unix.getprotobyname "udp").Unix.p_proto in
    let _ = 
      try
        (Lwt_unix.bind sock (Lwt_unix.ADDR_INET (Unix.inet_addr_any,
        port)))
      with Unix.Unix_error (e, _, _) ->
        printf "[direct] error: %s\n%!" (Unix.error_message e);
        raise (DirectError("Couldn't be a udp server"))
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
           | None -> raise (DirectError("Unreachable server"))
           | Some(ip) -> return (ip)
     with err -> 
       eprintf "[direct] client test error: %s\n%!" 
         (Printexc.to_string err);
        raise (DirectError(Printexc.to_string err))

  let test kind args =
    try_lwt 
      match kind with
        (* start udp server *)
        | "server_start" -> (
            let port = (int_of_string (List.hd args)) in 
           let _ = run_server port in
              return ("OK"))
        (* code to stop the udp echo server*)
        | "server_stop" -> (
          match conn_db.can with
            | Some t ->
                let _ = cancel t in
                let _ = conn_db.can <- None in 
                let _ = 
                  match conn_db.fd with
                   | Some(fd) -> 
                       let _ = Lwt_unix.close fd in
                       let _ = conn_db.fd <- None in
                         ()
                   | _ -> ()
                in
                  return ("OK")
            | _ -> return ("OK"))
        (* code to send udp packets to the destination*)
        | "client" -> (
            let port, ips = 
              match args with
              |port :: ips -> (int_of_string port), ips
              | _ -> failwith "inssuficient args"
                in 
              lwt ip = run_client  port ips in
              let _ = printf "[direct] reply from ip %s \n%!" ip in
                return (ip))
        | _ -> (
            printf "[direct] Action %s not supported in test" kind;
            return ("OK"))
      with exn -> 
       eprintf "[direct] client test error: %s\n%!" 
         (Printexc.to_string exn);
        raise (DirectError(Printexc.to_string exn))


  (***************************************************************
   * Connection code 
   * ************************************************************)
  
  let setup_flows dev mac_addr local_ip rem_ip local_sp_ip 
        remote_sp_ip = 
    let port = Net_cache.Port_cache.dev_to_port_id dev in
    (* outgoing flow configuration *)

    let actions = [ OP.Flow.Set_nw_src(local_ip);
                    OP.Flow.Set_nw_dst(rem_ip);
                    OP.Flow.Set_dl_dst(
                      (Net_cache.mac_of_string mac_addr));
                    OP.Flow.Output((OP.Port.port_of_int port), 
                                   2000);] in
    lwt _ = Sp_controller.setup_flow ~dl_type:(Some(0x0800)) 
              ~nw_dst_len:0 ~nw_dst:(Some(remote_sp_ip)) 
              ~priority:tactic_priority ~hard_timeout:0
              ~idle_timeout:0 actions in
      
    (* get local mac address *)
    let ip_stream = 
      (Unix.open_process_in
         (Config.dir^"/client_tactics/get_local_device br0")) in
    let ips = Re_str.split (Re_str.regexp " ") 
                (input_line ip_stream) in 
    let mac = List.nth ips 1 in
    let mac = Net_cache.mac_of_string mac in 
    
    (* Setup incoming flow *)
    let actions = [ OP.Flow.Set_nw_dst(local_sp_ip);
                     OP.Flow.Set_nw_src(remote_sp_ip); 
                    OP.Flow.Set_dl_dst(mac);
                    OP.Flow.Output(OP.Port.Local, 2000);] in
      Sp_controller.setup_flow ~in_port:(Some(port)) 
        ~dl_type:(Some(0x0800)) ~nw_dst_len:0
        ~nw_dst:(Some(local_ip)) ~priority:tactic_priority 
        ~hard_timeout:0 ~idle_timeout:0 actions
       
  let connect kind _ =
    raise(DirectError(
        (Printf.sprintf "[direct] invalid connect action %s" kind)))

  let enable kind args =
    match kind with
      | "enable" ->(
        try_lwt
          let mac_addr,local_ip,remote_ip,local_sp_ip,remote_sp_ip =
            match args with
            | mac_addr::local_ip::remote_ip::
              local_sp_ip::remote_sp_ip::_ -> 
                mac_addr,(Uri_IP.string_to_ipv4 local_ip),
                (Uri_IP.string_to_ipv4 remote_ip),
                (Uri_IP.string_to_ipv4 local_sp_ip),
                (Uri_IP.string_to_ipv4 remote_sp_ip)
            | _ -> failwith "Insufficient args"
          in
         lwt _ = setup_flows Config.net_intf mac_addr 
                    local_ip remote_ip local_sp_ip remote_sp_ip in
            return true
      with e -> 
        eprintf "[direct] enable error: %s\n%!" (Printexc.to_string e); 
        raise (DirectError((Printexc.to_string e)))
    )    
    | _ -> raise(DirectError(
        (Printf.sprintf "[direct] invalid invalid action %s" kind)))

  (* tearing down the flow that push traffic over the tunnel 
   * *)
  let unset_flows dev local_tun_ip = 
   (* Setup incoming flow *)
    let port = Net_cache.Port_cache.dev_to_port_id dev in
      Sp_controller.delete_flow ~in_port:(Some(port)) 
        ~dl_type:(Some(0x0800)) ~nw_dst_len:0
        ~nw_dst:(Some(local_tun_ip)) () 

  let disable kind  args =
    match kind with 
      | "disable" ->
          let local_tun_ip, _ =
            match args with 
            | local_tun_ip::remote_sp_ip::_ ->
                (Uri_IP.string_to_ipv4 local_tun_ip, 
                Uri_IP.string_to_ipv4 remote_sp_ip)
            | _ -> failwith "Insufficient args"
          in
          (* disable required openflow flows 
           * TODO is this right? *)
          lwt _ = unset_flows Config.net_intf local_tun_ip in
            return ("true")
      | _ -> (
          printf "[direct] teardown action %s not supported in test" kind;
          return ("false"))
  
  let teardown kind _ = 
    printf "[direct] teardown action %s not supported" kind;
    return ("false")
end
