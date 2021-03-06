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
open Sp_rpc

exception MonitorDisconnect  

type monitor_det = {
  dst_ip: string;
  tactic_name:string;
  dst_name: string;
}

type monitor_state_type = {
  monitored_ips : (string, monitor_det) Hashtbl.t;
}

let connect_client ip port =
    let client_sock = socket PF_INET SOCK_STREAM 0 in
    let hentry = Unix.inet_addr_of_string ip in
    lwt _ = 
       (Lwt_unix.sleep 4.0 >|= (fun _ -> raise MonitorDisconnect) ) <?> 
            Lwt_unix.connect client_sock(ADDR_INET(hentry, port)) in 
    let (loc_ip,loc_port) = 
      match (Lwt_unix.getsockname client_sock) with
      | ADDR_INET(loc_ip,loc_port) -> (loc_ip,loc_port)
      | _ -> failwith "Invalid socket type"
    in
    let buf = Cstruct.create 1024 in 
    let _ = Cstruct.BE.set_uint32 buf 0  (Uri_IP.string_to_ipv4
    (Unix.string_of_inet_addr loc_ip)) in 
    let _ = Cstruct.BE.set_uint16 buf 4 loc_port in 
    let _ = Cstruct.BE.set_uint16 buf 6 (String.length (Nodes.get_local_name
    ())) in
    let _ = Cstruct.blit_from_string (Nodes.get_local_name ()) 0 buf 8 
              (String.length (Nodes.get_local_name ())) in 
    let pkt = Cstruct.to_string buf in 
 
    lwt _ = Lwt_unix.send client_sock pkt 0 (String.length pkt) [] in
    let rcv_buf = String.create 2048 in 
    lwt _ = Lwt_unix.recv client_sock rcv_buf 0 1048 [] in
    let _ = Lwt_unix.shutdown client_sock SHUTDOWN_ALL in
      return ()

let monitor_state = 
  {monitored_ips = (Hashtbl.create 32);}

let print_monitors () =
  Hashtbl.iter (
    fun k _ ->
      printf "monitoring %s...\n%!" k
  ) monitor_state.monitored_ips


let add_dst ip dst_name tactic_name = 
  let key = String.concat ip ["-"; tactic_name] in 
  if (not (Hashtbl.mem monitor_state.monitored_ips key) ) then (
    Hashtbl.add monitor_state.monitored_ips key {dst_name; tactic_name; dst_ip=ip;};
    print_monitors ()
  )

let del_dst ip tactic_name = 
  let key = String.concat ip ["-"; tactic_name] in 
  if (Hashtbl.mem monitor_state.monitored_ips key) then (
    Hashtbl.remove monitor_state.monitored_ips key;
    print_monitors ()
  )


let test_sp_dst (ip,state) = 
  try_lwt 
    (connect_client state.dst_ip 11000) 
  with _ -> 
    let args = [(Nodes.get_local_name ()); state.dst_name; state.tactic_name;] in
    let rpc = create_notification "tactic_disconnected" args in 
    lwt _ = Nodes.send_to_server rpc in
    let _ = del_dst ip state.tactic_name in 
    printf "disconnect %s from tactic %s\n%!" state.tactic_name state.dst_name;
    return ()

let monitor_t () = 
  while_lwt true do 
    try_lwt 
      lwt _ = sleep Config.monitor_interval in 
      Lwt_list.iter_p test_sp_dst (Hashtbl.fold (fun k v r -> r @ [(k,v)]) 
        monitor_state.monitored_ips []) 
    with exn ->
      printf "XXXXXXXXXX [monitor] error : %s\n" (Printexc.to_string exn);
      return ()
  done
