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

exception MonitorDisconnect  

type monitor_det = {
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
        return ()

let monitor_state = 
  {monitored_ips = (Hashtbl.create 32);}

let add_dst ip dst_name tactic_name = 
  if (not (Hashtbl.mem monitor_state.monitored_ips ip) ) then
    Hashtbl.add monitor_state.monitored_ips ip {dst_name; tactic_name; }

let del_dst ip = 
  if (not (Hashtbl.mem monitor_state.monitored_ips ip) ) then
    Hashtbl.remove monitor_state.monitored_ips ip

let test_sp_dst (ip,state) = 
  try_lwt 
    (connect_client ip 11000) 
  with MonitorDisconnect -> 
    let args = [(Nodes.get_local_name ()); state.dst_name; state.tactic_name;] in
    let rpc = Rpc.create_notification "tactic_disconnected" args in 
    lwt _ = Nodes.send_to_server rpc in 
    printf "disconnect %s from tactic %s\n%!" state.tactic_name state.dst_name;
    return ()

let monitor_t () = 
  while_lwt true do 
    try_lwt 
      lwt _ = sleep Config.monitor_interval in 
      Lwt_list.iter_p test_sp_dst (Hashtbl.fold (fun k v r -> r @ [(k,v)]) 
        monitor_state.monitored_ips []) 
    with exn ->
      printf "[monitor] error : %s\n" (Printexc.to_string exn);
      return ()
  done
