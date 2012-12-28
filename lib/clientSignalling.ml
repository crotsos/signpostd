(*
 * Copyright (c) 2012 Sebastian Probst Eide <sebastian.probst.eide@gmail.com>
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
open Lwt_unix
open Lwt
open Printf
open Int64
open Sp_rpc
open Uri_IP

exception Tactic_error of string

let connect_client ip port =
  try_lwt 
    let client_sock = socket PF_INET SOCK_STREAM 0 in
    let hentry = Unix.inet_addr_of_string ip in
    lwt _ = 
       (Lwt_unix.sleep 4.0 >|= (fun _ -> failwith("Can't connect")) ) <?> 
            Lwt_unix.connect client_sock(ADDR_INET(hentry, port)) in 
    let loc_ip,loc_port = 
      match Lwt_unix.getsockname client_sock with 
      | ADDR_INET(loc_ip,loc_port) -> loc_ip,loc_port
      | _ -> failwith "not an ADDR_INET socket addr"
    in
    let pkt_bitstring = BITSTRING {
        (Uri_IP.string_to_ipv4 (Unix.string_of_inet_addr loc_ip)):32;
        loc_port:16; (String.length (Nodes.get_local_name ())):16;
        (Nodes.get_local_name ()):-1:string} in 
    let pkt = Bitstring.string_of_bitstring pkt_bitstring in 
    lwt _ = Lwt_unix.send client_sock pkt 0 (String.length pkt) [] in 
        Lwt_unix.shutdown client_sock SHUTDOWN_ALL; 
        return true
  with exn ->
    eprintf "[signal] tcp client error:%s\n%!" (Printexc.to_string exn);
    return false

let handle_request _ command arg_list =
  match command with
  | Command("test_nat") ->
      let ip, port = 
        match arg_list with
          | ip::port::_ -> ip, (int_of_string port)
          | _ -> failwith "test_nat invalid args"
      in
      lwt res = connect_client ip port in 
        return (Sp.ResponseValue (string_of_bool res))
  | Command c -> 
      let _ = eprintf "REQUEST %s with args %s\n%!" 
          c (String.concat ", " arg_list) in 
        return Sp.NoResponse 
  | TacticCommand(tactic_name, action, method_name) ->
      match Engine.tactic_by_name tactic_name with
      | Some(t) ->
          eprintf "REQUEST for %s with args %s\n%!" 
              tactic_name (String.concat ", " arg_list);
          let module Tactic = (val t : Sp.TacticSig) in
          Tactic.handle_request action method_name arg_list
      | None ->
          eprintf "Client doesn't know how to handle requests for %s\n%!"
              tactic_name;
          return Sp.NoResponse

let handle_notification _ command arg_list =
  match command with
  | Command("setup_sp_ip") -> 
      let ip = List.hd arg_list in
      let _ = Nodes.set_local_sp_ip (Uri_IP.string_to_ipv4 ip) in
        (* TODO make this libnl *)
      let gw_ip = ipv4_to_string 
                    (Int32.add (string_to_ipv4 ip) 1l) in 
      lwt _ = Lwt_unix.system (
        sprintf "%s/client_tactics/setup_sp_ip %s %s %s "
        Config.dir Config.bridge_intf ip gw_ip) in 
(*                (Printf.sprintf "ip addr add %s/30 dev br0"  ip) in       
                  (sprintf "ifconfig %s alias %s ") in
      lwt _ = Lwt_unix.system 
                (Printf.sprintf "arp -s %s fe:ff:ff:ff:ff:ff"  
                   gw_ip) in         
      lwt _ = Lwt_unix.system 
                (Printf.sprintf "route add -net %s/%d gw %s" 
                   Nodes.sp_ip_network Nodes.sp_ip_netmask gw_ip) in  *)
        return ()  
  | Command c -> 
      let _ = eprintf "NOTIFICATION: %s with args %s\n%!" 
          c (String.concat ", " arg_list) in 
        return () 
  | TacticCommand(tactic_name, action, method_name) ->
      match Engine.tactic_by_name tactic_name with
      | Some(t) ->
          eprintf "NOTIFICATION for %s with args %s\n%!" 
              tactic_name (String.concat ", " arg_list);
          let module Tactic = (val t : Sp.TacticSig) in
          Tactic.handle_notification action method_name arg_list
      | None ->
          eprintf "Client doesn't know how to handle requests for %s\n%!"
              tactic_name;
          return ()
