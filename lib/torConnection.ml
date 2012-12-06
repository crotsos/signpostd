(*
 * Copyright (c) 2012 Charalampos Rotsos <cr409@cl.cam.ac.uk>
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
open Printf
open Int64
open Sp_rpc

exception Tor_error

let name () = "tor"

let weight _ _ = 10

type tor_state_type = {
  (* a cache for the domain name of  *)
  conns :(string, string) Hashtbl.t;
}

let state = {conns=(Hashtbl.create 16);}

(******************************************************
 * connection method
 ******************************************************)

let test a b = 
  try_lwt 
  lwt [a_domain; b_domain] = 
    Lwt_list.map_p 
      ( fun a ->
          if (Hashtbl.mem state.conns a ) then 
            return (Hashtbl.find state.conns a)
          else
            lwt d = Nodes.send_blocking a ~timeout:120 
              (create_tactic_request "tor" 
                 TEST "server_start" []) in 
            let _ = Hashtbl.replace state.conns a d in 
              return d
      ) [a; b] in 
  lwt ret = 
    Lwt_list.map_p 
      ( fun (b, a, domain) -> 
          Nodes.send_blocking b ~timeout:120
            (create_tactic_request "tor" 
               TEST "connect"  
               [(Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip a)); 
                domain; (string_of_int SignalHandler.echo_port);])
      ) [(a, b, b_domain); (b, a, a_domain) ] in 
  match ret with
    | "true"::"true"::[] -> return true
    | _ -> return false 
  with exn -> 
    let _ = eprintf "[tor] test error:%s\n%!" (Printexc.to_string exn) in
      return false

let connect a b = 
  try_lwt 
    lwt res = 
      Lwt_list.map_p 
        (fun a -> 
           Nodes.send_blocking a
             (create_tactic_request "tor"
                CONNECT "listen" [])) [a;b] in 
      return (List.fold_right (fun a r -> r && (bool_of_string a)) res true)
  with exn -> 
    let _ = eprintf "[tor] connect error:%s\n%!" (Printexc.to_string exn) in
      return false

let enable a b =
  try_lwt 
    lwt res = 
      Lwt_list.map_p 
        (fun (a, b) -> 
           Nodes.send_blocking a
             (create_tactic_request "tor"
                ENABLE "forward" [b;
        (Hashtbl.find state.conns b); 
        (Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip b));])) 
        [(a, b);(b, a)] in 
      return (List.fold_right (fun a r -> r && (bool_of_string a)) res true)
  with exn -> 
    let _ = eprintf "[tor] connect error:%s\n%!" (Printexc.to_string exn) in
      return false

let disable a b = 
   try_lwt 
    lwt res = 
      Lwt_list.map_p 
        (fun (a, b) -> 
           Nodes.send_blocking a
             (create_tactic_request "tor"
                DISABLE "disable" [b;
        (Hashtbl.find state.conns b); 
        (Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip b));])) 
        [(a, b);(b, a)] in 
      return (List.fold_right (fun a r -> r && (bool_of_string a)) res true)
  with exn -> 
    let _ = eprintf "[tor] connect error:%s\n%!" (Printexc.to_string exn) in
      return false

let teardown a b = 
(*    lwt res = 
      Lwt_list.map_p 
        (fun a -> 
           Nodes.send_blocking a
             (create_tactic_request "tor"
                TEARDOWN "teardown" [])) [a;b] in 
      return (List.fold_right (fun a r -> r && (bool_of_string a)) res true)*)
  return true

(* ******************************************
 * A tactic to forward all traffic to the tor proxy
 * ******************************************)

let handle_request action method_name arg_list =
  let open Rpc in
  try_lwt
    match action with
      | TEST ->
        lwt ip = Tor.Manager.test method_name arg_list in
          return(Sp.ResponseValue ip)            
      | CONNECT ->
         printf "[socks] executing connect command\n%!";
         lwt ip = Tor.Manager.connect method_name arg_list in
            return(Sp.ResponseValue ip)           
      | ENABLE ->
         lwt ip = Tor.Manager.enable method_name arg_list in
            return(Sp.ResponseValue ip)           
      | DISABLE ->
         lwt ip = Tor.Manager.disable method_name arg_list in
            return(Sp.ResponseValue ip)           
     | TEARDOWN ->
         lwt ip = Tor.Manager.teardown method_name arg_list in
            return(Sp.ResponseValue ip)           
    with e -> 
      return (Sp.ResponseError (Printexc.to_string e)) 
 
let handle_notification action method_name arg_list =
  eprintf "Tor tactic doesn't handle notifications\n%!";
  return ()

