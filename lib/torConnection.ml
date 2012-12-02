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
  lwt [a_domain; b_domain] = 
    Lwt_list.map_p 
      ( fun a ->
          if (Hashtbl.mem state.conns a ) then 
            return (Hashtbl.find state.conns a)
          else
            Nodes.send_blocking a 
              (create_tactic_request "tor" 
                 TEST "server_start" [])
      ) [a; b] in 
  lwt ret = 
    Lwt_list.map_p 
      ( fun (a, domain) -> 
          Nodes.send_blocking a 
            (create_tactic_request "tor" 
               TEST "connect" [a; domain; (string_of_int SignalHandler.echo_port);])
      ) [(b, a_domain); (a, b_domain)] in 
  match ret with
    | "true"::"true"::[] -> return true
    | _ -> return false

let connect a b = return true
(*  (* Trying to see if connectivity is possible *)
  eprintf "[proxy] enabling between tor on %s \n%!" a;
  let rpc = (create_tactic_request "tor" 
               CONNECT "start" []) in
    try
      lwt res = (Nodes.send_blocking a rpc) in 
      let rpc = (create_tactic_request "tor" 
                   CONNECT "forward" []) in
      lwt res = (Nodes.send_blocking a rpc) in 
        return true
    with exn -> 
      Printf.printf "[socks] client fail %s\n%!" a;
(*       raise Tor_error *)
      return false*)
let enable _ _ = return true
let disable _ _ = return true 

let teardown a b = 
  return true

(* ******************************************
 * A tactic to forward all traffic to the tor proxy
 * ******************************************)

let handle_request action method_name arg_list =
  let open Rpc in
  try
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
      return (Sp.ResponseError "provxy_connect") 
 
let handle_notification action method_name arg_list =
  eprintf "Tor tactic doesn't handle notifications\n%!";
  return ()

