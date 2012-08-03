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
open Lwt_list
open Printf

module OP = Openflow.Packet
module OC = Openflow.Controller
module OE = OC.Event

let pp = Printf.printf
let sp = Printf.sprintf
let ep = Printf.eprintf

exception Nat_error

let name () = "natpanch"

(* a struct to store details for each node participating in a 
 * tunnel formation*)
type natpanch_client_state_type = {
  mutable name: string; (* node name *)
  mutable extern_ip: int32; (* public ip discovered through the test *)
}

type natpanch_conn_state_type = {
  (* a list of the nodes *)
  mutable nodes : natpanch_client_state_type list;
  (* Natpunch has no directionality. it must be birectional. *)
  (*   mutable direction : int;  *)
  conn_id : int32;          (* connection id *)
}

type natpanch_state_type = {
  conns : ((string * string), natpanch_conn_state_type) Hashtbl.t;
  mutable conn_counter : int32;
}

let natpanch_state = 
  {conns=(Hashtbl.create 64); conn_counter=1l;}

let gen_key a b =
  if(a < b) then (a, b) else (b, a)

let get_state a b =
  let key = gen_key a b in 
  if (Hashtbl.mem natpanch_state.conns key) then
    Hashtbl.find natpanch_state.conns key 
  else (
    let ret = {nodes=[];conn_id=(natpanch_state.conn_counter)} in 
      natpanch_state.conn_counter <- (Int32.add natpanch_state.conn_counter 1l);
      Hashtbl.add natpanch_state.conns key ret;
      ret
  )

(*
 * Testing methods 
 * *)
let test a b = 
  (* Fetch public ips to store them for mapping reasons *)
  let (a, b) = gen_key a b in
  let conn = get_state a b in 

  let pairwise_connection_test a b = 
    try_lwt 
    (* check if two nodes can connect *)
      let external_ip = List.hd (Nodes.get_public_ips b) in
      let rpc = (Rpc.create_tactic_request "natpanch" Rpc.TEST "client_test" 
                 [(List.hd (Nodes.get_public_ips b)); 
                  (Int64.to_string SignalHandler.echo_port); b;]) in
      lwt res = Nodes.send_blocking a rpc in
        return (bool_of_string res)
     with exn ->
       ep "[natpanch]error:%s\n%!" (Printexc.to_string exn);
       return false
  in
  lwt ret = (pairwise_connection_test a b) in
     match ret with
      | true ->
          (* In case we have a direct tunnel then the nodes will receive an 
          * ip from the subnet 10.3.(conn_id).0/24 *)
          let nodes = [ 
            {name=(sprintf "%s.d%d" a Config.signpost_number); 
             extern_ip=(Uri_IP.string_to_ipv4 (List.hd (Nodes.get_public_ips a)));};
            {name=(sprintf "%s.d%d" b Config.signpost_number);
             extern_ip=(Uri_IP.string_to_ipv4 (List.hd (Nodes.get_public_ips b)));} ] in 
          conn.nodes <- nodes;
          return true
      (* test failed, so no conection :S *)
      | false -> 
          Hashtbl.remove natpanch_state.conns (gen_key a b);
          return false

(*
 * Conection methods
 * *)
let connect a b =
  try_lwt
    let conn = Hashtbl.find natpanch_state.conns (gen_key a b) in 
      return true
  with exn ->
    printf "[natpunch] Connection beetween %s - %s failed during test\n%!" a b; 
    return false

let enable a b = 
  try_lwt
    let conn = Hashtbl.find natpanch_state.conns (gen_key a b) in 
      (* register an openflow hook for tcp connections destined 
       * to specific port *)
    let enable_client a b =
      let a_q = sprintf "%s.d%d" a Config.signpost_number in
      let b_q = sprintf "%s.d%d" b Config.signpost_number in 
      let external_ip = (List.hd (Nodes.get_public_ips b)) in
      let rpc = 
        Rpc.create_tactic_request "natpanch" Rpc.CONNECT "register_host"
          [b;external_ip;(Uri_IP.ipv4_to_string (Nodes.get_sp_ip b));] in
      lwt _ = (Nodes.send_blocking a rpc) in
        return ()
    in
    lwt _ = (enable_client a b) <&> (enable_client b a) in 
      return true
   with exn ->
     ep "[natpanch]error:%s\n%!" (Printexc.to_string exn);
     return false

let handle_notification _ method_name arg_list =
  match method_name with 
    | "server_connect" -> (
        try_lwt
          (* connection parameter *)
          let dst = List.nth arg_list 0 in 
          let src = List.nth arg_list 1 in 
          let _ = List.nth arg_list 2 in
          let tp_src = List.nth arg_list 3 in
          let tp_dst = List.nth arg_list 4 in
          let isn = List.nth arg_list 5 in
          (* TODO: High end NAT may use src port mapping which we could detect if we
           * tried to send a packet from the source port to the destination. *)
          let nw_dst = List.hd (Nodes.get_public_ips src) in
          let rpc = 
            (Rpc.create_tactic_request "natpanch" 
             Rpc.CONNECT "server_connect" 
             [nw_dst; tp_src; tp_dst; (Uri_IP.ipv4_to_string (Nodes.get_sp_ip dst));
              (Uri_IP.ipv4_to_string (Nodes.get_sp_ip src));isn;]) in
          lwt _ = Nodes.send_blocking dst rpc in 
            return () 
        with exn ->
          eprintf "[natpanch]notification error: %s\n%!" 
              (Printexc.to_string exn);
            return()
        )
    | _ -> 
        (eprintf "[natpanch] tactic doesn't handle notifications\n%!";
        return ())

let disable a b = 
  Printf.eprintf "[natpanch] disable connection between %s - %s\n%!" a b;
  return true

let teardown a b = 
  Printf.eprintf "[natpanch] teardown connection between %s - %s\n%!" a b;
  return true

(* ******************************************
 * A tactic to setup a Nat punch
 * ******************************************)
let handle_request action method_name arg_list =
  let open Rpc in
    match action with
      | TEST ->
        (try_lwt 
          lwt ip = Natpunch.Manager.test method_name arg_list in
            return(Sp.ResponseValue ip)
        with ex ->  
          return(Sp.ResponseError (Printexc.to_string ex)) )
      | CONNECT ->
          (try 
             lwt ip = Natpunch.Manager.connect method_name arg_list in
               return(Sp.ResponseValue ip)            
           with e -> 
             return (Sp.ResponseError (sprintf "ssh_connect %s" (Printexc.to_string e))))
      | ENABLE  ->
          (try 
             lwt ip = Natpunch.Manager.enable method_name arg_list in
               return(Sp.ResponseValue ip)            
           with e -> 
             return (Sp.ResponseError (sprintf "ssh_connect %s" (Printexc.to_string e))))
      | DISABLE ->
          (try 
             lwt ip = Natpunch.Manager.disable method_name arg_list in
               return(Sp.ResponseValue ip)            
           with e -> 
             return (Sp.ResponseError (sprintf "ssh_connect %s" (Printexc.to_string e))))
      | TEARDOWN ->
           eprintf "Ssh doesn't support teardown action\n%!";
             return(Sp.ResponseError "Ssh teardown is not supported yet")


