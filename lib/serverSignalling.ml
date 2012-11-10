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

open Sp_rpc
open Lwt
open Printf
open Int64
open Rpc

let config_json =
  let open Json in
  Object [
    ("user", String Config.user);
    ("signpost_number", Int (Int64.of_int Config.signpost_number));
    ("domain", String Config.domain);
    ("external_ip", String Config.external_ip);
    ("external_dns", String Config.external_dns)
  ]

let handle_hello fd args =
  let node :: ip :: str_port :: mac :: local_ips = args in
  let port = Int64.of_int (int_of_string str_port) in
  eprintf "rpc: hello %s -> %s:%Li\n%!" node ip port;
  Nodes.set_signalling_channel node fd;
  Nodes.set_node_local_ips node local_ips;
  Nodes.set_node_mac node mac;
  let rpc = create_notification "setup_sp_ip" 
              [(Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip node))] in 
  lwt _ = Nodes.send node rpc in 
  let rpc = create_request "test_nat" 
              [Config.external_ip; 
               (string_of_int SignalHandler.echo_port)] in
  lwt _ = Nodes.send node rpc in 
    return ()

let handle_request _ command arg_list =
  match command with
  | Command(command_name) -> 
    eprintf "ERROR: Received a REQUEST RPC that the server can't handle
    (%s)\n%!" command_name;
    return Sp.NoResponse
  | TacticCommand(tactic_name, action, method_name) ->
    match Engine.tactic_by_name tactic_name with
    | Some(t) ->
      eprintf "REQUEST for %s with args %s\n%!" 
      tactic_name (String.concat ", " arg_list);
      let module Tactic = (val t : Sp.TacticSig) in
      Tactic.handle_request action method_name arg_list
    | None ->
      eprintf "Server doesn't know how to handle requests for %s\n%!"
      tactic_name;
      return Sp.NoResponse

let handle_notification fd command arg_list =
  match command with
  | Command("hello") -> 
    eprintf "HELLO with args %s\n%!" 
    (String.concat ", " arg_list);
    handle_hello fd arg_list
  | Command("register_mobile_host") -> 
      let a::b::_ = arg_list in
    eprintf "register_mobile_host with args %s\n%!" 
    (String.concat ", " arg_list);
      return (Connections.store_tactic_state a b "direct" Connections.SUCCESS_ACTIVE None)
  | Command("tactic_disconnected") ->
      let a::b::tactic::_ = arg_list in 
        Engine.disconnect a b tactic 
  | Command(value)  ->
    Printf.eprintf "Invalid command %s\n%!" value;
    return ()
  | TacticCommand(tactic_name, action, method_name) ->
    match Engine.tactic_by_name tactic_name with
    | Some(t) ->
      eprintf "NOTIFICATION for %s with args %s\n%!" 
      tactic_name (String.concat ", " arg_list);
      let module Tactic = (val t : Sp.TacticSig) in
      Tactic.handle_notification action method_name arg_list
    | None ->
      eprintf "Server doesn't know how to handle requests for %s\n%!"
      tactic_name;
      return ()
