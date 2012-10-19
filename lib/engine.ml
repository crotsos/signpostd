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


open Lwt
open Printf
open Connections

let tactics = [
(*      (module DirectConnection : Sp.TacticSig);   *)
(*    (module AvahiConnection : Sp.TacticSig);  *)
     (module OpenvpnConnection : Sp.TacticSig); 
(*      (module SshConnection : Sp.TacticSig);    *)
(*   (module PrivoxyConnection : Sp.TacticSig);  *)
(*   (module TorConnection : Sp.TacticSig);  *)
(*      (module NatpunchConnection : Sp.TacticSig); *)
  ]

let get_tactic_module name = 
  try 
    List.find (
      fun t -> 
        let module Tactic = (val t : Sp.TacticSig) in
          ((String.compare name (Tactic.name ())) = 0)
    ) tactics 
  with Not_found -> 
    failwith (sprintf "Tactic '%s' not found \n%!" name)

let disable_tactic tactic a b = 
  Printf.printf "using tactic %s to disable %s %s\n%!" tactic a b; 
  try_lwt
    lwt t = Lwt_list.find_s ( fun t -> 
    let module Tactic = (val t : Sp.TacticSig) in
      return ( (String.compare tactic (Tactic.name ())) = 0)
    ) tactics in
    let module Tactic = (val t : Sp.TacticSig) in
    Printf.eprintf "found tactic %s\n%!" (Tactic.name ()); 
    lwt _ = Tactic.disable a b in  
  (*     lwt ret = Tactic.teardown a b in *)
      Connections.store_tactic_state a b 
        (Tactic.name ()) Connections.SUCCESS_INACTIVE 
        None;
      return true
  with Not_found ->
    Printf.eprintf "cannot find tactic %s\n%!" tactic;
    return false

let compare_tactics a b new_tactic old_tactic =
  let module Tactic_new = (val new_tactic : Sp.TacticSig) in
  let module Tactic_old = (val old_tactic : Sp.TacticSig) in
    ((Tactic_new.weight a b) < 
        (Tactic_old.weight a b))

let connect_using_tactic_inner t a b force =
  try_lwt 
    let module Tactic = (val t : Sp.TacticSig) in
      printf "Using tactic %s to connect \n%!" (Tactic.name ());
      match (Connections.get_tactic_status a b (Tactic.name ())) with 
        | Connections.IN_PROGRESS 
        | Connections.FAILED -> begin
            Connections.store_tactic_state a b (Tactic.name ()) 
            Connections.IN_PROGRESS None; 
          lwt res = Tactic.test a b in 
            match res with 
              | false -> 
                  Connections.store_tactic_state a b (Tactic.name ()) 
                    Connections.FAILED None; 
                  return false;
              | true -> begin
                lwt res = Tactic.connect a b in 
                match res with
                  | false -> 
                      Connections.store_tactic_state a b (Tactic.name ()) 
                        Connections.FAILED None; 
                      Printf.printf "XXXXX tactic %s failed\n%!" (Tactic.name ());
                      return false;
                  | true ->(
                      Connections.store_tactic_state a b (Tactic.name ()) 
                        Connections.SUCCESS_INACTIVE None;
                      match (Connections.get_link_active_tactic a b) with
                        | None -> 
                            lwt _ = Tactic.enable a b in
                              Connections.store_tactic_state a b 
                                (Tactic.name ()) Connections.SUCCESS_ACTIVE None;
                              return true
                        | Some(old_tactic) -> 
                           let s = get_tactic_module old_tactic in  
                           if ( force ||  (compare_tactics a b t s)) then (
                             lwt _ = Tactic.enable a b in
                             let module Tactic_old = (val s: Sp.TacticSig) in  
                             Connections.store_tactic_state a b (Tactic_old.name ()) 
                                Connections.SUCCESS_INACTIVE None;
                              Connections.store_tactic_state a b (Tactic.name ()) 
                                Connections.SUCCESS_ACTIVE None;
                             lwt _ = disable_tactic old_tactic a b in
                              return false;
                           ) else 
                             return false;
                    ) 
                end
          end
        | Connections.SUCCESS_ACTIVE ->
            return false
        | Connections.SUCCESS_INACTIVE -> 
            match (Connections.get_link_active_tactic a b) with
              | None -> ( 
                  lwt _ = Tactic.enable a b in
                    Connections.store_tactic_state a b 
                      (Tactic.name ()) Connections.SUCCESS_ACTIVE None;
                    return(true))
              | Some(old_tactic) -> (
                  let s = get_tactic_module old_tactic in  
                  if (force || (compare_tactics a b t s)) then (
                    lwt _ = Tactic.enable a b in
                    let module Tactic_old = (val s: Sp.TacticSig) in  
                      Connections.store_tactic_state a b old_tactic  
                        Connections.SUCCESS_INACTIVE None;
                      Connections.store_tactic_state a b (Tactic.name ()) 
                        Connections.SUCCESS_ACTIVE None;
                    let _ = notify_waiters a b in
                    lwt _ = disable_tactic old_tactic a b in
                      return false
                   ) else 
                     return false)
  with exn ->
    printf "ERROR: iter_over_tactics: %s\n%!" (Printexc.to_string exn);
    return false

let iter_over_tactics wakener a b =
  let _ = Connections.set_link_status a b PROCESSING in
  lwt _ = 
    Lwt_list.iter_p 
      (fun t ->
         lwt res = connect_using_tactic_inner t a b  false in 
          match (res) with
            | true -> return (Lwt.wakeup wakener true)
            | false -> return ()
      ) tactics  in
  let _ = set_link_status a b IDLE in
  let _ = notify_waiters a b in
  match (Connections.get_link_connection_status a b) with
    | Connections.IN_PROGRESS 
    | Connections.SUCCESS_INACTIVE 
    | Connections.FAILED -> 
        Connections.store_tactic_state a b "direct" Connections.FAILED 
          None;
        return(Lwt.wakeup wakener false)
    | _ ->  return() 

let connect wakener a b =
  eprintf "Engine is trying to connect %s and %s\n" a b;
  lwt _ = iter_over_tactics wakener a b in
  eprintf "XXXXXX got a first connection yeah!!!!\n%!";
    return () (* (Lwt.wakeup wakener ret) *)

let connect_using_tactic tactic a b = 
  Printf.printf "using tactic %s to connect %s %s\n%!" tactic a b; 
  try_lwt
    let t = get_tactic_module tactic in 
      connect_using_tactic_inner t a b true
  with exn ->
    Printf.eprintf "ERROR connect_using_tactic: %s\n%!" 
      (Printexc.to_string exn);
    return false

let tactic_by_name name =
  try 
    let tactic = List.find (fun t -> 
      let module Tactic = (val t : Sp.TacticSig) in
      Tactic.name () = name) tactics in
      Some(tactic)
    with Not_found ->
      None

let dump_tunnels_t () = 
  let _ = 
    while_lwt (true) do 
      lwt _ = Lwt_unix.sleep 1.0 in 
        Connections.dump_tunnels ()
    done
  in 
    return ()

let find a b =
  eprintf "Finding existing connections between %s and %s\n" a b;
  try_lwt
    match (Connections.get_link_status a b) with
      | IDLE -> begin 
      match (Connections.get_link_connection_status a b) with 
        | Connections.IN_PROGRESS 
        | Connections.SUCCESS_INACTIVE 
        | Connections.FAILED -> (
          Printf.printf "[engine] failed tactic\n%!";
          let waiter, wakener = Lwt.task () in 
          let _ = Lwt.ignore_result(connect wakener a b) in
          lwt res = waiter in 
          let ret = Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip b) in
            (match res with
              | true -> return (Sp.IPAddressInstance(ret)) 
              | false -> return (Sp.Unreachable) ))
        | Connections.SUCCESS_ACTIVE -> 
            return(Sp.IPAddressInstance(
              (Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip b))))
        end 
      | PROCESSING -> 
          Printf.printf "[engine] waiting for tactic\n%!";
          lwt res = Connections.wait_for_link a b in
            (match res with
              | Connections.SUCCESS_ACTIVE -> 
            return(Sp.IPAddressInstance(
              (Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip b))))
              | _ ->return (Sp.Unreachable) )

  with _ ->
    Printf.printf "[Nodes] cannot find node %s \n%!" b;
    return(Sp.Unreachable)

let disconnect a b tactic =
    match (Connections.get_tactic_status a b tactic) with
        (* If I am trying to connect or I am disconnected, 
         * then I can disregard the message *)
      | Connections.IN_PROGRESS 
      | Connections.FAILED ->
          return ()
      | Connections.SUCCESS_ACTIVE ->  
          let s = get_tactic_module tactic in  
          let module Tactic = (val s : Sp.TacticSig) in
          lwt _ = Tactic.disable a b in 
          lwt _ = Tactic.teardown a b in
            Connections.store_tactic_state a b tactic
              Connections.FAILED None;
          lwt _ = find a b in
            return ()
      | Connections.SUCCESS_INACTIVE -> 
          let s = get_tactic_module tactic in  
          let module Tactic = (val s : Sp.TacticSig) in
          lwt _ = Tactic.teardown a b in
            Connections.store_tactic_state a b tactic  
              Connections.FAILED None;
          lwt _ = find a b in
            return ()

let tunnel_monitor_t () = 
  while_lwt true do 
    lwt _ = Lwt_unix.sleep Config.tunnel_check_interval in
    let conns = Connections.get_active_connections () in 
      Lwt_list.iter_p (
        fun (a, b) -> 
          let waiter, wakener = Lwt.task () in 
          lwt _ = connect wakener a b in
          lwt res = waiter in
            return ()
      ) conns 
  done

