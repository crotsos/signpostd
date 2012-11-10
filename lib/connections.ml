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
open List

type tactic_state = 
  | SUCCESS_INACTIVE
  | SUCCESS_ACTIVE
  | IN_PROGRESS
  | FAILED
let string_of_tactic_state = function
  | SUCCESS_INACTIVE-> "SUCCESS_INACTIVE"
  | SUCCESS_ACTIVE  -> "SUCCESS_ACTIVE"
  | IN_PROGRESS     -> "IN_PROGRESS" 
  | FAILED          -> "FAILED"    
type link_state = 
  | IDLE
  | PROCESSING
let string_of_link_state = function
  | SUCCESS_INACTIVE -> "SUCCESS_INACTIVE"
  | SUCCESS_ACTIVE   -> "SUCCESS_ACTIVE"  
  | IN_PROGRESS      -> "IN_PROGRESS"     
  | FAILED           -> "FAILED"          

type tunnel_state = {
  (* Current state ofthe tunnel *)
  mutable tactic_state : tactic_state;
  (*
   * Cache what was the result of the last try.
  * *)
  mutable last_res : tactic_state;
  (* A connection identification in order to be able to tear down 
   * connections.
  * *)
  mutable conn_id : int option;
  (*
   * Is there a local device we should store?
   * TODO: this is not accurate as for a tactic we might 
   * have multiple devices. Maybe make it a list and add
   * a node.
  * *)
  device : string option;
  (* For each tunel a string may have multiple ip addresses 
  * semantically miningful only for the tunnel *)
  address : (string, int32 list) Hashtbl.t;
}


type connection_state = {
  wait: unit Lwt_condition.t; 
  mutable link_state : link_state; 
  tactic : (string, tunnel_state) Hashtbl.t;
}

(*
type _state = {
  connections : (handle * handle, tactic_result list) Hashtbl.t;
}
 *)

let connections = 
  (Hashtbl.create 0)

let in_order a b = a < b

let construct_key a b =
  match in_order a b with
    | true -> (a,b)
    | false -> (b,a)


(**********************************************************************
 * Public API *********************************************************)
let set_link_status a b link_state = 
  let key = construct_key a b in
  try 
    let link = Hashtbl.find connections key in
      link.link_state <-  link_state
  with Not_found -> 
    let link = {wait=(Lwt_condition.create ()); link_state;
                tactic=(Hashtbl.create 16);} in 
      Hashtbl.add connections key link

let get_link_status a b = 
  let key = construct_key a b in
  try 
    let link = Hashtbl.find connections key in 
      link.link_state
  with Not_found -> 
    let link = {wait=(Lwt_condition.create ()); link_state=IDLE;
                tactic=(Hashtbl.create 16);} in 
      Hashtbl.add connections key link;
      IDLE

let notify_waiters  a b = 
  let key = construct_key a b in
  try 
    let link = Hashtbl.find connections key in 
      Lwt_condition.broadcast link.wait ()
  with Not_found -> 
    ()

let print_tactics_state a b =                                                     
  let key = construct_key a b in                                                  
  try                                                                             
    let conn = Hashtbl.find connections key in                                    
    let _ = Hashtbl.iter (                                                        
      fun name tact ->                                                            
        printf "--> %s ->\t %s\n%!" name (string_of_link_state tact.tactic_state) 
    ) conn.tactic in  
        ()                                                            
  with Not_found ->                                                               
    printf "link not found %s - %s\n%!" a b                                       

let get_link_active_tactic a b =
  let key = construct_key a b in
  try
    let name = ref None in 
    let conn = Hashtbl.find connections key in
      Hashtbl.iter 
        (fun a b -> 
           if (b.tactic_state = SUCCESS_ACTIVE) then
             name := Some(a)
        ) conn.tactic;
      !name
  with Not_found ->
    None

let dump_tunnels () = 
  let file = 
    "/home/ubuntu/SignpostDemo/SignpostDemoWeb/signpost-sigcomm-connections-live.json" 
  in 
  let out = [] in 
  let res = Hashtbl.fold 
              (fun k v r ->
                let (cl, s)  = k in 
                 match (get_link_active_tactic cl s) with
                   | None -> 
                       r
                   | Some(tactic) ->
                       match (cl, s) with
                         | ("home", _) -> 
                          (r @ 
                            ([Json.Object 
                              [("client", Json.String s); 
                               ("server", Json.String cl);
                               ("type", Json.String tactic);
                              ]]))
                         | (_, "home") -> 
                          (r @ 
                            ([Json.Object 
                              [("client", Json.String cl); 
                               ("server", Json.String s);
                               ("type", Json.String tactic);
                              ]]))
                         | ("slave", _) -> 
                          (r @ 
                            ([Json.Object 
                              [("client", Json.String s); 
                               ("server", Json.String cl);
                               ("type", Json.String tactic);
                              ]]))
                         | (_, "slave") -> 
                          (r @ 
                            ([Json.Object 
                              [("client", Json.String cl); 
                               ("server", Json.String s);
                               ("type", Json.String tactic);
                              ]]))
                         | (_, _) -> 
                          (r @ 
                            ([Json.Object 
                              [("client", Json.String cl); 
                               ("server", Json.String s);
                               ("type", Json.String tactic);
                              ]]))
              ) 
              connections out in
  let str_out = Json.to_string (Json.Array res) in 
(*
  let _ = 
    if ((List.length res) > 0) then
      printf "%s\n%!" str_out
  in
 *)
  let output = open_out file in 
  let _ = output_string output str_out in 
  let _ = close_out output in 
    return ()

let print_tactic_state a b =
  let key = construct_key a b in 
    try 
      let conn = Hashtbl.find connections key in 
      let _ = printf "----tactics for connection %s - %s ----\n%!" a b in 
        Hashtbl.iter (
          fun k v -> 
            printf "\t %s -> %s \n%!" k (string_of_tactic_state v.tactic_state)
        ) conn.tactic 
    with Not_found ->
      eprintf "connections print no connection found %s - %s\n%!" a b


let store_tactic_state a b tactic_name link_state conn_id = 
  let key = construct_key a b in
(*     print_tactic_state a b; *)
  let link = match (Hashtbl.mem connections key) with
    | true -> Hashtbl.find connections key
    | false -> 
        let link = {wait=(Lwt_condition.create ()); link_state=IDLE;
        tactic=(Hashtbl.create 16);} in 
          Hashtbl.add connections key link;
          link
  in
  let _ = 
     match link_state with 
       | SUCCESS_INACTIVE 
       | IN_PROGRESS 
       | FAILED -> ()
       | SUCCESS_ACTIVE ->
           Lwt_condition.broadcast link.wait ()
   in 
    let conn = 
      if (Hashtbl.mem link.tactic tactic_name) then
        Hashtbl.find link.tactic tactic_name
      else (
        let tactic = {tactic_state=link_state; last_res=link_state; 
                      conn_id; device=None;address=(Hashtbl.create 16);} in
          Hashtbl.add link.tactic tactic_name tactic;
          tactic
      )
    in
      conn.conn_id <- conn_id;
      conn.tactic_state <- link_state;
        ()

let get_link_connection_status a b =
  let key = construct_key a b in
  try
    let conn = Hashtbl.find connections key in
      Hashtbl.fold (
        fun t st r ->
          match ( r, st.tactic_state) with
            | (SUCCESS_ACTIVE, _) ->
                r
            | (_, SUCCESS_ACTIVE) ->
                st.tactic_state 
            | (SUCCESS_INACTIVE, _) ->
                r
            | (_, SUCCESS_INACTIVE) ->
                st.tactic_state 
            | (IN_PROGRESS, _) ->
                r
            | (_, IN_PROGRESS) -> 
                st.tactic_state 
            | (FAILED, FAILED) -> 
                r) 
        conn.tactic FAILED 
  with Not_found ->
    FAILED

let wait_for_link a b =
  let key = construct_key a b in
  try
    let conn = Hashtbl.find connections key in 
      match (get_link_connection_status a b) with
        | IN_PROGRESS ->
            lwt _ = Lwt_condition.wait conn.wait  in
              return((get_link_connection_status a b))
        | a -> return(a)
  with Not_found ->
    return(FAILED)



let get_tactic_status a b tactic_name =
  let key = construct_key a b in
  try
    let conn = Hashtbl.find connections key in 
    let tactic = Hashtbl.find conn.tactic tactic_name in 
      tactic.tactic_state
  with Not_found ->
    FAILED


let get_active_connections () = 
  Hashtbl.fold (
    fun k v ret ->
      let (a, b) = k in
      match (get_link_connection_status a b) with
        | SUCCESS_ACTIVE ->
            ret @ [k]
        | _ -> 
            ret 
  ) connections  [] 
