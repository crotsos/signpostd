(*
 * Copyright (c) 2005-2012 Charalampos Rotsos <cr490@cl.cam.ac.uk>
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

module OP = Openflow.Ofpacket

external get_local_ips: unit ->  (string * string * int) list = 
  "ocaml_get_local_ip"
external get_routing_table: unit -> 
  (int * int * int * int * string) list = 
    "ocaml_get_routing_table"

let string_of_mac mac = 
  let ret = ref "" in 
  let _ = 
    String.iter 
      (fun a -> 
         ret := sprintf "%s%02x:" !ret (int_of_char a)) mac
  in
    String.sub (!ret) 0 17

let mac_of_string mac = 
  let entries = Re_str.split (Re_str.regexp ":") mac in 
  let rec parse_mac = function
    | [] -> ""
    | [b] -> (String.make 1 (char_of_int (int_of_string ("0x"^b))))
    | b :: r -> 
        ((String.make 1 (char_of_int (int_of_string ("0x"^b)))) ^ 
         (parse_mac r))
  in 
    parse_mac entries

module Routing = struct
  type t = {
    ip: int32;
    mask : int32;
    gw : int32;
    local_ip : int32; 
    (* this is a bit useless, as the device will usually be br0 *)
    dev_id : string;
  }

  type routing_tbl_typ = { mutable tbl : t list; }
  let routing_tbl = {tbl=[];}

  let string_rev str =
    let len = String.length str in
    let ret = String.create len in 
    let rec string_rev src dst n i =
      match i with 
        | -1 ->  dst.[n] <- str.[0]; dst
        | -2 -> dst
        | i -> 
            dst.[n - i - 1] <- str.[i]; 
            dst.[n - i ] <- str.[i + 1]; 
            string_rev src dst n (i-2)
    in
      string_rev str ret (len-1) (len-2)

  let match_ip_fib fib ip = 
    (Int32.logand fib.ip fib.mask) = 
      (Int32.logand ip fib.mask)
 
  let load_routing_table () =
    let init_fib = 
      List.map
        (fun (ip, mask, gw, local_ip, dev_id) -> 
           Int32.({ip=(of_int ip); mask=(of_int mask); 
            gw=(of_int gw); local_ip=(of_int local_ip); 
            dev_id;})
        )  (get_routing_table ()) in
    let local_ips = Nodes.discover_local_ips () in
    let filter_local_net_fib ips fib r =
      try 
        match (fib.mask) with
          | 0l -> r
          | _ ->
              let local_ip = List.find (match_ip_fib fib) ips in
              [{ip=fib.ip;mask=fib.mask;dev_id=fib.dev_id;
                gw=fib.gw;local_ip;}] @ r 
      with Not_found -> r
    in 
    let filter_default_gw_fib fibs fib r = 
      try 
        match (fib.mask) with 
          | 0l -> 
              let local_fib = List.find (fun f -> match_ip_fib f fib.gw) fibs in
              [{ip=fib.ip;mask=fib.mask;gw=fib.gw;dev_id=fib.dev_id;
                local_ip=local_fib.local_ip;}] @ r 
          | _ -> r
      with Not_found ->r 
    in
    let direct_fib = List.fold_right (filter_local_net_fib local_ips) init_fib [] in
    let default_gw_fib = List.fold_right (filter_default_gw_fib direct_fib) init_fib [] in
      return (routing_tbl.tbl <- default_gw_fib @ direct_fib)

 let longest_match_fib dst fib_new fib_old = 
   if ((Int32.logand fib_new.ip fib_new.mask) <> 
          (Int32.logand dst fib_new.mask)) then (
            fib_old
   ) else begin
     match fib_old with
       | None -> Some(fib_new)
       | Some(fib) -> begin 
           if( fib.mask < fib_new.mask) then
             fib_old
           else
             Some(fib_new)
         end
   end

  let get_next_hop dst =
      (* TODO need to consider weights in the routing table? *)
      match (List.fold_right (longest_match_fib dst) routing_tbl.tbl None) with
        | None -> raise Not_found
        | Some(fib) -> 
          (fib.ip, fib.gw, fib.dev_id)
  let get_next_hop_local_ip dst =
      (* TODO need to consider weights in the routing table? *)
      match (List.fold_right (longest_match_fib dst) routing_tbl.tbl None) with
        | None -> raise Not_found
        | Some(fib) -> fib.local_ip 

  let add_next_hop ip mask gw dev_id local_ip = 
    let entry = {ip; mask; gw; dev_id;local_ip;} in
       if (not (List.mem entry routing_tbl.tbl)) then
        routing_tbl.tbl <- routing_tbl.tbl @ [entry;]

  let del_next_hop ip mask gw dev_id = 
    routing_tbl.tbl <- 
    (List.filter 
       (fun a -> not ((a.ip = ip) && (a.mask = mask))) 
       routing_tbl.tbl)
end

module Port_cache = struct
  let dev_cache = Hashtbl.create 64 
  (* Maybe I need here an additional field to define a datapath id*)
  let mac_cache = Hashtbl.create 64

  let add_dev dev port_id =
    let dev = Re_str.global_replace (Re_str.regexp "\x00") "" dev in 
      Hashtbl.replace dev_cache dev port_id

  let del_dev = Hashtbl.remove dev_cache

  let dev_to_port_id = Hashtbl.find dev_cache

  let port_id_to_dev port_id = 
      Hashtbl.fold 
        (fun a b r -> 
           if (b = port_id) then Some(a)
           else r
      ) dev_cache None

  let add_mac = Hashtbl.replace mac_cache 

  let port_id_of_mac mac =
    try   
      Some(Hashtbl.find mac_cache mac )
    with e -> None

  let mac_of_port_id port_id =
    let ret = ref None in
    Hashtbl.fold 
      (fun a b r ->
         if(b = port_id) then Some(a)
         else r
    ) mac_cache None
end

module Arp_cache = struct 
  external get_arp_table: unit ->  (string * int) list = 
    "ocaml_get_arp_table"
  
  let cache = Hashtbl.create 64

  let add_mapping mac ip = 
    (* Check if ip addr is local *)
    try 
      let (_,gw,_) = Routing.get_next_hop ip in
        match gw with 
          | 0l -> Hashtbl.replace cache ip mac
          | _ -> ()
    with Not_found -> ()

  let del_mapping ip = 
    (* Check if ip addr is local *)
    try 
      let (_,gw,_) = Routing.get_next_hop ip in 
        match gw with 
          | 0l ->  Hashtbl.remove cache ip
          | _ -> ()
    with Not_found -> ()


  let load_arp () =
    (* reading ip dev mappings *)
    let _ = 
      List.iter 
        (fun (dev, mac, ip) -> 
           let _ = add_mapping mac (Int32.of_int ip) in 
             Port_cache.add_mac mac 
               (OP.Port.int_of_port OP.Port.Local)
        ) (get_local_ips ()) in 
    (* reading arp cache *)
    let arps = get_arp_table () in 
    let _ = List.iter 
              (fun (mac, ip) -> 
                 add_mapping mac (Int32.of_int ip)) arps in 
      return ()

  let mac_of_ip ip =
    try 
      Some(Hashtbl.find cache ip)
    with ex -> None
  let ip_of_mac mac = 
      Hashtbl.fold 
        (fun ip dev r -> 
           if (dev = mac) then Some(ip)
           else r 
      ) cache None
    
  let get_next_hop_mac dst = 
    let (_, gw, _) = Routing.get_next_hop dst in
      match gw with 
        | 0l -> mac_of_ip dst
        | ip -> mac_of_ip ip    
end

