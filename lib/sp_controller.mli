(*
 * Copyright (c) 2005-2012 Anil Madhavapeddy <anil@recoil.org>, 
 *                         Charalampos Rotsos <cr409@cl.cam.ac.uk>
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

(* register a callback for a specific flow match *)

type pkt_in_cb_struct 

type switch_state = {
  mutable mac_cache: (Openflow.Ofpacket.eaddr, Openflow.Ofpacket.Port.t) Hashtbl.t; 
  mutable dpid: Openflow.Ofpacket.datapath_id;
  mutable of_ctrl: Openflow.Ofcontroller.t option;
  mutable pkt_in_cb_cache : pkt_in_cb_struct list;
  cb_register : (Openflow.Ofpacket.Match.t, (Openflow.Ofcontroller.t ->Openflow.Ofpacket.datapath_id -> 
                   Openflow.Ofcontroller.Event.e -> unit Lwt.t) ) Hashtbl.t;
} 

val switch_data : switch_state
(* setup a listening openflow controller *)
val listen : ?port:int -> Net.Manager.t -> unit Lwt.t

val register_handler : Openflow.Ofpacket.Match.t -> 
  (Openflow.Ofcontroller.t -> Openflow.Ofpacket.datapath_id -> 
     Openflow.Ofcontroller.Event.e -> unit Lwt.t) -> unit Lwt.t
val unregister_handler : Openflow.Ofpacket.Match.t -> 
  (Openflow.Ofcontroller.t -> Openflow.Ofpacket.datapath_id -> 
     Openflow.Ofcontroller.Event.e -> unit Lwt.t) -> unit Lwt.t

val add_dev : string -> string -> string -> unit Lwt.t
val del_dev : string -> string -> string -> unit Lwt.t
val get_ctrl : unit -> Openflow.Ofcontroller.t
val get_dpid : unit -> int64

val send_packet : ?in_port:Openflow.Ofpacket.Port.t -> ?buffer_id:int32 ->
  Cstruct.buf -> Openflow.Ofpacket.Flow.action list -> unit Lwt.t

val delete_flow : ?in_port:int option -> ?dl_vlan:int option -> 
  ?dl_src:string option -> ?dl_dst:string option ->
  ?dl_type:int option -> ?nw_proto:char option ->
  ?tp_dst:int option -> ?tp_src:int option ->
  ?nw_dst:int32 option -> ?nw_dst_len:int ->
  ?nw_src:int32 option -> ?nw_src_len:int ->
  ?dl_vlan_pcp:char option -> ?nw_tos:char option ->
  ?priority:int -> unit -> unit Lwt.t

val setup_flow : ?in_port:int option -> ?dl_vlan:int option -> 
  ?dl_src:string option -> ?dl_dst:string option ->
  ?dl_type:int option -> ?nw_proto:char option ->
  ?tp_dst:int option -> ?tp_src:int option ->
  ?nw_dst:int32 option -> ?nw_dst_len:int ->
  ?nw_src:int32 option -> ?nw_src_len:int ->
  ?dl_vlan_pcp:char option -> ?nw_tos:char option ->
  ?priority:int -> ?buffer_id:int ->
  ?idle_timeout:int -> ?hard_timeout:int ->
  Openflow.Ofpacket.Flow.action list -> unit Lwt.t
