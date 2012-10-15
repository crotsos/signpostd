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

val sp_ip_network : string
val sp_ip_netmask : int

(* API for sending rpc's to a node *)
val send : Sp.name -> t -> unit Lwt.t
val send_to_server : t -> unit Lwt.t
val send_blocking : Sp.name -> t -> string Lwt.t

(* Let the SignalHandler wake up a pending sender *)
val wake_up_thread_with_reply : id -> t -> unit Lwt.t

(* registry function for local node informations *)
val get_local_name : unit -> string
val set_local_name : string -> unit
val discover_local_ips : ?dev:string -> unit -> int32 list
val set_local_sp_ip: int32 -> unit
val get_local_sp_ip: unit -> int32

(* control channel manipulation *)
val set_signalling_channel : Sp.name -> Lwt_unix.file_descr -> unit
val set_server_signalling_channel : Lwt_unix.file_descr -> unit

(* API for updatating the node store *)
val set_node_local_ips : Sp.name -> Sp.ip list -> unit
val get_node_local_ips : Sp.name -> Sp.ip list
val add_node_public_ip: Sp.name -> Sp.ip -> bool -> bool -> unit
val get_node_public_ips:Sp.name -> Sp.ip list
val get_node_mac : Sp.name -> string
val set_node_mac : Sp.name -> string -> unit
val get_node_sp_ip : Sp.name -> int32
val get_nodes : unit -> Sp.name list

