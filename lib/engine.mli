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

(** Find is the main entry point to the connections module.
 *  Given the name of two endpoints it will attempt to establish
 *  a link between them, and will immediately return with all
 *  known existing links
 *)
val find : Sp.name -> Sp.name -> int32 option Lwt.t

val tactic_by_name : tactic_name -> (module Sp.TacticSig) option
val connect_using_tactic : string -> string -> string -> bool Lwt.t
val dump_tunnels_t: unit -> unit Lwt.t
val disconnect: string -> string -> string -> unit Lwt.t

val tunnel_monitor_t: unit -> unit Lwt.t
