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
open Printf
open Int64
open Re_str

module IncomingSignalling = SignalHandler.Make (ClientSignalling)
let usage () = 
  Printf.printf "Usage: %s tactic_name\n%!" Sys.argv.(0)

let create_fd address port =
  let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
    return fd

lwt _ =
  let server_ip = Config.external_ip in 
  let remote_port = Config.signal_port in 
  let tactic = 
    try 
      Sys.argv.(1) 
    with _ -> 
      usage ();
      raise Exit
  in
              
  try_lwt 
    lwt fd = create_fd server_ip remote_port in
    lwt src = try_lwt
      let hent = Unix.gethostbyname server_ip in
      return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), remote_port))
    with _ ->
      raise_lwt (Failure ("cannot resolve " ^ server_ip ))
    in
    lwt _ = Lwt_unix.connect fd src in
    let rpc = Rpc.create_notification "exec_tactic" [tactic;"home";"slave"] in
    let buf = Rpc.rpc_to_string rpc in
    lwt _ = Lwt_unix.send fd buf 0 (String.length buf) [] in
    let _ = Lwt_unix.shutdown fd Lwt_unix.SHUTDOWN_ALL in
      return ()
  with exn ->
    return (printf "ERROR: %s\n%!" (Printexc.to_string exn))
