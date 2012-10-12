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

open Sp_rpc
open Lwt
open Printf
open Int64
open Re_str
open Lwt_unix

lwt _ =
   let server_ip = Config.external_ip in 
   let remote_port = Config.signal_port in 
    let command = 
      try 
         Sys.argv.(1)
      with _ -> 
        failwith (Printf.sprintf "Invalid arg\n%!")
    in
      try_lwt 
        let client_sock = socket PF_INET SOCK_STREAM 0 in
        let hentry = Unix.inet_addr_of_string server_ip in
        lwt _ = 
           (Lwt_unix.sleep 4.0 >|= (fun _ -> failwith("Can't connect")) ) <?> 
                Lwt_unix.connect client_sock(ADDR_INET(hentry, remote_port)) in 
        let ADDR_INET(loc_ip,loc_port) = Lwt_unix.getsockname client_sock in

        let rpc = create_notification "exec_tactic" [command; "home"; "slave";] in
        let data = rpc_to_string rpc in  
          
        lwt _ = Lwt_unix.send client_sock data 0 (String.length data) [] in 
            Lwt_unix.shutdown client_sock SHUTDOWN_ALL; 
            return ()
      with exn ->
        eprintf "[signal] tcp client error:%s\n%!" (Printexc.to_string exn);
        return ()
