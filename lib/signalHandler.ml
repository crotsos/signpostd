(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
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
(* Signalling UDP server that runs over Iodine *)
open Lwt
open Printf
open Sp_rpc

let echo_port = 11000 

module type HandlerSig = sig
  val handle_request : Lwt_unix.file_descr -> command -> 
    arg list -> Sp.request_response Lwt.t
  val handle_notification : Lwt_unix.file_descr -> command -> 
    arg list -> unit Lwt.t
end

module type Functor = sig
  val thread_client : address:Sp.ip -> 
    port:int -> (unit -> unit Lwt.t) -> unit Lwt.t
  val thread_server : address:Sp.ip -> port:int -> unit Lwt.t
end

module Make (Handler : HandlerSig) = struct

  let classify fd msg =
    match msg with
    | Request(c, args, id) -> begin
        lwt response = (Handler.handle_request fd c args) in
          match response with
          | Sp.ResponseValue v -> 
              Nodes.send_to_server (create_response_ok v id)
          | Sp.ResponseError e -> 
              Nodes.send_to_server (create_response_error e id)
          | Sp.NoResponse -> return ()
    end
    | Response(r, id) ->
        Nodes.wake_up_thread_with_reply id (Response(r, id))
    | Notification(c, args) ->
        Handler.handle_notification fd c args

  let bind_fd ~address ~port =
    let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in 
    lwt src = try_lwt
      let hent = Unix.gethostbyname address in
      return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), port))
    with _ ->
      raise_lwt (Failure ("cannot resolve " ^ address))
    in
      (* so we can restart our server quickly *)
    Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true ;
    let () = Lwt_unix.bind fd src in
    let _ = Lwt_unix.listen fd 10 in 
      return fd

  let sockaddr_to_string =
    function
    | Unix.ADDR_UNIX x -> sprintf "UNIX %s" x
    | Unix.ADDR_INET (a,p) -> 
        sprintf "%s:%d" (Unix.string_of_inet_addr a) p

  let rec process_buffer sock data =
    match (String.length data) with
      | 0 -> return data
      | _ -> begin 
          match rpc_of_string data with 
            | (Some(msg), len) ->
                let data = String.sub data len ((String.length data) - len) in
                let _ = Lwt.ignore_result (classify sock msg) in 
                  process_buffer sock data
            | None , _ -> return data
        end

  let process_channel sock dst =
    try_lwt
      let rec channel_loop sock buf data =
        lwt len = Lwt_unix.recv sock buf 0 (String.length buf) [] in
        match len with 
          | 0 -> begin 
              (* TODO: Propagate an event to engine to serverSignal 
               * to clean up state for node *)
                eprintf "[signal] session terminated with end-node %s\n%!"
                  (sockaddr_to_string dst);
              return () 
          end
          | _ ->
            let subbuf = String.sub buf 0 len in
            let data = data ^ subbuf in 
            let _ = eprintf "tcp recvfrom %s : %s\n%!" 
                      (sockaddr_to_string dst) subbuf in
            lwt data = process_buffer sock data in 
              channel_loop sock buf data
      in 
        channel_loop sock (String.create 4096) "" 
    with exn ->
      Printf.printf "[signal] session terminated with end-node %s : %s\n%!"
        (sockaddr_to_string dst) (Printexc.to_string exn);
      return ()

  let echo_testing_server listen_port =
    lwt server_sock = bind_fd ~address:"0.0.0.0" ~port:listen_port in 
    (* accept and process connections *)
    while_lwt true do
      try_lwt
        lwt (client_sock, client_addr) = Lwt_unix.accept server_sock in
        let  Unix.ADDR_INET(ip, port) = client_addr in 
        let ip = (Uri_IP.string_to_ipv4 (Unix.string_of_inet_addr ip)) in
        let rcv_buf = String.create 2048 in 
        lwt recvlen = Lwt_unix.recv client_sock rcv_buf 0 1048 [] in
        let buf = 
          Cstruct.of_bigarray 
            (Lwt_bytes.of_string
              (String.sub rcv_buf 0 recvlen)) in
        let loc_ip = Cstruct.BE.get_uint32 buf 0 in 
        let loc_port = Cstruct.BE.get_uint16 buf 4 in 
        let name_len = Cstruct.BE.get_uint16 buf 6 in 
        let name = Cstruct.copy buf 8 name_len in 
        let _ = printf "received %s from %s:%d external %s:%d\n%!"
                  name (Uri_IP.ipv4_to_string loc_ip) loc_port 
                  (Uri_IP.ipv4_to_string ip) port in
        let _ = Nodes.add_node_public_ip name 
                (Uri_IP.ipv4_to_string ip) (loc_ip = ip) 
                (loc_port = port) in 
        
        let buf = Cstruct.create 1024 in 
        let _ = Cstruct.BE.set_uint32 buf 0 ip in 
        let _ = Cstruct.BE.set_uint16 buf 4 port in 
        let _ = Cstruct.BE.set_uint16 buf 6 name_len in
        let _ = Cstruct.blit_from_string name 0 buf 8 name_len in 
        let reply = Cstruct.to_string buf in 
        lwt _ = Lwt_unix.send client_sock reply 0 
                        (String.length reply) [] in 
          return (Lwt_unix.shutdown client_sock Lwt_unix.SHUTDOWN_ALL)
     with exn -> 
        Printf.eprintf "[echo_server]daemon error: %s\n%!" 
          (Printexc.to_string exn);
        return ()
    done

  let thread_server ~address ~port =
    (* Listen for UDP packets *)
    let _ = Lwt.ignore_result (echo_testing_server echo_port) in
    lwt fd = bind_fd ~address ~port in
    while_lwt true do 
      lwt (sock, dst) = Lwt_unix.accept fd in
      let _ = Lwt.ignore_result (process_channel sock dst) in 
        return ()
    done 

let thread_client ~address ~port init =
    (* Listen for UDP packets *)
  let _ = Lwt.ignore_result (echo_testing_server echo_port) in
  let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
  lwt src = 
    try_lwt
      let hent = Unix.gethostbyname address in
      return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), 
                              port))
    with _ ->
      raise_lwt (Failure ("cannot resolve " ^ address))
  in
  lwt _ = Lwt_unix.connect fd src in
  let _ = printf "client connected\n%!" in 
  let _ = Nodes.set_server_signalling_channel fd in
    (init ()) <&> (process_channel fd src )
end
