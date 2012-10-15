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
open Int64
open Sp_rpc

type sp_msg = {
  src_ip : int32;
  src_port : int;
  cmd : t option;
}

let echo_port = 11000L 

module type HandlerSig = sig
  val handle_request : Lwt_unix.file_descr -> int32 -> command -> 
    arg list -> Sp.request_response Lwt.t
  val handle_notification : Lwt_unix.file_descr -> int32 -> command -> 
    arg list -> unit Lwt.t
end

module type Functor = sig
  val thread_client : address:Sp.ip -> 
    port:Sp.port -> (unit -> unit Lwt.t) -> unit Lwt.t
  val thread_server : address:Sp.ip -> port:Sp.port -> unit Lwt.t
end

module Make (Handler : HandlerSig) = struct
  let classify fd msg =
    let open Rpc in
    match msg.cmd with
    | Some (Request(c, args, id)) -> begin
        lwt response = (Handler.handle_request fd msg.src_ip c args) in
        match response with
        | Sp.ResponseValue v -> begin
            let resp = (create_response_ok v id) in
            Nodes.send_to_server resp 
        end
        | Sp.ResponseError e -> begin
            let error = create_response_error e id in
            Nodes.send_to_server error 
        end
        | Sp.NoResponse -> return ()
    end
    | Some (Response(r, id)) ->
        Nodes.wake_up_thread_with_reply id (Response(r, id))
    | Some (Notification(c, args)) ->
        Handler.handle_notification fd msg.src_ip c args
    | _ -> Printf.eprintf "[signalHandler] failed to process req\n%!";
           return ()

  let dispatch_rpc fd msg = 
    match msg.cmd with 
      | Some _ -> return (Lwt.ignore_result (classify fd msg))
      | None -> 
          eprintf "signal handler cannot dispatch a 'None'-RPC\n%!";
          return ()

  (* Listens on port Config.signal_port *)
  let create_fd ~address ~port =
    let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
      (* so we can restart our server quickly *)
    return fd

  let bind_fd ~address ~port =
    lwt fd = create_fd address port in 
    lwt src = try_lwt
      let hent = Unix.gethostbyname address in
      return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), (to_int port)))
    with _ ->
      raise_lwt (Failure ("cannot resolve " ^ address))
    in
    Lwt_unix.setsockopt fd Unix.SO_REUSEADDR true ;
    let () = Lwt_unix.bind fd src in
    let _ = Lwt_unix.listen fd 10 in 
      return fd


  let sockaddr_to_string =
    function
    | Unix.ADDR_UNIX x -> sprintf "UNIX %s" x
    | Unix.ADDR_INET (a,p) -> sprintf "%s:%d" 
                                (Unix.string_of_inet_addr a) p

  let process_channel sock dst =
    let data = ref "" in 
    let running = ref true in 
      try_lwt
        let rec process_buffer () =
          match (String.length !data) with
            | 0 -> return ()
            | _ -> begin 
                let (Some(rpc), len) = rpc_of_string !data in
(*
                  Printf.printf "XXXXXXXXXXXXX processing %s [remainder: %s]\n%!" 
                    (String.sub !data 0 len)
                    (String.sub !data len ((String.length !data) - len));
 *)
                  data := String.sub !data len ((String.length !data) - len);
                  let msg = 
                    match dst with 
                      |  Unix.ADDR_UNIX _ ->{src_ip=0l;src_port=0; cmd=Some(rpc);}
                      | Unix.ADDR_INET (a,_) -> {
                          src_ip=(Uri_IP.string_to_ipv4(Unix.string_of_inet_addr a)); 
                          src_port=0; cmd=Some(rpc);}
                  in 
                  let _ = Lwt.ignore_result (dispatch_rpc sock msg) in 
                    process_buffer ()
              end
        in
        while_lwt !running do
          let buf = String.create 4096 in
          lwt len = Lwt_unix.recv sock buf 0 (String.length buf) [] in
          match len with 
            | 0 -> begin 
                (* TODO: Propagate an event to engine to serverSignal to clean up 
                 * state for node *)
                printf "Channel read 0 bytes\n%!";
                Printf.printf "[signal] session terminated with end-node %s\n%!"
                  (sockaddr_to_string dst);
                running := false;
                return () 
              end
            | _ ->
                let subbuf = String.sub buf 0 len in
                  data := !data ^ subbuf;
                  eprintf "tcp recvfrom %s : %s\n%!" (sockaddr_to_string dst) subbuf;
                  process_buffer ()
        done
    with exn ->
      Printf.printf "[signal] session terminated with end-node %s : %s\n%!"
        (sockaddr_to_string dst) (Printexc.to_string exn);
      running := false;
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
        let buf = Bitstring.bitstring_of_string 
                    (String.sub rcv_buf 0 recvlen) in 
        bitmatch buf with 
          | {loc_ip:32; loc_port:16; 
             name_len:16; name:(name_len*8):string} ->
            (printf "received %s from %s:%d external %s:%d\n%!"
              name (Uri_IP.ipv4_to_string loc_ip) loc_port 
              (Uri_IP.ipv4_to_string ip) port;
            Nodes.add_node_public_ip name 
              (Uri_IP.ipv4_to_string ip) (loc_ip = ip) 
              (loc_port = port); 
            let reply = BITSTRING{ip:32; port:16; name_len:16;
                                  name:(name_len*8):string} in 
            let reply_str = Bitstring.string_of_bitstring reply in 
              lwt _ = Lwt_unix.send client_sock reply_str 0 
                        (String.length reply_str) [] in 
            
              return (Lwt_unix.shutdown client_sock Lwt_unix.SHUTDOWN_ALL))
    (*     let x = send client_sock str 0 len [] in *)
          | {_} ->
              printf "[echo_server] failed to parse packet\n%!";
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
  lwt fd = create_fd ~address ~port in
    lwt src = try_lwt
      let hent = Unix.gethostbyname address in
      return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), 
                              (to_int port)))
    with _ ->
      raise_lwt (Failure ("cannot resolve " ^ address))
    in
      lwt _ = Lwt_unix.connect fd src in
      let _ = Nodes.set_server_signalling_channel fd in
        (init ()) <&> (process_channel fd src )
end
