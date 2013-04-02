(*
 * Copyright (c) 2012 Charalampos Rotsos <cr409@cl.cam.ac.uk>
 *
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

open Printf

open Lwt
open Lwt_unix
open Lwt_io

type tor_ctl_state = {
  fd : file_descr;
  output : output_channel;
  input : input_channel;
}

exception Tor_request_error of int * string

let print_data (status, lines) =
  let _ = eprintf "%d status\n%!" status in 
    List.iter (fun line -> 
      Printf.eprintf "%d+%s\n%!" status line 
    ) lines

let is_num value = 
  try 
    let _ = int_of_string value in true
  with exn -> false

let send_command st cmd = 
  lwt _ = write_line st.output cmd in 

  let rec read_reply st status = 
    lwt line = read_line st.input in
    let (status, data,more) = 
      if ( ((String.length line) >= 3) &&
          (is_num (String.sub line 0 3)) ) then 
        let status = int_of_string (String.sub line 0 3) in 
        let data = (String.sub line 4 ((String.length line) - 4)) in
        let more = String.sub line 3 1 in 
          (status, data, more)
        else
          (status, line, "+")
      in
      if (more = "+" || more = "-") then 
        lwt (_, fields) = read_reply st status in 
          return (status, ([data]@fields))
      else
        return (status, [data]) 
  in
  lwt ret = read_reply st 0 in 
(*  let _ = print_data ret in *)
    return ret

let init_tor_ctl ip port =
  try_lwt
  (* openning the socket *)
    let fd = socket PF_INET SOCK_STREAM 0 in
    let dst = Unix.inet_addr_of_string ip in 
    lwt _ = connect fd (ADDR_INET (dst, port)) in
    let input = of_fd ~mode:(input) fd in
    let output = of_fd ~mode:(output) fd in
  
    let ret = {fd;input;output;} in 
    lwt _ = send_command ret "AUTHENTICATE \"\"" in 
     return ret
  with exn ->
    let _ = eprintf "[tor] error %s\n%!" (Printexc.to_string exn) in
      failwith "error"

let close_tor_ctl st =
  try_lwt
  (* closing the socket *)
    close st.input
  with exn ->
    let _ = eprintf "[tor] error %s\n%!" (Printexc.to_string exn) in
      failwith "error"

let is_service_established st =
  lwt (status, reply) = send_command st "GETINFO circuit-status" in 
  let hashtbl_get_value r name = 
    try Some(Hashtbl.find r name) with Not_found -> None
  in
    Lwt_list.fold_right_s (
      fun circuit res -> 
        if (res) then return res 
        else
          let fields = 
            List.fold_right ( 
              fun a r -> 
                match (Re_str.split (Re_str.regexp "=") a) with
                | name::value::_ ->
                    let _ = Hashtbl.add r name value in r
                | _ -> r
            ) (Re_str.split (Re_str.regexp " ") circuit) 
            (Hashtbl.create 16) in
          let get = hashtbl_get_value fields in 
          match ((get "PURPOSE"), (get "HS_STATE")) with 
          | (Some "HS_SERVICE_INTRO", Some "HSSI_ESTABLISHED") -> 
              return true
          | _ , _ -> return res
    ) reply false 

let expose_service st dir ports =
  let cmd = ref (sprintf "SETCONF HiddenServiceDir=%s" dir) in 
  let _ = List.iter (fun port -> 
    cmd := sprintf "%s HiddenServicePort=%d" !cmd port 
  ) ports in 
    send_command st !cmd 
