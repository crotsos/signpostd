(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
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

open Dns.Operators
open Dns.Packet
open Dns.Query 

open Lwt
open Printf
open Re_str
open Sp_rpc

module IncomingSignalling = SignalHandler.Make (ClientSignalling)

let our_domain = sprintf "d%d.%s" Config.signpost_number Config.domain
let node_name = ref "unknown"
let node_ip = ref "unknown"
let node_port = ref 0
let local_ips = ref []
  
let dns_domain = split (regexp_string ".") our_domain

let usage () = eprintf "Usage: %s <node-name> <node-ip> <node-signalling-port>\n%!" Sys.argv.(0); exit 1

(*checks if list v2 is a sublist of v1 *)
let rec compareVs v1 v2 = match v1, v2 with
  | [], _ -> (false, [])
  | rest, [] -> (true, rest)
  | x::xs, y::ys -> 
      if(x = y) then 
        compareVs xs ys
      else 
        (false, [])

let nxdomain =
  {Dns.Query.rcode=NXDomain; aa=false; 
   answer=[]; authority=[]; additional=[]}

let register_mobile_host name = 
  let args = [!node_name; name] in
  let rpc = create_notification "register_mobile_host" args in
      Nodes.send_to_server rpc

let sp_rr_to_packet rr name = 
  let ans = 
    {name; cls=RR_IN; ttl=60l; 
     rdata=rr.rdata;} in 
    {rcode=NoError; aa=true; 
     answer=[ans]; authority=[];
     additional=[];}

let forward_dns_query_to_ns resolv q = 
  try_lwt
    lwt p = Dns_resolver.resolve resolv ~dnssec:false 
              q.q_class q.q_type q.q_name in
      match p.answers with 
        | ans::_ -> return (sp_rr_to_packet ans q.q_name)
        | [] -> return (nxdomain)
  
  with ex -> 
    return (nxdomain) 

let forward_dns_query_to_sp st dst q = 
  (* Normalise the domain names to lower case *)
  let src = !node_name in 
  let host = dst::src::dns_domain in
  lwt res = Sec.resolve st q.q_class q.q_type host in 
    match res with
      | Sec.Signed(res::_) -> 
          return (sp_rr_to_packet res (dst::dns_domain))
      | _ -> return(nxdomain)

  (* Figure out the response from a query packet and its question section *)
let get_response resolv st q = 
  let qnames = List.map String.lowercase q.q_name in
  eprintf "Q: %s\n%!" (String.concat " " qnames);
  match (compareVs (List.rev qnames) (List.rev dns_domain)) with
    | (false, _) 
    | (true, []) -> forward_dns_query_to_ns resolv q 
    | (true, src) when ((List.length src) = 1)-> 
        printf "Forward to sp %s\n%!" (String.concat "." src) ;
        forward_dns_query_to_sp st (List.hd src) q
    | (true, src)  when ((List.length src) = 2) ->
        printf "sp mobile client %s\n%!" (String.concat "." src) ;
        lwt ret = forward_dns_query_to_sp st (List.hd src) q in 
        let _ = Lwt.ignore_result (register_mobile_host (List.nth src 1)) in 
          return (ret)
    | (_, _) -> failwith "XXX Error\n%!"

let dnsfn resolv st ~src ~dst packet =
  match packet.questions with
    | [] -> eprintf "bad dns query: no questions\n%!"; return None
    | q::_ -> 
        lwt ret = get_response resolv st q in
          return (Some ret)

let dns_t () =
  try_lwt
  (* setup default resovler for the rest *)
  lwt resolv = Dns_resolver.create () in
  (* setup resolver for the signpost *)
  let config = `Static([Config.external_ip,Config.dns_port], []) in
  lwt t = Dns_resolver.create ~config () in 
  lwt st = Sec.init_dnssec ~resolver:(Some(t)) () in

  lwt p = Dns_resolver.resolve t Q_IN Q_DNSKEY 
            dns_domain in
  let rec add_root_dnskey = function
    | [] -> ()
    | hd :: tl when (rdata_to_rr_type hd.rdata) = RR_DNSKEY -> 
        let _ = Sec.add_anchor st hd in
          add_root_dnskey tl 
    | hd :: tl -> add_root_dnskey tl
  in 
  let _ = add_root_dnskey p.answers in 
  (* local nameserver *)
  lwt fd, src = Dns_server.bind_fd ~address:"0.0.0.0" ~port:53 in
    Dns_server.listen ~fd ~src ~dnsfn:(dnsfn resolv st)
  with ex ->
    return (eprintf "[dns] error: %s\n%!" (Printexc.to_string ex))

let get_hello_rpc ips =
  let string_port = (string_of_int !node_port) in
  let ips = List.map Uri_IP.ipv4_to_string ips in 
  let ip_stream = (Unix.open_process_in
                     (Config.dir ^ 
                      "/client_tactics/get_local_device br0")) in
  let test = Re_str.split (Re_str.regexp " ") 
              (input_line ip_stream) in 
  let _::mac::_ = test in
  let args = [!node_name; !node_ip; string_port; mac;] @ ips in
    create_notification "hello" args

let update_server_if_state_has_changed () =
  let ips = Nodes.discover_local_ips ~dev:"br0" () in
  match (ips <> !local_ips) with
  | true -> begin
      let _ = local_ips := ips in 
      let hello_rpc = get_hello_rpc !local_ips in
        Nodes.send_to_server hello_rpc
  end
  | false -> return ()

let client_t () =
  try_lwt
    lwt _ = Net_cache.Routing.load_routing_table () in
    lwt _ = Net_cache.Arp_cache.load_arp () in
    let xmit_t =
      while_lwt true do
        update_server_if_state_has_changed ();
        Lwt_unix.sleep 2.0
      done
    in
     xmit_t 
  with exn ->
    printf "[client] Error: %s\n%!" (Printexc.to_string exn); 
    return ()

let signal_t ~port =
  IncomingSignalling.thread_client ~address:Config.external_ip ~port

lwt _ =
  (try node_name := Sys.argv.(1) with _ -> usage ());
  Nodes.set_local_name !node_name;
  (try node_ip := Sys.argv.(2) with _ -> usage ());
  (try node_port := (int_of_string Sys.argv.(3)) with _ -> usage ());
    Net.Manager.create (
      fun mgr _ _ -> 
        join [ 
         signal_t ~port:Config.signal_port (client_t);
         (*Monitor.monitor_t ();*)
         dns_t ();
         Sp_controller.listen mgr; 
        ]
    )
