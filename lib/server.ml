(*
 * Copyright (c) 2005-2012 Anil Madhavapeddy <anil@recoil.org>
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

open Dns
open Dns.Packet
open Dns.Query

open Lwt 

open Printf
open Int64
open Sp_controller
open Key

(* The domain we are authoritative for *)
let our_domain =
  sprintf "d%d.%s" Config.signpost_number Config.domain

let our_domain_l =
  let d = "d" ^ (string_of_int Config.signpost_number) in
  [ d; Config.domain ]

(* Respond with an NXDomain if record doesnt exist *)
let nxdomain =
  {rcode=NXDomain;aa=false;
   answer=[]; authority=[]; additional=[]}

(* Ip address response for a node *)
let ip_resp key ~dst ~src ~domain =
  lwt ip = Engine.find src dst in
    match ip with
      | Some ip -> 
          let answers = 
            { name=dst::src::domain;cls=RR_IN; ttl=0l;
              rdata=(A ip);} in
          let lbl = (List.length domain) + 2 in 
          let sign = 
            Sec.sign_records ~expiration:(60l) 
              Dns.Packet.RSASHA1 key lbl domain 
              [answers] in 
            return 
              ({rcode=NoError;aa=true;
                answer=[answers; sign;]; 
                authority=[]; 
                additional=[]; })
      | None -> 
          return nxdomain

(* Figure out the response from a query packet and its question section *)
let get_response key packet q =
  (* Normalise the domain names to lower case *)
  let qnames = List.map String.lowercase q.q_name in
  eprintf "Q: %s\n%!" (String.concat " " qnames);
  let from_trie = answer_query q.q_name 
                    q.q_type Loader.(state.db.trie) in
  match qnames with
    (* For this strawman, we assume a valid query has form
     * <dst node>.<src node>.<domain name>
     *)
  |dst::src::domain -> begin
     let domain'=String.concat "." domain in
     if domain' = our_domain then begin
       eprintf "src:%s dst:%s dom:%s\n%!" src dst domain';
       ip_resp key ~dst ~src ~domain
     end else return(from_trie)
  end
  |_ -> return (from_trie)

let dnsfn key ~src ~dst packet =
  match packet.questions with
  |[] -> eprintf "bad dns query: no questions\n%!"; return None
  |[q] -> lwt resp = get_response key packet q in
    return (Some (resp))
  |_ -> eprintf "dns dns query: multiple questions\n%!"; return None

let load_dnskey_rr () = 
  let ret = ref "" in 
  let dir = (Unix.opendir (Config.conf_dir ^ "/authorized_keys/")) in
  let rec read_pub_key dir =  
  try 
    let file = Unix.readdir dir in
    lwt _ = 
      if ( Re_str.string_match (Re_str.regexp ".*\\.pub") file 0) then 
          lwt dnskey_rr = 
            dnskey_of_pem_pub_file 
              (Config.conf_dir ^ "/authorized_keys/" ^ file) in
          let hostname = 
            List.nth (Re_str.split (Re_str.regexp "\\.") file) 0 in 
            match dnskey_rr with
              | Some(value) -> 
                  return (ret := (!ret) ^ "\n" ^ 
                  (sprintf "%s IN %s\n" hostname (List.hd value)))
              | None -> return ()
      else
        return ()
  in
    read_pub_key dir
  with End_of_file -> 
    let _ = Unix.closedir dir in 
      return (!ret)
  in 
  read_pub_key dir

let load_key file = 
  let k = Key.load_rsa_priv_key file in 
    Sec.Rsa (Dnssec_rsa.new_rsa_key_from_param k) 

let dns_t () =
  lwt fd, src = Dns_server.bind_fd ~address:"0.0.0.0" ~port:5354 in
  lwt dns_keys = load_dnskey_rr () in
  let key  = load_key (Config.conf_dir ^ "/signpost.pem") in
  lwt zone_keys = (dnskey_of_pem_priv_file 
    (Config.conf_dir ^ "/signpost.pem"))  in 
  let zsk = 
    match zone_keys with
    | None -> failwith "Cannot open signpost.pem private key"
    | Some(keys) -> List.hd keys
  in
  let zonebuf = sprintf "
$ORIGIN %s. ;
$TTL 0

@ IN SOA %s. hostmaster.%s. (
  2012011206      ; serial number YYMMDDNN
  28800           ; Refresh
  7200            ; Retry
  864000          ; Expire
  86400           ; Min TTL
)

@ A %s
i NS %s.
@ %s
%s" our_domain Config.external_ip our_domain Config.external_ip 
   Config.external_dns zsk dns_keys in
  eprintf "%s\n%!" zonebuf;
  Dns.Zone.load_zone [] zonebuf;
  Dns_server.listen ~fd ~src ~dnsfn:(dnsfn key)

module IncomingSignalling = SignalHandler.Make (ServerSignalling)

let signal_t () =
  IncomingSignalling.thread_server ~address:"0.0.0.0" 
    ~port:(Config.signal_port)

lwt _ =
  let _ = Net_cache.Routing.load_routing_table () in 
  
  let _ = printf "routing table loaded...\n%!" in 
  let _ = Net_cache.Arp_cache.load_arp () in
    Net.Manager.create (
    fun mgr dev id -> 
    join [
      dns_t ();
      signal_t ();
      Engine.dump_tunnels_t ();                  
      Sp_controller.listen mgr ]
    )
