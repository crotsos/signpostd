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
let ip_resp key sign_tag ~dst ~src ~domain =
  lwt ip = Engine.find src dst in
    match ip with
      | Some ip -> 
          let answers = 
            { name=dst::src::domain;cls=RR_IN; ttl=0l;
              rdata=(A ip);} in
          let sign = 
            Sec.sign_records ~expiration:(Int32.of_float ((Unix.gettimeofday ()) +. 60.0) )
              Dns.Packet.RSASHA1 key sign_tag domain 
              [answers] in 
            return 
              ({rcode=NoError;aa=true;
                answer=[answers; sign;]; 
                authority=[]; 
                additional=[]; })
      | None -> 
          return nxdomain

(* Figure out the response from a query packet and its question section *)
let get_response key sign_tag packet q =
  (* Normalise the domain names to lower case *)
  let qnames = List.map String.lowercase q.q_name in
  eprintf "Q: %s\n%!" (String.concat " " qnames);
  let from_trie = answer_query ~dnssec:true q.q_name 
                    q.q_type Loader.(state.db.trie) in
  match qnames with
    (* For this strawman, we assume a valid query has form
     * <dst node>.<src node>.<domain name>
     *)
  |dst::src::domain -> begin
     let domain'=String.concat "." domain in
     if domain' = our_domain then begin
       eprintf "src:%s dst:%s dom:%s\n%!" src dst domain';
       ip_resp key sign_tag ~dst ~src ~domain
     end else return(from_trie)
  end
  |_ -> return (from_trie)

let dnsfn key sign_tag ~src ~dst packet =
  match packet.questions with
  |[] -> eprintf "bad dns query: no questions\n%!"; return None
  |[q] -> lwt resp = get_response key sign_tag packet q in
    return (Some (resp))
  |_ -> eprintf "dns dns query: multiple questions\n%!"; return None

let rdata_to_zone_file_record rr =
  match rr.rdata with
    | DNSKEY(f,a,k) ->
      let k = Cryptokit.transform_string (Cryptokit.Base64.encode_compact ()) k in
      let pad = ((String.length k) mod 4) in
      let k = 
        if (pad = 0) then
          k
        else
          k ^ (String.make (4 - pad) '=') 
      in 
      sprintf "%s. %s %ld DNSKEY %d 3 %d %s\n"
        (Dns.Name.domain_name_to_string rr.name)
        (rr_class_to_string rr.cls) rr.ttl 
        f (dnssec_alg_to_int a) k
    | RRSIG(typ, alg, lbl, orig_ttl, exp_ts, inc_ts, tag, name, sign) ->  
        let sign = Cryptokit.transform_string (Cryptokit.Base64.encode_compact ()) sign in
        let pad = ((String.length sign) mod 4) in
        let sign = 
          if (pad = 0) then
            sign
          else
            sign ^ (String.make (4 - pad) '=') 
        in 
        let typ = Re_str.global_replace (Re_str.regexp "RR_") 
                    "" (rr_type_to_string typ) in 
        sprintf "%s. %s %ld RRSIG %s %d %d %ld %ld %ld %d %s. \"%s\"\n"
          (Dns.Name.domain_name_to_string rr.name)
          (rr_class_to_string rr.cls) rr.ttl
          typ (dnssec_alg_to_int alg)
          (int_of_char lbl) orig_ttl exp_ts inc_ts tag
          (Dns.Name.domain_name_to_string name) sign
    | _ -> failwith "Unsupported rr type"

let load_dnskey_rr sign_tag key = 
  let ret = ref [] in 
  let dir = (Unix.opendir (Config.conf_dir ^ "/authorized_keys/")) in
  let rec read_pub_key dir =  
  try 
    let file = Unix.readdir dir in
    lwt _ = 
      if ( Re_str.string_match (Re_str.regexp ".*\\.pub") file 0) then
          let key = Config.conf_dir ^ "/authorized_keys/" ^ file in
          lwt dnskey_rr = 
            dnskey_rdata_of_pem_pub_file key 0 Dns.Packet.RSASHA1 in
            match dnskey_rr with
              | Some(rdata) -> 
                  let hostname = 
                    List.nth (Re_str.split (Re_str.regexp "\\.") file) 0 in 
                  let rr = Dns.Packet.({
                    name=([hostname] @ (our_domain_l));
                    cls=Dns.Packet.RR_IN;
                    ttl=120l;
                    rdata;}) in 
                  return (ret := (!ret) @ [rr])
                      
              | None -> return ()
      else
        return ()
  in
    read_pub_key dir
  with End_of_file -> 
    let _ = Unix.closedir dir in 
      return (!ret)
  in 
  lwt rrset = read_pub_key dir in 
  let rec rrset_to_string = function
    | [] -> ""
    | rr::tl when ((Dns.Packet.rdata_to_rr_type rr.rdata) = (Dns.Packet.RR_DNSKEY)) -> 
        let sign = 
          Sec.sign_records  
            Dns.Packet.RSASHA1 key sign_tag our_domain_l
            [rr] in 
          sprintf "%s\n%s\n%s"
            (rdata_to_zone_file_record rr)
            (rdata_to_zone_file_record sign)
            (rrset_to_string tl)
  in
    return (rrset_to_string rrset)

let load_key file = 
  let k = Key.load_rsa_priv_key file in 
    Sec.Rsa (Dnssec_rsa.new_rsa_key_from_param k) 

let dns_t () =
  lwt fd, src = Dns_server.bind_fd ~address:"0.0.0.0" ~port:5354 in
  let key  = load_key (Config.conf_dir ^ "/signpost.pem") in
  lwt Some(sign_dnskey) = Key.dnskey_rdata_of_pem_priv_file
                       (Config.conf_dir ^ "/signpost.pem")
                       257 Dns.Packet.RSASHA1 in 
  let sign_tag = Sec.get_dnskey_tag sign_dnskey in 
  let zsk = Dns.Packet.({
    name=(our_domain_l);
    cls=Dns.Packet.RR_IN;
    ttl=120l; rdata=sign_dnskey;}) in 
  let sign = 
    Sec.sign_records  
      Dns.Packet.RSASHA1 key sign_tag our_domain_l
      [zsk] in 
  lwt zone_keys = dnskey_of_pem_priv_file 
    (Config.conf_dir ^ "/signpost.pem")  in 
  lwt dns_keys = load_dnskey_rr sign_tag key in
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
%s
%s
%s" our_domain Config.external_ip our_domain Config.external_ip 
   Config.external_dns (rdata_to_zone_file_record zsk) 
                  (rdata_to_zone_file_record sign) dns_keys in
  eprintf "%s\n%!" zonebuf;
  Dns.Zone.load_zone [] zonebuf;
  Dns_server.listen ~fd ~src ~dnsfn:(dnsfn key sign_tag)

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
