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
open Lwt_unix
open Printf
open Int64
open Sp_rpc
open Net_cache
open Config 


module OP = Openflow.Ofpacket
module OC = Openflow.Ofcontroller

exception Ssh_error

let name () = "ssh"
let ssh_port = 10000

let ssh_weight = 8

(* a struct to store details for each node participating in a 
 * tunnel formation *)
type ssh_client_state_type = {
  name: string;                    (* node name *)
  mutable tactic_ip: int32;        (* ip for the node for the tunnel *)
  mutable extern_ip: int32 option; (* public ip discovered through the test *)
  mutable dev_id: int option;      (* dev id of the tunnel tun tap device *)
}

type ssh_conn_state_type = {
  (* a list of the nodes *)
  mutable nodes : ssh_client_state_type list;
  (* the direction of the tunnel as discovered through
   * the test. 1 -> (a > b), 2 -> (b > a), 3 -> cloud *)
  mutable direction : int; 
  mutable pid : int option; (* server pid *)
  mutable conn_id : int32;  (* connection id *)
}

type ssh_state_type = {
  (* a cache for connection informations *)
  conns : ((string * string), 
           ssh_conn_state_type) Hashtbl.t;
  (* a monotonically increasing connection id generator *)
  mutable conn_counter : int32;
}

let state = {conns=Hashtbl.create 64; conn_counter=0l;}
(*
 * Util functions to handle tactic state
 * *)
let get_external_ip state name =
    let ret = List.find (fun a -> (a.name = name)) state.nodes in
    match ret.extern_ip with
    | Some a -> a 
    | None -> raise Not_found

let get_dev_id state name =
    let ret = List.find (fun a -> (a.name = name)) state.nodes in
      match ret.dev_id with
      | Some a -> a 
      | None -> raise Not_found

let set_dev_id state name dev_id =
  let ret = List.find (fun a -> (a.name = name)) state.nodes in
    ret.dev_id <- Some(dev_id)

let get_tactic_ip state name =
  let _ = printf "[ssh] looking up name %s...\n%!" in 
  let ret = List.find (fun a -> (a.name = name)) state.nodes in
    ret.tactic_ip

let gen_key a b =
  if(a < b) then (a, b) else (b, a)

let get_state a b =
  let key = gen_key a b in 
  if (Hashtbl.mem state.conns key) then
    Hashtbl.find state.conns key 
  else (
    let ret = {nodes=[];direction=0;pid=None;conn_id=(state.conn_counter)} in 
      state.conn_counter <- (Int32.add state.conn_counter 1l);
      Hashtbl.add state.conns key ret;
      ret
  )

(* 
 * weight function
 * *)

let weight a b = 
  let key = gen_key a b in
    try 
      let conn = Hashtbl.find state.conns key in 
        if (conn.direction = 3) then
          ssh_weight 
        else 
          (ssh_weight/2)
    with Not_found ->
      100

(*
 * testing code
 * *)
let calculate_tactic_ip base conn =
  Int32.add base (Int32.shift_left conn.conn_id 8)

let test a b =
  (* Trying to see if connectivity is possible *)
  let (a, b) = gen_key a b in
  let conn = get_state a b in 
  let succ = ref false in 
  let dir = ref 3 in 
  let ip = ref Config.external_ip in
  (*
   * A method to instruct client nodes to test if connectivity is possible
   * on tcp port 10000. The function test connectivity from host a to host b.
   * return the ip address the was accesible
   * *)  
  let pairwise_connection_test a b direction =
    try_lwt 
      Printf.printf "[ssh] Trying to start ssh service...\n%!";
      let rpc = (create_tactic_request "ssh" 
        TEST "server_start" [(string_of_int ssh_port)]) in
      lwt _ = (Nodes.send_blocking a rpc) in 
  
      (* Avoid testing my self for open connections *)
      let not_ips =  (Nodes.get_node_local_ips b) in
      let ips = 
        List.filter (
          fun a -> not (List.mem a not_ips) ) 
          ((Nodes.get_node_local_ips a) @ 
           (Nodes.get_node_public_ips a)) in  
      
      lwt res = Nodes.send_blocking b 
                  (create_tactic_request "ssh" 
                     TEST "client" 
                     ([(string_of_int ssh_port)] @ ips))  in
        dir := direction; succ := true; ip := res;
        return ()
    with exn ->
      return (Printf.eprintf "[ssh] Pairwise test %s->%s failed:%s\n%!" 
                a b (Printexc.to_string exn))
  in

  lwt _ = (pairwise_connection_test a b 1) <&> 
             (pairwise_connection_test b a 2) in
     match (!succ) with
      | true ->
          (* In case we have a direct tunnel then the nodes will receive an 
          * ip from the subnet 10.2.(conn_id).0/24 *)
          let nodes = [ 
            {name=(sprintf "%s.d%d" a Config.signpost_number); 
             tactic_ip=(calculate_tactic_ip 0x0a020001l conn); 
             extern_ip=Some(Uri_IP.string_to_ipv4 !ip);dev_id=None;};
            {name=(sprintf "%s.d%d" b Config.signpost_number);
             tactic_ip=(calculate_tactic_ip 0x0a020002l conn); 
             extern_ip=Some(Uri_IP.string_to_ipv4 !ip);dev_id=None} ] in 
          conn.nodes <- nodes;
          conn.direction <- !dir;
          conn.pid <- None;
          return true
      (* go through cloud then *)
      | false -> 
          let nodes = [ 
            {name=(sprintf "d%d" Config.signpost_number); 
             tactic_ip=(calculate_tactic_ip 0x0a020001l conn); 
             extern_ip=Some(Uri_IP.string_to_ipv4 Config.external_ip);
             dev_id=None};
            {name=(sprintf "%s.d%d" a Config.signpost_number); 
             tactic_ip=(calculate_tactic_ip 0x0a020002l conn);
             extern_ip=None;dev_id=None;};
            {name=(sprintf "%s.d%d" b Config.signpost_number); 
             tactic_ip=(calculate_tactic_ip 0x0a020003l conn);
             extern_ip=None;dev_id=None;}; ] in 
          conn.nodes <- nodes;
          conn.direction <- !dir;
          conn.pid <- None;
          return true

(*
 * connection code
 * *)

(* 
 * a function to start ssh server on node node and add 
 * client_name as a permitted connecting node.
 * *)
let start_ssh_server conn loc_node rem_node =
  try_lwt
    let q_rem_node = (sprintf "%s.d%d" rem_node Config.signpost_number) in 
    let rem_sp_ip = (Uri_IP.ipv4_to_string 
                       (Nodes.get_node_sp_ip rem_node)) in
    let tunnel_ip = 
      Uri_IP.ipv4_to_string 
        (get_tactic_ip conn 
           (sprintf "%s.d%d" loc_node Config.signpost_number)) in     
    lwt res = Nodes.send_blocking loc_node  
                (create_tactic_request "ssh" CONNECT "start_server" 
                   [q_rem_node; rem_node; 
                    (Int32.to_string conn.conn_id ); 
                    rem_sp_ip;tunnel_ip]) in 
      return (res)
  with exn -> 
    printf "[ssh] server %s error: %s\n%!" loc_node (Printexc.to_string exn);
    raise Ssh_error

let connect_ssh_server conn loc_node rem_node dev_id =
  try_lwt
    let q_rem_node = (sprintf "%s.d%d" rem_node Config.signpost_number) in 
    let rem_sp_ip = (Uri_IP.ipv4_to_string 
                       (Nodes.get_node_sp_ip rem_node)) in
    let tunnel_ip = 
      Uri_IP.ipv4_to_string 
        (get_tactic_ip conn 
           (sprintf "%s.d%d" loc_node Config.signpost_number)) in     
    lwt res = Nodes.send_blocking loc_node  
                (create_tactic_request "ssh" CONNECT "connect_server" 
                   [q_rem_node; rem_node; 
                    (Int32.to_string conn.conn_id ); 
                    rem_sp_ip;tunnel_ip; dev_id;]) in 
      return (res)
  with exn -> 
    printf "[ssh] server %s error: %s\n%!" loc_node (Printexc.to_string exn);
    raise Ssh_error

(*
 * a function to start an ssh client that connects to 
 * dst_ip:dst_port with host node and assigns an ip 
 * under the vpn_subnet subnet. 
 * *)
let start_ssh_client conn loc_node rem_node rem_dev_id =
  try_lwt
    let q_rem_node = sprintf "%s.d%d" rem_node Config.signpost_number in 
    let server_ip = 
      get_external_ip conn 
        (sprintf "%s.d%d" loc_node Config.signpost_number) in
    let server_ip = Uri_IP.ipv4_to_string server_ip in
          
    let loc_tun_ip = 
      Uri_IP.ipv4_to_string 
        (get_tactic_ip conn (sprintf "%s.d%d" loc_node Config.signpost_number)) in     
    let rpc = (create_tactic_request "ssh" CONNECT "client" 
                 [server_ip; (string_of_int ssh_port); q_rem_node; rem_node; 
                  (Int32.to_string conn.conn_id); loc_tun_ip; 
                  rem_dev_id;]) in
    lwt _ = Nodes.send_blocking loc_node rpc in 
      return ()
  with exn -> 
    printf "[ssh] client error %s: %s\n%!" loc_node (Printexc.to_string exn);
    raise Ssh_error

(*
 * setup an ssh tunnel between hosts a and b where a 
 * will connect to remote ip ip.
 * return ip pair of the ssh tunnel.
 * *)
let init_ssh conn a b = 
  (* Init server on b *)
  lwt dev_id = start_ssh_server conn a b in
  let q_a = sprintf "%s.d%d" a Config.signpost_number in 
  let _ = set_dev_id conn q_a (int_of_string dev_id) in
  lwt _ = start_ssh_client conn b a dev_id in
  lwt dev_id = connect_ssh_server conn a b dev_id in
    return true


let start_local_server conn a b =
  (* Maybe load a copy of the Openvpn module and let it 
   * do the magic? *)
  printf "[ssh] Starting ssh server...\n%!";
  lwt _ = Ssh.Manager.run_server () in

  let create_devices host = 
    let dev_id = Tap.get_new_dev_ip () in 
    let host = sprintf "%s.d%d.%s" host Config.signpost_number
                 Config.domain in
    let _ = Ssh.Manager.server_add_client conn.conn_id host 
              0l dev_id "" in
      dev_id
  in
  let connect_client loc_node rem_dev rem_node =
    let domain = (sprintf "d%d" Config.signpost_number) in 
    let q_loc_node = sprintf "%s.d%d" loc_node Config.signpost_number in
(*     let dev = Printf.sprintf "tap%d" local_dev in   *)
    let _ = set_dev_id conn q_loc_node rem_dev in 
    let ip = Uri_IP.ipv4_to_string (get_tactic_ip conn domain) in
    lwt _ = Tap.setup_dev rem_dev ip in  
    
    let loc_tun_ip = 
      Uri_IP.ipv4_to_string (get_tactic_ip conn q_loc_node) in     
    let rpc = (create_tactic_request "ssh" 
                 CONNECT "client" 
                 [Config.external_ip; (string_of_int ssh_port);
                  domain; rem_node; (Int32.to_string conn.conn_id); 
                  loc_tun_ip; (string_of_int rem_dev);]) in
    lwt _ = (Nodes.send_blocking loc_node rpc) in 
      return ()
  in
  try_lwt
    lwt _ = 
      Lwt_list.map_p 
       (fun (a, b) -> 
         let a_dev = create_devices a in 
            connect_client a a_dev b )
       [(a, b);(b, a)] in
(*     lwt _ = setup_cloud_flows a_dev b_dev in  *)
      return ("true")
  with ex ->
    Printf.printf "[ssh] client fail %s\n%!" (Printexc.to_string ex);
    failwith (Printexc.to_string ex)

(*
 * a function to setup an ssh tunnel between hosts 
 * a b.
 * *)
let connect a b =
  try_lwt
  (* Trying to see if connectivity is possible *)
    let (a, b) = gen_key a b in
    let conn = get_state a b in 
    match conn.direction with
      | 1 -> init_ssh conn a b 
      | 2 -> init_ssh conn b a
      | 3 -> begin
          lwt _ = start_local_server conn b a in
            return (true)
        end
      | _ -> return false
  with exn ->
    Printf.eprintf "[ssh] connect failed (%s)\n%!" 
      (Printexc.to_string exn);
    return false

(*
 * methods to enable traffic transmission over the tunnel
 * *)

let setup_cloud_flows a_dev b_dev a_tun_ip b_tun_ip = 
  let a_port = Port_cache.dev_to_port_id (sprintf "tap%d" a_dev) in 
  let b_port = Port_cache.dev_to_port_id (sprintf "tap%d" b_dev) in 

 let actions = [OP.Flow.Output((OP.Port.port_of_int b_port), 
                                2000);] in
  lwt _ = Sp_controller.setup_flow ~in_port:(Some(a_port)) 
            ~dl_type:(Some(0x0800)) ~nw_dst_len:0 
            ~nw_dst:(Some(b_tun_ip)) ~idle_timeout:0 ~hard_timeout:0 
            ~priority:Ssh.tactic_priority actions in
  
  let actions = [OP.Flow.Output((OP.Port.port_of_int a_port), 
                                2000);] in
    Sp_controller.setup_flow ~nw_dst_len:0
      ~in_port:(Some(b_port)) ~dl_type:(Some(0x0800))
      ~nw_dst:(Some(a_tun_ip)) ~priority:Ssh.tactic_priority 
      ~idle_timeout:0  ~hard_timeout:0 actions 

let enable_ssh conn a b = 
  (* Init server on b *)
  try_lwt
    let q_a = sprintf "%s.d%d" a signpost_number in 
    let q_b = sprintf "%s.d%d" b signpost_number in 
    let rpc_a = 
      (create_tactic_request "ssh" ENABLE "enable" 
         [(Int32.to_string conn.conn_id); (Nodes.get_node_mac b); 
          (Uri_IP.ipv4_to_string (get_tactic_ip conn q_a));
          (Uri_IP.ipv4_to_string (get_tactic_ip conn q_b));
          (Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip a));
          (Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip b))]) in
    lwt _ = Nodes.send_blocking a rpc_a in
      return ()
  with ex -> 
    Printf.printf "[ssh]Failed ssh enabling %s->%s:%s \n%s\n%!" a b
      (Printexc.to_string ex) (Printexc.get_backtrace ());
    raise Ssh_error

let enable_cloud_ssh conn a b =
  try_lwt 
      if (conn.direction = 3) then (
        let q_a = sprintf "%s.d%d" a signpost_number in 
        let q_b = sprintf "%s.d%d" b signpost_number in 
        let a_dev = get_dev_id conn q_a in
        let b_dev = get_dev_id conn q_b in
        let a_tun_ip = get_tactic_ip conn q_a in
        let b_tun_ip = get_tactic_ip conn q_b in
          setup_cloud_flows a_dev b_dev a_tun_ip b_tun_ip
      ) else (
        return ()
      )
  with ex -> 
    Printf.printf "[ssh]Failed ssh enabling %s->%s:%s\n%!" a b
      (Printexc.to_string ex);
    raise Ssh_error

let enable a b =
  let (a, b) = gen_key a b in
  let conn = get_state a b in
  let _ = printf "[ssh] trying to enable connection...\n%!" in 
  lwt _ = (enable_ssh conn a b) <&>
          (enable_ssh conn b a) <&>
          (enable_cloud_ssh conn a b) in
    return true

(*
 * disable code
 * *)
let disable_ssh conn a b = 
  (* Init server on b *)
  try_lwt
    let q_a = Printf.sprintf "%s.d%d" a Config.signpost_number in 
    let rpc_a = 
      (create_tactic_request "ssh" DISABLE "disable" 
         [(Int32.to_string conn.conn_id); 
          (Uri_IP.ipv4_to_string (get_tactic_ip conn q_a));
          (Uri_IP.ipv4_to_string (Nodes.get_node_sp_ip b))]) in
    lwt _ = Nodes.send_blocking a rpc_a in
      return ()
  with ex -> 
    Printf.printf "[ssh]Failed ssh enabling :%s\n%!"
      (Printexc.to_string ex);
    raise Ssh_error

let disable_cloud_ssh conn a b =
  try_lwt 
      if (conn.direction = 3) then 
        let q_a = sprintf "%s.d%d" a Config.signpost_number in 
        let a_tun_ip = get_tactic_ip conn q_a in
          Sp_controller.delete_flow
            ~dl_type:(Some(0x0800)) ~priority:Ssh.tactic_priority
            ~nw_dst:(Some(a_tun_ip)) ()
      else
        return ()
  with ex -> 
    Printf.printf "[ssh]Failed ssh enabling %s->%s:%s\n%!" a b
      (Printexc.to_string ex);
    raise Ssh_error

let disable a b =
  let (a, b) = gen_key a b in
  let conn = get_state a b in
  lwt _ = (disable_ssh conn a b) <&>
          (disable_ssh conn b a) <&>
          (disable_cloud_ssh conn a b) in
  return true

(*
 * teardown code
 * *)
let teardown _ _ = return true

(* ******************************************
 * A tactic to setup a layer 2 ssh tunnel
 * ******************************************)

let handle_request action method_name arg_list =
  let open Rpc in
    (try_lwt 
       match action with
         | TEST ->
             lwt ip = Ssh.Manager.test method_name arg_list in
               return(Sp.ResponseValue ip)
         | CONNECT ->
             lwt ip = Ssh.Manager.connect method_name arg_list in
               return(Sp.ResponseValue ip)            
         | ENABLE ->
             lwt ip = Ssh.Manager.enable method_name arg_list in
               return(Sp.ResponseValue ip)            
         | DISABLE ->
             lwt ip = Ssh.Manager.disable method_name arg_list in
               return(Sp.ResponseValue ip)            
         | TEARDOWN ->
             lwt ip = Ssh.Manager.teardown method_name arg_list in
               return(Sp.ResponseValue ip)            
      with ex ->  
        return(Sp.ResponseError (Printexc.to_string ex)) )

let handle_notification _ _ _ =
  eprintf "Ssh tactic doesn't handle notifications\n%!";
  return ()
