/*
 * =====================================================================================
 *
 *       Filename:  tap_routing.c
 *
 *    Description:  A c interface to the os network layer in order to fetch information 
 *    from the network stack
 *
 *        Version:  1.0
 *        Created:  01/10/2012 15:44:31
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Charalampos Rotsos (cr409@cl.cam.ac.uk), 
 *   Organization:  University of Cambridge
 *
 * =====================================================================================
 */

#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>

#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <sys/sysctl.h>

#ifdef __linux__

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/cache.h>
#include <netlink/route/route.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>

#elif __APPLE__

#include <net/if.h>
#include <sys/sockio.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <ifaddrs.h>

#endif

#ifdef __linux__
CAMLprim value 
ocaml_get_routing_table(value unit) {
  CAMLparam1(unit);
  CAMLlocal3( ret, tmp, entry );

  struct nl_sock *fd; 
  struct nl_cache *res, *links;
  struct rtnl_route *it;
  uint32 i_ip, netmask = 0, mask_len, gw;
  int i;
  struct nl_addr *ip; 
  char device_name[IFNAMSIZ]; 
  struct rtnl_nexthop *to;
  fd = nl_socket_alloc();
  if (!fd) {
    fprintf(stderr, "error nl_socket_alloc\n");
    exit(1);
  }

  if(nl_connect(fd, NETLINK_ROUTE) < 0) {
    fprintf(stderr, "error nl_connect\n");
    exit(1);
  }

  ret = Val_emptylist;
  
  if(rtnl_route_alloc_cache(fd, AF_UNSPEC, 0, &res) < 0) {
    fprintf(stderr, "error rtnl_route_alloc_cache");
    exit(1);
  }

  if(rtnl_link_alloc_cache (fd, AF_UNSPEC, &links) < 0) {
    fprintf(stderr, "error rtnl_link_alloc_cache");
    exit(1);
  }

  it = (struct rtnl_route *)nl_cache_get_first(res);
  for(;it != NULL; it = (struct rtnl_route *) 
      nl_cache_get_next((struct nl_object *)it) ) {
    if(rtnl_route_get_family (it) == AF_INET) {
      ip = rtnl_route_get_dst(it);
      i_ip = ntohl(*(int *)nl_addr_get_binary_addr(ip));
      mask_len = nl_addr_get_prefixlen(ip);
      for(i = 0; i < 32; i++)
        netmask = (netmask << 1) + (i< mask_len?1:0);
      to = rtnl_route_nexthop_n(it, 0);
      rtnl_link_i2name(links, rtnl_route_nh_get_ifindex(to),
          device_name, IFNAMSIZ);
      if ( rtnl_route_nh_get_gateway (to) != NULL)
        gw = ntohl(*(int *)nl_addr_get_binary_addr(
              rtnl_route_nh_get_gateway (to)));
      else
        gw = 0;
      /*printf("src ip:%x mask:%x gw:%x dev:%s\n", i_ip, netmask, */
          /*gw, device_name);*/

      entry = caml_alloc(5,0);
      Store_field(entry, 0, Val_int(i_ip));
      Store_field(entry, 1, Val_int(netmask));
      Store_field(entry, 3, Val_int(gw));
      Store_field(entry, 4, caml_copy_string(device_name));
    
    // store in list
    tmp =  caml_alloc(2, 0);
    Store_field( tmp, 0, entry);  // head
    Store_field( tmp, 1, ret);  // tail
    ret = tmp;
    }
  }

  nl_cache_free(res);
  nl_cache_free(links);
  nl_close(fd);
  nl_socket_free(fd);
  CAMLreturn(ret);
}

CAMLprim value 
ocaml_get_local_ip(value unit) {
  CAMLparam1(unit);
  CAMLlocal4( ret, tmp, entry, mac);
  struct nl_sock *fd; 
  struct nl_cache *addrs, *links;
  struct rtnl_addr *it;
  struct nl_addr *addr, *mac_addr;
  struct rtnl_link *dev;

  // Init return list
  fd = nl_socket_alloc();
  if (!fd) {
    fprintf(stderr, "error nl_socket_alloc\n");
    exit(1);
  }

  if(nl_connect(fd, NETLINK_ROUTE) < 0) {
    fprintf(stderr, "error nl_connect\n");
    exit(1);
  }

  ret = Val_emptylist;
  
  if(rtnl_addr_alloc_cache (fd,&addrs) < 0) {
    fprintf(stderr, "error rtnl_link_alloc_cache");
    exit(1);
  }
  if(rtnl_link_alloc_cache (fd, AF_UNSPEC, &links) < 0) {
    fprintf(stderr, "error rtnl_link_alloc_cache");
    exit(1);
  }


  it = (struct rtnl_addr *)nl_cache_get_first(addrs);
  for(;it != NULL; it = (struct rtnl_addr *) 
      nl_cache_get_next((struct nl_object *)it) ) {
    addr = rtnl_addr_get_local(it);
    if (nl_addr_get_family(addr) != AF_INET) continue;
    /*printf("got an ip %x on dev %d\n",*/
        /*ntohl(*(int *)nl_addr_get_binary_addr(addr)), */
        /*rtnl_addr_get_ifindex(it));*/
    dev = rtnl_link_get (links, rtnl_addr_get_ifindex(it));
    if (!dev) continue;
    mac_addr = rtnl_link_get_addr(dev);
    if (!mac_addr) continue;
    tmp =  caml_alloc(2, 0);
    entry = caml_alloc(3, 0); 
    Store_field(entry, 0, caml_copy_string(rtnl_link_get_name(dev)));
    mac = caml_alloc_string(6); 
    memcpy( String_val(mac), nl_addr_get_binary_addr(mac_addr), 6);
    Store_field(entry, 1, mac);
    Store_field(entry, 2, Val_int(
          ntohl(*(int *)nl_addr_get_binary_addr(addr))));
    Store_field( tmp, 0, entry);  // head
    Store_field( tmp, 1, ret);  // tail
    ret = tmp;
  }

  nl_cache_free(links);
  nl_cache_free(addrs);
  nl_close(fd);
  nl_socket_free(fd);
  CAMLreturn(ret);
}

CAMLprim value 
ocaml_get_arp_table(value unit) {
  CAMLparam1(unit);
  CAMLlocal4( ret, tmp, mac, entry );
  ret = Val_emptylist;
  char buf[1024];
  int i;

  FILE *arp = fopen("/proc/net/arp", "r");
  if(!arp) {
    fprintf(stderr, "cannot open /proc/net/arp");
    exit(1);
  }
  
  fgets(buf, 1024, arp);

  while(fgets(buf, 1024, arp)) {
    int type, flag;
    char ip[64], str_mac[64], b_mac[6], *p;
    sscanf(buf, "%s %x %x %s", ip, &type, &flag, str_mac);
    /*printf("git ip %s and mac %s\n", ip, str_mac);*/
    bzero(b_mac, 6);
    p = (char *)str_mac;
    for (i = 0; i< 6; i++) {
      *(p+2) = '\0';
      b_mac[i] = (char)strtol(p, NULL, 16);
      p += 3;
    }
    //PRINT ETHER (OR STATUS)
    in_addr_t in_ip = inet_addr(ip);
    entry = caml_alloc(2,0);
    Store_field(entry, 1, Val_int(ntohl(in_ip)));
    mac = caml_alloc_string(6); 
    memcpy( String_val(mac), b_mac, 6);

    // store in list
    tmp =  caml_alloc(2, 0);
    Store_field( tmp, 0, entry);  // head
    Store_field( tmp, 1, ret);  // tail
    ret = tmp;

  }

  fclose(arp);
  CAMLreturn(ret);
}



#elif __APPLE__

/* Darwin doesn't define this for some very odd reason */
#ifndef SA_SIZE
# define SA_SIZE(sa)                        \
  (  (!(sa) || ((struct sockaddr *)(sa))->sa_len == 0) ?  \
     sizeof(long)     :               \
     1 + ( (((struct sockaddr *)(sa))->sa_len - 1) | (sizeof(long) - 1) ) )
#endif

#define min(a,b) ((a) < (b) ? (a) : (b))
#define max(a,b) ((a) > (b) ? (a) : (b))

CAMLprim value 
ocaml_get_routing_table(value unit) {
  CAMLparam1(unit);
  CAMLlocal3( ret, tmp, entry );

  size_t needed;
  int mib[6];
  char *buf, *next, *lim;
  struct rt_msghdr *rtm;
  struct sockaddr *dst, *gw, *mask;
  struct sockaddr_in *dstin, *gwin, *maskin;
  char device_name[IFNAMSIZ];

  // Init return list
  ret = Val_emptylist;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_DUMP;
  mib[5] = 0;

  //check first how much memory we need and allocate memory
  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) 
    err(1, "sysctl: net.route.0.0.dump estimate");

  if ((buf = (char *)malloc(needed)) == NULL) 
    errx(2, "malloc(%lu)", (unsigned long)needed);

  // now that we have the memory, get the data
  if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) 
    err(1, "sysctl: net.route.0.0.dump");

  // parse routing messages
  lim  = buf + needed;
  for (next = buf; next < lim; next += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)next;

    // filter out any non routing entries
    if ((rtm->rtm_addrs & (RTA_GATEWAY | RTA_DST | RTA_NETMASK )) != 
        (RTA_GATEWAY | RTA_DST | RTA_NETMASK))  continue;

    /* informations start right after the message content */
    dst = (struct sockaddr *)(rtm +1);

    /* first sockaddr is the subnet */
    dstin = (struct sockaddr_in *)dst;

    /* second is the gw address or sockaddr_dl of the interface */
    gw = (struct sockaddr *)(SA_SIZE(dst) + (char *)dst);

    /* third entry is the netmask */
    /* TODO sockaddr some times has wrong sa_family. */
    if (gw->sa_family != AF_INET) 
      mask = (struct sockaddr *)((char *)(gw->sa_len + (char *)gw));
    else
      mask = (struct sockaddr *)((char *)(SA_SIZE(gw) + (char *)gw));
    maskin = (struct sockaddr_in *)mask;
    if_indextoname(rtm->rtm_index, device_name);

    /* if the gateway is an up use it, otherwise value is 0 */
    entry = caml_alloc(5,0);
    if(gw->sa_family == AF_INET) { 
      gwin = (struct sockaddr_in *)gw;
      Store_field(entry, 2, Val_int(ntohl(gwin->sin_addr.s_addr)));
/*      printf("net %x gw %x mask %x dev %s\n", */
          /*ntohl(dstin->sin_addr.s_addr), ntohl(gwin->sin_addr.s_addr), ntohl(maskin->sin_addr.s_addr), device_name);*/
    } else {
      Store_field(entry, 2, Val_int(0));
/*      printf("net %x gw %x mask %x dev %s\n", ntohl(dstin->sin_addr.s_addr), 0,*/
          /*ntohl(maskin->sin_addr.s_addr), device_name);*/
    }
    Store_field(entry, 0, Val_int(ntohl(dstin->sin_addr.s_addr)));
    Store_field(entry, 1, Val_int(ntohl(maskin->sin_addr.s_addr)));
    Store_field(entry, 3, Val_int(0));
    Store_field(entry, 4, caml_copy_string(device_name));

    // store in list
    tmp =  caml_alloc(2, 0);
    Store_field( tmp, 0, entry);  // head
    Store_field( tmp, 1, ret);  // tail
    ret = tmp;
  }

  free(buf);
  CAMLreturn(ret);
}

CAMLprim value 
ocaml_get_local_ip(value unit) {
  CAMLparam1(unit);
  CAMLlocal4( ret, tmp, entry, mac);

  struct ifaddrs *ifa, *p;
  struct sockaddr_in *ip_in;

  struct ifconf ifc;
  struct ifreq *ifr;
  int i, sockfd, intf_count;
  char buffer[4096], *cp, *cplim;
  char ***name_cache;

  // Init return list
  ret = Val_emptylist;

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
    err(1, "socket failed");

  ifc.ifc_len = 4096;
  ifc.ifc_buf = buffer;

  if (ioctl(sockfd, SIOCGIFCONF, (char *)&ifc) < 0)
    err(1, "ioctl error");

  ifr = ifc.ifc_req;

  cplim = buffer + ifc.ifc_len;

  intf_count = 0;
  for (cp=buffer; cp < cplim; ) {
    ifr = (struct ifreq *)cp;
    if (ifr->ifr_addr.sa_family == AF_LINK) 
      intf_count++;
    cp += sizeof(ifr->ifr_name) + max(sizeof(ifr->ifr_addr), ifr->ifr_addr.sa_len);
  }

  name_cache = (char ***)malloc(intf_count * sizeof(char **));  

  i = -1;
  for (cp=buffer; cp < cplim; ) {
    ifr = (struct ifreq *)cp;
    if (ifr->ifr_addr.sa_family == AF_LINK) {
      struct sockaddr_dl *sdl = (struct sockaddr_dl *)&ifr->ifr_addr;
      i++;
      name_cache[i] = (char **)malloc(2*sizeof(char *));
      name_cache[i][0] = (char *)malloc(6);
      name_cache[i][1] = (char *)malloc(strlen(ifr->ifr_name) + 1);
      strcpy(name_cache[i][1], ifr->ifr_name);
      memcpy(name_cache[i][0], LLADDR(sdl), 6); 
    }
    cp += sizeof(ifr->ifr_name) + max(sizeof(ifr->ifr_addr), ifr->ifr_addr.sa_len);
  }

  close(sockfd);

  if(getifaddrs(&ifa) < 0)
    err(1, "Failed to fetch local ips");

  for(p = ifa; p != NULL; p = p->ifa_next) {
    if(p->ifa_addr->sa_family != AF_INET) continue; 
    ip_in = (struct sockaddr_in *)p-> ifa_addr; 
    for (i = 0; i<intf_count; i++) {
      if(strcmp(name_cache[i][1], p->ifa_name) != 0) continue;

      /*printf("found ip %x\n", ip_in->sin_addr.s_addr);*/
      tmp =  caml_alloc(2, 0);
      entry = caml_alloc(3, 0); 
      Store_field(entry, 0, caml_copy_string(name_cache[i][1]));
      mac = caml_alloc_string(6); 
      memcpy( String_val(mac), name_cache[i][0], 6);
      Store_field(entry, 1, mac);
      Store_field(entry, 2, Val_int(ntohl(ip_in->sin_addr.s_addr)));
      Store_field( tmp, 0, entry);  // head
      Store_field( tmp, 1, ret);  // tail
      ret = tmp;
    }
  }

  for(i = 0; i < intf_count; i++) {
    free(name_cache[i][0]);
    free(name_cache[i][1]);
  }
  free(name_cache);

  freeifaddrs(ifa);
  CAMLreturn(ret);
}

CAMLprim value 
ocaml_get_arp_table(value unit) {
  CAMLparam1(unit);
  CAMLlocal3( ret, tmp, entry );

  int mib[6];
  size_t needed;
  char *lim, *buf, *next;
  struct rt_msghdr *rtm;
  struct sockaddr_inarp *sin;
  struct sockaddr_dl *sdl;

  // Init return list
  ret = Val_emptylist;

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;
  mib[5] = RTF_LLINFO;

  if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
    err(1, "route-sysctl-estimate");
  if ((buf = malloc(needed)) == NULL)
    err(1, "malloc");
  if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
    err(1, "actual retrieval of routing table");

  lim = buf + needed;
  for (next = buf; next < lim; next += rtm->rtm_msglen) {
    rtm = (struct rt_msghdr *)next;
    sin = (struct sockaddr_inarp *)(rtm + 1);
    sdl = (struct sockaddr_dl *)(sin + 1);

    //PRINT ETHER (OR STATUS)
    entry = caml_alloc(2,0);
    // Store_field(entry, 0, Val_int(ntohl(dstin->sin_addr.s_addr)));
    Store_field(entry, 1, Val_int(ntohl(sin->sin_addr.s_addr)));
    /*printf("mac: %s, ip %x\n", ether_ntoa(LLADDR(sdl)), sin->sin_addr.s_addr);*/

    // store in list
    tmp =  caml_alloc(2, 0);
    Store_field( tmp, 0, entry);  // head
    Store_field( tmp, 1, ret);  // tail
    ret = tmp;

  }
  free(buf);
  CAMLreturn(ret);
}

#endif
