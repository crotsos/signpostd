#!/usr/bin/env bash 
set -e

eval `opam config -env`

# ./openvpn_tactic.sh 10000 0 d2.signpo.st debian haris 10.10.0.2

port=$1
dev_id=$2
local_node=$3
remote_node=$4
remote_ip=$5
tmp_dir=$7
conf_dir=$6
ns_ip=${8}
ns_port=${9}

# create tmp folder
remote_host=$remote_node
local_host=$local_node
dst_dir=$tmp_dir/$remote_host/

if [ ! -e $dst_dir ]; then 
  mkdir $dst_dir
fi

openssl genrsa -out $dst_dir/vpn.pem 512

# self sign key
echo "self sign key...."
crypto-convert \
  -p $conf_dir/signpost.pem  \
  -s "C=UK,O=signpost,CN=$local_host," \
  -i "C=UK,O=signpost,CN=$local_host," \
  -d 30758400 \
  -S $ns_ip \
  -P $ns_port \
  SIGN \
  $conf_dir/signpost.pem \
  PEM_PRIV \
  $dst_dir/tmp.crt \
  PEM_CERT 

# sign the vpn key
echo "sign the vpn key $ns_ip:$ns_port...."
echo "crypto-convert \
  -p $conf_dir/signpost.pem  \
  -d 30758400 \
  -s \"C=UK,O=signpost,CN=vpn.$local_host,\" \
  -i \"C=UK,O=signpost,CN=$local_host,\" \
  -S $ns_ip \
  -P $ns_port \
  SIGN \
  $dst_dir/vpn.pem \
  PEM_PRIV \
  $dst_dir/vpn.crt \
  PEM_CERT "


crypto-convert \
  -p $conf_dir/signpost.pem  \
  -d 30758400 \
  -s "C=UK,O=signpost,CN=vpn.$local_host," \
  -i "C=UK,O=signpost,CN=$local_host," \
  -S $ns_ip \
  -P $ns_port \
  SIGN \
  $dst_dir/vpn.pem \
  PEM_PRIV \
  $dst_dir/vpn.crt \
  PEM_CERT 

# sign the remote domain certificate
echo "sign the remote domain certificate...."
crypto-convert \
  -p $conf_dir/signpost.pem  \
  -d 30758400 \
  -s "C=UK,O=signpost,CN=$remote_host," \
  -i "C=UK,O=signpost,CN=$local_host," \
  -S $ns_ip \
  -P $ns_port \
  SIGN \
  $remote_host \
  DNS_PUB \
  $dst_dir/allowed-$remote_host.crt \
  PEM_CERT 

cat $dst_dir/tmp.crt $dst_dir/allowed-*.crt > $dst_dir/ca.crt

tmp_dir=`echo $tmp_dir  | sed -e 's/\//\\\\\//g' `

cat $conf_dir/../client_tactics/openvpn/client.conf.template |\
   sed -e "s/\\\$port\\\$/$port/g"\
   -e "s/\\\$dev_id\\\$/$dev_id/g" \
   -e "s/\\\$domain\\\$/$remote_host/g" \
   -e "s/\\\$tmp_dir\\\$/$tmp_dir/g" \
   -e "s/\\\$ip\\\$/$remote_ip/g" > $dst_dir/client.conf

chmod a+x $dst_dir
chmod -R a+rw $dst_dir
