#!/usr/bin/env bash 

DIR=$1

echo $DIR | sed -e "s/\//\\\\\//g" > /tmp/dir
processed=`cat /tmp/dir`
sed -e "s/\\\$dir\\\$/$processed/g" $DIR/client_tactics/tor/tor.conf.sample > \
  $DIR/tmp/tor.conf
rm /tmp/dir 

tor -f $DIR/tmp/tor.conf

