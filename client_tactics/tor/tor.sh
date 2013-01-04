#!/usr/bin/env bash 

DIR=$1

if [ ! -e $DIR/tmp/tor ]; then 
  mkdir $DIR/tmp/tor
fi

echo $DIR/tmp/tor/ | sed -e "s/\//\\\\\//g" > /tmp/dir
processed=`cat /tmp/dir`
sed -e "s/\\\$dir\\\$/$processed/g" $DIR/client_tactics/tor/tor.conf.sample > \
  $DIR/tmp/tor/tor.conf
rm /tmp/dir 

case `uname` in
  Linux )
    chown -R debian-tor:debian-tor $DIR/tmp/tor/
    echo User debian-tor >> $DIR/tmp/tor/tor.conf
    ;;
  esac


tor -f $DIR/tmp/tor/tor.conf

