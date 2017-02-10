#!/bin/bash
#change the network interface names according to your needs
newAddr=$1
echo "changing ip address to $newAddr"
ifconfig vboxnet0 inet6 add $newAddr
echo "ip address changed"
