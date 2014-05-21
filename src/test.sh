#!/bin/bash
ltest="192.168.3.125"
btest="172.16.0.121"

# Normal ping:
# sendip -p ipv4 -is $ltest -p icmp $btest -d 0xffff0001

# # Bad ICMP Type:
# sendip -p ipv4 -is $ltest -p icmp -ct 1 $btest -d 0xffff0001

# # Bad ICMP BAD Reply ID:
# sendip -p ipv4 -is $ltest -p icmp -ct 0 $btest -d r4

# # Bad ICMP code 
# sendip -p ipv4 -is $ltest -p icmp -ct 8 -cd 1 $btest -d 0xffff0001

# # Bad ICMP checksum:
# sendip -p ipv4 -is $ltest -p icmp -ct 8 -cc 0xffff $btest -d 0xffff0001

# # Evil bit:
# sendip -p ipv4 -is $ltest -ifr 1 -p icmp $btest -d 0xffff0001

# # Bad IP Version:
# sendip -p ipv4 -is $ltest -iv 0 -p icmp $btest -d 0xffff0001

# # Bad IP Protocol:
# sendip -p ipv4 -is $ltest -ip 2 -p icmp $btest -d 0xffff0001

# # Bad IP TTL:
# sendip -p ipv4 -is $ltest -it 0 -p icmp $btest -d 0xffff0001

# # Bad IP Min Header Length:
# sendip -p ipv4 -is $ltest -ih 4 -p icmp $btest -d 0xffff0001

#Bad IP Max Header Length:
#sendip -p ipv4 -is $ltest -ih 72 -p icmp $btest -d 0xffff0001

#Normal TCP
sendip -p ipv4 -is $ltest -p tcp -td 8080 -ts 0xfaaf $btest

# # Bad TCP Checksum:
# sendip -p ipv4 -is $ltest -p tcp -td 8080 -ts 0xfaaf -tc 0 $btest

# # Bad TCP Min Length:
# sendip -p ipv4 -is $ltest -p tcp -td 8080 -ts 0xfaaf -tt 4 $btest

# # FTP
# ftp -Aa -P <port> $btest:/randfile.tmp

# # TCP:
# with a webclient
# w3m $btest