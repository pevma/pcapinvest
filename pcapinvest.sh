#!/bin/bash

##
#
# Peter Manev (pevma)
# pmanev@oisf.net
#
# Ths script runs tcpdump filters against a provided pcap
# and displays the results.
# Further more the tcpdump filters below can be used to extract exactly 
# those packets that match.
#
# Exmple: 
# (HTTP TRACE)
# tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x54524143 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4520)' \
# -r pcap_file.pcap -w output_pcap.pcap
#
##
#
# Thanks to:
# Wirehark String-Matching Capture Filter Generator
# https://www.wireshark.org/tools/string-cf.html
# https://www.wireshark.org/tools/
#
##

pcap_file=$1
ARGS=1         # Script requires 1 arguments.
ERR_CODE=0     #defaulting to success return to the OS

echo -e "\n Supplied pcap file is:  $pcap_file \n";

  if [ $# -ne "$ARGS" ];
    then
      echo -e "\n USAGE: `basename $0` the script requires one argument - full path to pcap file."
      echo -e "\n Please supply a full path to pcap file."
      exit 1;
  fi

# We check if the pcap file is present
if [ ! -f "$pcap_file" ];then
  echo "The provided file $pcap_file NOT FOUND !!"
  exit 1;
fi



#echo "HTTP TOTAL (GET/POST/PUT/HEAD/OPTIONS/PROPFIND/TRACE/SEARCH/DELETE/CONNECT/PATCH) ->"
http_total=$(tcpdump -nn \
' (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:1] = 0x20) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48454144 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:1] = 0x20) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50555420) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x4f505449 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x4f4e5320) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50524f50 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x46494e44 && tcp[((tcp[12:1] & 0xf0) >> 2) + 8:1] = 0x20) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x54524143 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4520) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x53454152 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4348 && tcp[((tcp[12:1] & 0xf0) >> 2) + 6:1] = 0x20) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x44454c45 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x5445 && tcp[((tcp[12:1] & 0xf0) >> 2) + 6:1] = 0x20) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x434f4e4e && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x45435420) or (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50415443 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4820) ' \
-r ${pcap_file}  2> /dev/null | wc -l)
echo "${http_total} <- HTTP total requests"

#echo -e "\n HTTP GET ->"
http_get=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420)' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${http_get} <- HTTP GET"

#echo -e "\n HTTP POST ->"
http_post=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:1] = 0x20)' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${http_post} <- HTTP POST"

#echo -e "\nHTTP HEAD ->"
http_head=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48454144 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:1] = 0x20)' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${http_head} <- HTTP HEAD"

#echo -e "\nHTTP PUT ->"
http_put=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50555420)' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${http_put} <- HTTP PUT"

#echo -e "\nHTTP OPTIONS ->"
http_options=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x4f505449 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x4f4e5320)' -r ${pcap_file} 2> /dev/null | wc -l )
echo "${http_options} <- HTTP OPTIONS"

#echo -e "\nHTTP PROPFIND ->"
http_propfind=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50524f50 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x46494e44 && tcp[((tcp[12:1] & 0xf0) >> 2) + 8:1] = 0x20)' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${http_propfind} <- HTTP PROPFIND"

#echo -e "\nHTTP TRACE ->"
http_trace=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x54524143 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4520)' -r ${pcap_file} 2> /dev/null | wc -l )
echo "${http_trace} <- HTTP TRACE"

#echo -e "\nHTTP SEARCH ->"
http_search=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x53454152 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4348 && tcp[((tcp[12:1] & 0xf0) >> 2) + 6:1] = 0x20)' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${http_search} <- HTTP SEARCH"

#echo -e "\nHTTP DELETE ->"
http_delete=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x44454c45 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x5445 && tcp[((tcp[12:1] & 0xf0) >> 2) + 6:1] = 0x20)' -r ${pcap_file} 2> /dev/null | wc -l )
echo "${http_delete} <- HTTP DELETE"

#echo -e "\nHTTP CONNECT ->"
http_connect=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x434f4e4e && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:4] = 0x45435420)' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${http_connect} <- HTTP CONNECT"

#echo -e "\nHTTP PATCH ->"
http_patch=$(tcpdump -nn '(tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x50415443 && tcp[((tcp[12:1] & 0xf0) >> 2) + 4:2] = 0x4820)' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${http_patch} <- HTTP PATCH"

#echo -e "\nDNS UDP requests ->"
dns_udp_req=$(tcpdump -nn -i eth0 'udp[10] & 0x80 = 0 and port 53' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${dns_udp_req} <- DNS UDP requests"

#echo -e "\nDNS UDP answers ->"
dns_udp_ans=$(tcpdump -nn -i eth0 'udp[10] & 0x80 != 0 and port 53' -r ${pcap_file} 2> /dev/null | wc -l)
echo "${dns_udp_ans} <- DNS UDP answers"

#echo -e "\nIPv4 packets ->"
ipv4=$(tcpdump -nn ip -r ${pcap_file} 2> /dev/null | wc -l)
echo "${ipv4} <- IPv4 packets"

#echo -e "\nIPv6 packets ->"
ipv6=$(tcpdump -nn ip6 -r ${pcap_file} 2> /dev/null | wc -l)
echo "${ipv6} <- IPv6 packets"

#echo -e "\nUDP packets ->"
udp=$(tcpdump -nn udp -r ${pcap_file} 2> /dev/null | wc -l)
echo "${udp} <- UDP packets"

#echo -e "\nTCP packets ->"
tcp=$(tcpdump -nn tcp -r ${pcap_file} 2> /dev/null | wc -l)
echo "${tcp} <- TCP packets"

#echo -e "\nICMP packets ->"
icmp=$(tcpdump -nn icmp -r ${pcap_file} 2> /dev/null | wc -l)
echo "${icmp} <- ICMP packets"

#echo -e "\nARP packets ->"
arp=$(tcpdump -nn arp -r ${pcap_file} 2> /dev/null | wc -l)
echo "${arp} <- ARP packets"
