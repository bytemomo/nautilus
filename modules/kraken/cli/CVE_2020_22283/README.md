# CVE-2020-22283

- **Score**: 7.5
- **Description**:
  A buffer overflow vulnerability in the icmp6_send_response_with_addrs_and_netif()
  function of Free Software Foundation lwIP version git head allows malicious
  users to access sensitive information via a crafted ICMPv6 packet.

Probably affect **lwip** versions < 2.1.2
