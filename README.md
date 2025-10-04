Im making a network assessment tool called ORCA. The idea is this, its an orchestrator and it manages the life cycle of the application: - Scan the hosts and their ports - Use against the findings a campaign ( a set of assessment tests, tls check, tls version check. mitm vulns, fuzzing , etc...) - get the results - gives back the results to the user The tool is intended for IoT protocols (MQTT, EtherCAT, CoAP, ... etc) but i would like it to be protocol agnostic. I would like the campaign's tests to be implemented as plugin style method (like dll or lib or grpc) but tell me what you think. The tool should be written in go (as later on it should support the docker sdk). Also i would like make the lifecycle to be made of this steps: - scanner - classifier (map services -> campaigns steps) - assessor (job executor , concurrency&timeouts) - reporter (aggregate findings write reports) - the campaigns should be in yaml - plugins via gRPC - results are nice in json Give me an architecture done using the clean architecture principle. The plugins are completely transparent to ORCA, ORCA gives only the target:host tuple if the plugins tags matches the one given by the classifier for that specific tuple. The cycle is done like this: - Scan -> gives host:port list - Classifier -> gives tags for each host:port - Runner -> run the plugins (for now one at the time) and saves results - Reporter -> gives back results

### Possible tests

#### 🔐 TLS / Crypto Plugins

- **Certificate Expiry Check**
  Parse server cert, report if it’s expired or expiring soon.
- **Weak Cipher Detection**
  Attempt handshake with known weak ciphers (RC4, 3DES).
- **Self-signed / Untrusted Cert Check**
  Verify if the cert is self-signed or missing CA.
- **Certificate Hostname Mismatch**
  Check CN/SAN vs target hostname.

---

#### 🌐 Protocol-Specific Plugins

##### MQTT

- **Anonymous Auth Check**
  Try connecting with no username/password.
- **Weak Default Creds**
  Test with common creds (`admin:admin`, `guest:guest`).
- **Unauth Publish/Subscribe**
  Verify if topics are open without authentication.

##### CoAP

- **Unauthenticated Access**
  Send a simple `GET`/`POST` and check if device responds.
- **DTLS Support Check**
  Verify whether CoAP supports DTLS (and which versions).

##### Modbus/TCP

- **Function Code Fuzzer**
  Send unsupported or invalid function codes.
- **Broadcast Storm Check**
  Detect if the device responds dangerously to broadcast queries.

##### EtherCAT / Industrial

- **Node Enumeration**
  Discover EtherCAT slaves and check vendor IDs.
- **Safety Over EtherCAT**
  Verify whether safety functions are exposed on unsecured links.

---

#### 🛰️ IoT / Embedded Weakness Plugins

- **Default Password Audit**
  Try logging into HTTP/FTP/Telnet/SSH with vendor defaults.
- **Open Debug Interface Detection**
  Probe for exposed JTAG-over-Ethernet, or debug protocols.
- **Unauth Firmware Download**
  Attempt to pull firmware without authentication.
- **Directory Traversal (HTTP)**
  Simple `../../` traversal check on embedded web servers.

---

#### 📡 General Network Service Plugins

- **Banner Grabber**
  Collect banners and versions, report outdated services.
- **HTTP Security Headers**
  Check for missing HSTS, CSP, X-Frame-Options, etc.
- **Anonymous FTP**
  Test if anonymous login is enabled.
- **Open Redis/Memcached Check**
  Detect if DB is exposed without auth.

---

#### 🧪 Fuzzing / Robustness Plugins

- **Simple Protocol Fuzzer**
  Send malformed packets and log whether device crashes/reboots.
- **Replay Attack Simulator**
  Record a legit request, replay it, and see if accepted.
- **Fragmentation / Oversized Packet Test**
  Test how IoT service reacts to weird packet fragmentation.

---

#### 🛡️ Hardening & Misconfig Checks

- **Open Management Ports**
  Detect if Telnet, SSH, Web admin are world-exposed.
- **SNMP Public Community**
  Try `public`/`private` community strings.
- **UPnP/SSDP Exposure**
  Probe for UPnP devices leaking details.
- **TFTP Service Check**
  Test if trivial file transfer service is exposed (common in IoT).
