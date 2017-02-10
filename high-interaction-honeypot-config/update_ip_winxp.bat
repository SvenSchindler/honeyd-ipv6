REM change the connection names below according to your needs
echo changing ip to %1
netsh interface ipv6 add address "LAN-Verbindung" %1
netsh interface ipv6 delete address "LAN-Verbindung" %2