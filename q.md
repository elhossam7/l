Yes — this VM is currently in the wrong network:

```text
Current IP: 172.16.10.104
Current Gateway: 172.16.10.1
```

That means it is in **MGMT VLAN 10**, but according to your architecture, **WIN-TARGET-1 alice.dupont must be in CORP VLAN 20 with IP 172.16.20.30**. 

First, make sure the VM network adapter in VMware is connected to:

```text
CORP-PG
```

Not `MGMT-PG`, not `win01_PG`, not NAT.

Then inside the Windows VM, run PowerShell as Administrator:

```powershell
Get-NetAdapter
```

You will probably see the adapter name as `Ethernet0`. Then run:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 172.16.20.30 -PrefixLength 24 -DefaultGateway 172.16.20.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 172.16.20.10
```

If it says an IP already exists, remove the old DHCP/IP config first:

```powershell
Remove-NetIPAddress -InterfaceAlias "Ethernet0" -Confirm:$false
Remove-NetRoute -InterfaceAlias "Ethernet0" -Confirm:$false
```

Then run again:

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 172.16.20.30 -PrefixLength 24 -DefaultGateway 172.16.20.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet0" -ServerAddresses 172.16.20.10
```

Verify:

```powershell
ipconfig /all
ping 172.16.20.1
ping 172.16.20.10
ping 172.16.10.10
```

Expected result:

```text
IPv4 Address: 172.16.20.30
Subnet Mask: 255.255.255.0
Default Gateway: 172.16.20.1
DNS Server: 172.16.20.10
```

For Winlogbeat, keep Logstash as:

```yaml
output.logstash:
  hosts: ["172.16.10.10:5044"]
```

Because Windows targets in VLAN 20 should send Beats logs to ELK/Logstash in VLAN 10 on port `5044`. Your pfSense rules allow VLAN 20/30 to VLAN 10:5044 for Beats traffic. 
