New-NetFirewallRule -DisplayName "CCDC-HTTP-80-TCP" -Direction Inbound -Protocol TCP -LocalPort 80 -Profile Domain,Public,Private
New-NetFirewallRule -DisplayName "CCDC-HTTPS-443-TCP" -Direction Inbound -Protocol TCP -LocalPort 443 -Profile Domain,Public,Private
New-NetFirewallRule -DisplayName "CCDC-SMB-445-TCP" -Direction Inbound -Protocol TCP -LocalPort 445 -Profile Domain,Public,Private
New-NetFirewallRule -DisplayName "Allow All Inbound from DC" -Direction Inbound -Action Allow -RemoteAddress 192.168.1.35
New-NetFirewallRule -DisplayName "Allow All Inbound from DC" -Direction Outbound -Action Allow -RemoteAddress 192.168.1.35
