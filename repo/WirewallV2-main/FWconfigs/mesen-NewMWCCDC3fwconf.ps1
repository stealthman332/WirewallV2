New-NetFirewallRule -DisplayName "CCDC-SMTP-25-TCP" -Direction Inbound -Protocol TCP -LocalPort 25 -Profile Domain,Public,Private
New-NetFirewallRule -DisplayName "Allow All Inbound from DC" -Direction Inbound -Action Allow -RemoteAddress 192.168.1.35
New-NetFirewallRule -DisplayName "Allow All Inbound from DC" -Direction Outbound -Action Allow -RemoteAddress 192.168.1.35