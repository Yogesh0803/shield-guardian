@echo off
netsh advfirewall firewall add rule name=GuardianShield_ee06b464-a17a-4cee-9f5e-06afca76a558 dir=out action=block remoteip=185.220.101.0/24,23.129.64.0/24 protocol=any & netsh advfirewall firewall add rule name=GuardianShield_ee06b464-a17a-4cee-9f5e-06afca76a558_in dir=in action=block remoteip=185.220.101.0/24,23.129.64.0/24 protocol=any
echo DONE > "E:\guardian-shield\tmp\gs_fw_done.txt"
