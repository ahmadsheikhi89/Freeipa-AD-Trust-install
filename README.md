---

✨ What this repo gives you

A repeatable, production-style recipe to integrate FreeIPA (ipa.local) with Microsoft Active Directory (test.local).

You’ll be able to:

✅ Join Linux hosts to FreeIPA and let AD users log in with HBAC/SUDO policies enforced by IPA.

✅ Secure the FreeIPA Web UI behind Keycloak (OIDC) while Keycloak pulls users/groups from AD (LDAP).

✅ Keep name resolution clean with conditional forwarders and/or delegation between ipa.local and test.local.

✅ Add a cross-forest AD Trust so Linux systems talk only to IPA, while authentication flows through to AD.


Choose one or both integration paths:

1. FreeIPA → Keycloak → Active Directory (OIDC for UI; AD via LDAP)


2. FreeIPA → Domain Trust → Active Directory (AD users on Linux via trust)



> 🔐 Replace sample IPs, passwords, and tokens with your own. Never commit real secrets.




---

🖼️ Architecture banner (GitHub-native Mermaid)

%%{init: {'theme': 'neutral', 'flowchart': {'curve': 'basis'}}}%%
flowchart LR
  classDef banner fill:#f5f7fb,stroke:#d0d7de,stroke-width:1px,color:#0b1221
  classDef box fill:#ffffff,stroke:#1f6feb,stroke-width:1px,color:#0b1221
  classDef svc fill:#f0fff4,stroke:#1a7f37,stroke-width:1px,color:#0b1221
  classDef auth fill:#fff7ed,stroke:#bf8700,stroke-width:1px,color:#0b1221
  classDef dns fill:#eef6ff,stroke:#0969da,stroke-width:1px,color:#0b1221

  subgraph BANNER["FreeIPA ↔ Microsoft AD Integration (Overview)"]
  class BANNER banner

  AD[(Active Directory\n(test.local))]:::box
  DC1[[AD DC / DNS\n10.20.20.11]]:::dns
  DC2[[AD DC / DNS\n10.20.20.12]]:::dns

  subgraph IPA["FreeIPA Realm (ipa.local)"]
    class IPA banner
    IPA1[(IPA Master\n10.10.10.11)]:::box
    IPA2[(IPA Replica\n10.10.10.12)]:::box
    HBAC{{HBAC / SUDO}}:::svc
  end

  KC[(Keycloak OIDC\n10.10.10.14)]:::auth
  APACHE[(Apache on IPA UI\nmod_auth_openidc)]:::auth
  LNX[(Linux Clients\nSSSD)]:::svc

  AD --- DC1
  AD --- DC2
  DC1 <-- DNS forwarders / delegation --> IPA1
  IPA1 <-- replication --> IPA2
  LNX ---|Kerberos/LDAP| IPA1
  LNX ---|Failover| IPA2
  HBAC --- LNX
  APACHE ---|OIDC| KC
  KC ---|LDAP Federation| AD
  APACHE ---|protects| IPA1
  IPA1 -. Cross-forest Trust .-> AD

  end

(راهنمای رسمی Mermaid برای رندر در README: )


---

🔐 FreeIPA install with DNS + Microsoft AD integration

Two supported paths (same scenario, organized clearly):

1. FreeIPA → Keycloak → Active Directory (OIDC for the FreeIPA UI; AD via LDAP)


2. FreeIPA → Domain Trust → Active Directory (use AD users on Linux with HBAC/Sudo)



> 💡 Notes
• Replace IPs, passwords, and tokens with your own. Never commit real secrets.
• Correct file name is /etc/resolv.conf (not resolve.conf).
• For AD trust, promote at least one IPA server as an AD trust controller.




---

📦 0) Packages

# Server-side
dnf install -y freeipa-server freeipa-server-dns freeipa-client ipa-healthcheck \
  freeipa-server-trust-ad samba samba-client oddjob oddjob-mkhomedir

# Client/aux
dnf install -y ipa-client sssd samba-client oddjob oddjob-mkhomedir adcli realmd


---

🧹 1) Uninstall / Cleanup (when re-running)

ipa-server-install --uninstall -U || true
ipa-replica-install --uninstall -U || true
ipa-client-install  --uninstall -U || true

systemctl stop sssd || true
rm -rf /etc/ipa /var/lib/ipa /var/log/ipa* /var/lib/sss/db/* /var/lib/sss/mc/* /var/lib/ipa/sysrestore/* 2>/dev/null || true
rm -f  /etc/krb5.keytab /etc/krb5.conf.bak 2>/dev/null || true


---

🌐 2) Network & DNS

2.1 Set DNS on the NIC

nmcli connection modify ens33 ipv4.dns "10.10.10.11,10.10.10.12"
nmcli connection down ens33 && nmcli connection up ens33

2.2 Hostname & /etc/hosts

hostnamectl set-hostname ipa-mas.ipa.test.local

# /etc/hosts (variant 1 - FQDNs inside ipa.test.local)
127.0.0.1   localhost
::1         localhost

# IPA Servers (ipa.test.local)
10.10.10.11 ipa-mas.ipa.test.local  ipa-mas
10.10.10.12 ipa-rep.ipa.test.local  ipa-rep
10.10.10.13 log-srv.ipa.test.local  log-srv

# /etc/hosts (variant 2 - separate IPA vs AD)
# FreeIPA Hosts (ipa.local)
10.10.10.11  ipa-mas.ipa.local   ipa-mas
10.10.10.12  ipa-rep.ipa.local   ipa-rep
# Active Directory Hosts (test.local)
10.20.20.11  dc1.test.local      dc1
10.20.20.12  dc2.test.local      dc2

# /etc/hosts (variant 3 - full sample profile)
# IPA
10.10.10.11 ipa-master.ipa.local   ipa-master
10.10.10.12 ipa-replica.ipa.local  ipa-replica
10.10.10.14 keycloak.ipa.local     keycloak
10.10.10.13 log-srv.ipa.local      log-srv
10.10.10.15 linuxclient.ipa.local  linuxclient
# AD (test.local)
10.20.20.11 dc1.test.local         dc1
10.20.20.12 dc2.test.local         dc2
10.20.20.31 win-client.test.local  win-client

2.3 /etc/resolv.conf (DNS list & optional lock)

# /etc/resolv.conf
# IPA DNS
nameserver 10.10.10.11
nameserver 10.10.10.12
# AD DNS
nameserver 10.20.20.11
nameserver 10.20.20.12

# Optional lock/unlock (use with care)
sudo chattr +i /etc/resolv.conf
lsattr /etc/resolv.conf
sudo chattr -i /etc/resolv.conf

> 🔧 If NetworkManager manages DNS, prefer setting DNS via nmcli rather than locking the file.




---

🔥 3) Firewall

firewall-cmd --permanent --add-port={80/tcp,443/tcp,389/tcp,636/tcp,88/tcp,88/udp,464/tcp,464/udp,53/tcp,53/udp}
firewall-cmd --reload
firewall-cmd --list-ports

firewall-cmd --permanent \
  --add-service=http --add-service=https --add-service=ldap --add-service=ldaps \
  --add-service=kerberos --add-service=kpasswd \
  --add-service=freeipa-trust --add-service=freeipa-replication

firewall-cmd --reload
firewall-cmd --list-services


---

🖥️ 4) Active Directory (Windows Server) – setup

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment
$safeModePassword = Read-Host -AsSecureString "<STRONG_PASSWORD>"

Install-ADDSForest `
  -CreateDnsDelegation:$false `
  -DatabasePath "C:\Windows\NTDS" `
  -DomainName "test.local" `
  -DomainNetbiosName "TEST" `
  -InstallDns:$true `
  -LogPath "C:\Windows\NTDS" `
  -NoRebootOnCompletion:$false `
  -SysvolPath "C:\Windows\SYSVOL" `
  -SafeModeAdministratorPassword $safeModePassword `
  -Force


---

☁️ 5) Keycloak (for SSO path)

5.1 Docker Compose

services:
  my-keycloak:
    image: quay.io/keycloak/keycloak:24.0
    environment:
      KC_HOSTNAME: localhost
      KC_HOSTNAME_PORT: 7080
      KC_HOSTNAME_STRICT_BACKCHANNEL: "true"
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: <STRONG_PASSWORD>
      KC_HEALTH_ENABLED: "true"
      KC_LOG_LEVEL: info
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7080/health/ready"]
      interval: 15s
      timeout: 2s
      retries: 15
    command: ["start-dev", "--http-port", "7080", "--https-port", "7443"]
    ports:
      - "7080:7080"
      - "7443:7443"
    networks: [local_network]
networks:
  local_network:
    driver: bridge

5.2 LDAP basics (AD as user store)

Connection: ldap://10.20.20.11:389

Bind Type: simple

Bind DN: CN=keycloak,CN=users,DC=test,DC=local

Users DN: DC=test,DC=local

Username attr: userPrincipalName

RDN attr: cn

Scope: subtree

Pagination / Import users / Sync registrations: ON.



---

🔐 6) Apache OIDC (protect FreeIPA UI via Keycloak)

sudo dnf install -y mod_auth_openidc jq
sudo nano /etc/httpd/conf.d/05-oidc.conf

OIDCProviderMetadataURL http://keycloak.ipa.local:7080/realms/master/.well-known/openid-configuration

OIDCClientID        freeipa
OIDCClientSecret    <OIDC_CLIENT_SECRET>
OIDCRedirectURI     https://ipa-master.ipa.local/oidc_callback
OIDCCryptoPassphrase <LONG_RANDOM_VALUE>

OIDCScope               "openid profile email"
OIDCRemoteUserClaim     preferred_username
OIDCOAuthAcceptTokenAs  header
OIDCClaimPrefix         ""
OIDCPassIDTokenAs       serialized
OIDCPassUserInfoAs      claims

OIDCSessionType             server-cache
OIDCSessionInactivityTimeout 3600
OIDCStripCookies            On

LogLevel auth_openidc:warn

<Location /oidc_callback>
  AuthType openid-connect
  Require valid-user
</Location>

<Location "/ipa/ui">
  AuthType openid-connect
  Require valid-user
  RequestHeader set X-Remote-User %{REMOTE_USER}s
</Location>

<Location "/ipa/json">
  AuthType openid-connect
  Require valid-user
  RequestHeader set X-Remote-User %{REMOTE_USER}s
</Location>

sudo systemctl restart httpd
sudo tail -n 50 -f /var/log/httpd/error_log


---

🧭 7) DNS Delegation (if used)

On AD DNS (test.local), create New Delegation for ipa pointing NS to:

ipa-mas.ipa.test.local. → A: 10.10.10.11

ipa-rep.ipa.test.local. → A: 10.10.10.12
(Also create Glue A records.)



---

🏗️ 8) Install FreeIPA Master (with internal DNS)

With forwarders

ipa-server-install --unattended \
  --realm IPA.LOCAL \
  --domain ipa.local \
  --hostname ipa-mas.ipa.local \
  --ds-password '<DM_PASSWORD>' \
  --admin-password '<IPA_ADMIN_PASSWORD>' \
  --setup-dns \
  --forwarder=10.20.20.11 \
  --forwarder=10.20.20.12 \
  --no-ntp

ipactl status
ipa-healthcheck

Without forwarding

ipa-server-install --unattended \
  --realm IPA.LOCAL \
  --domain ipa.local \
  --hostname ipa-master.ipa.local \
  --ds-password '<DM_PASSWORD>' \
  --admin-password '<IPA_ADMIN_PASSWORD>' \
  --setup-dns \
  --no-forwarders \
  --ntp


---

🔁 9) Conditional Forwarders

On FreeIPA → forward AD (test.local)

ipa dnsforwardzone-add test.local \
  --forwarder=10.20.20.11 \
  --forwarder=10.20.20.12 \
  --forward-policy=only

Show & test:

ipa dnsforwardzone-show test.local
dig @127.0.0.1 +short _ldap._tcp.test.local SRV
dig @127.0.0.1 +short dc1.test.local

(مستندات Forward Zones و Forward Policy در FreeIPA/IdM: )

On AD → forward IPA (ipa.local)

Add-DnsServerConditionalForwarderZone -Name "ipa.local" -MasterServers "10.10.10.11","10.10.10.12" -ReplicationScope "Forest"

nslookup ipa-mas.ipa.local
nslookup ipa-rep.ipa.local
Get-DnsServerConditionalForwarderZone -Name "ipa.local" | fl *
Resolve-DnsName ipa-mas.ipa.local
Resolve-DnsName _ldap._tcp.ipa.local -Type SRV


---

🧬 10) Replica install (on ipa-rep)

ipa-client-install -U \
  --domain=ipa.local \
  --server=ipa-mas.ipa.local \
  --realm=IPA.LOCAL \
  --mkhomedir -N \
  --principal=admin \
  --password '<IPA_ADMIN_PASSWORD>'

ipa-replica-install -U \
  --hostname ipa-replica.ipa.local \
  --setup-dns \
  --no-ntp \
  --no-forwarders \
  --principal=admin \
  --admin-password '<IPA_ADMIN_PASSWORD>'

Validate:

kinit admin
ipactl status
ipa-healthcheck

ipa trust-find
ipa trust-fetch-domain
systemctl restart sssd
sss_cache -E

SRV tests (test.local):

dig +short _ldap._tcp.test.local SRV
dig +short _kerberos._tcp.test.local SRV
host -t A dc1.test.local

Topology:

ipa topologysegment-find domain
ipa topologysegment-find ca
ipa trust-fetch-domains


---

🧪 11) DNS & HA sanity tests

# A records
dig +short ipa-master.ipa.local A
dig +short ipa-rep.ipa.test.local A

# SRV (after replica, should list both servers)
dig +short _ldap._tcp.ipa.test.local SRV @127.0.0.1
dig +short _kerberos._tcp.ipa.test.local SRV @127.0.0.1

From a machine using AD DNS:

nslookup ipa-mas.ipa.test.local 10.20.20.11
nslookup -type=NS ipa.test.local 10.20.20.11


---

🛡️ 12) Build AD Trust (second path)

Enable trust components & create trust:

dnf install -y freeipa-server-trust-ad samba samba-winbind samba-winbind-clients
systemctl enable --now smb winbind sssd
ipa-adtrust-install -U --netbios-name=IPA --enable-compat --add-sids
firewall-cmd --add-service=freeipa-trust --permanent && firewall-cmd --reload

ipa trust-add --type=ad test.local --trust-secret
# OR:
ipa trust-add --type=ad test.local --admin Administrator --password

Refresh & verify:

kdestroy
kinit admin
systemctl restart smb winbind sssd
ipa trust-fetch-domains test.local
wbinfo -m
wbinfo -D TEST
wbinfo --online-status


---

🧷 13) HBAC & SUDO (AD groups)

ipa group-add ad-linux-sudo-ext --external
ipa group-add-member ad-linux-sudo-ext --external 'S-1-5-21-1339670884-2023611603-4245298173-1234'

ipa group-add linux-sudo --gid=55000 --desc="POSIX sudo group"
ipa group-add-member linux-sudo --groups=ad-linux-sudo-ext

ipa sudorule-add sudo_linux_sudo --hostcat=all --runasusercat=all
ipa sudorule-add-user sudo_linux_sudo --groups=linux-sudo
ipa sudorule-add-allow-command sudo_linux_sudo --sudocmds=ALL
ipa sudorule-enable sudo_linux_sudo

ipa hbacrule-add allow_ssh_linux_sudo --servicecat=all
ipa hbacrule-add-user allow_ssh_linux_sudo --groups=linux-sudo
ipa hbacrule-add-service allow_ssh_linux_sudo --hbacsvcs=sshd
ipa hbacrule-add-host allow_ssh_linux_sudo --hostcat=all
ipa hbacrule-enable allow_ssh_linux_sudo

Client-side sudo via SSSD:

sudo sed -i 's/^services = .*/services = nss, pam, ssh, sudo/' /etc/sssd/sssd.conf
sudo awk 'BEGIN{d=0}/^sudoers:/{print "sudoers: files sss";d=1;next}{print}END{if(!d)print "sudoers: files sss"}' \
  /etc/nsswitch.conf | sudo tee /etc/nsswitch.conf >/dev/null
sudo sss_cache -E
sudo systemctl restart sssd


---

🔍 14) Useful queries & checks

ipa group-show linux-admin --all | egrep 'Group name|Member groups|GID'
ipa group-show ad-linux-admin-ext1 --all | grep -E 'External member'

ipa sudorule-disable sudo_linux_sudo 2>/dev/null || true
ipa sudorule-del     sudo_linux_sudo 2>/dev/null || true
ipa sudorule-add sudo_linux_admin --hostcat=all --runasusercat=all 2>/dev/null || true
ipa sudorule-add-user sudo_linux_admin --groups=linux-admin
ipa sudorule-add-allow-command sudo_linux_admin --sudocmds=ALL
ipa sudorule-enable sudo_linux_admin
ipa sudorule-show sudo_linux_admin --all | egrep -i 'Enabled|User Groups|Host|Command'

HBAC admin rule:

ipa hbacrule-add allow_ssh_admin --servicecat=all 2>/dev/null || true
ipa hbacrule-add-user allow_ssh_admin --groups=linux-admin
ipa hbacrule-add-service allow_ssh_admin --hbacsvcs=sshd
ipa hbacrule-add-host allow_ssh_admin --hostcat=all
ipa hbacrule-enable allow_ssh_admin
ipa hbacrule-disable allow_all 2>/dev/null || true


---

🧪 15) Client tests

grep ^services /etc/sssd/sssd.conf
grep ^sudoers  /etc/nsswitch.conf

sssctl user-show 'TEST\a.sheikhi'
id 'TEST\a.sheikhi'
sudo -l -U 'TEST\a.sheikhi'

sudo -l -U 'TEST\m.hadadian'   # expect no sudo if not in group


---

🧰 16) Logs & service restarts

journalctl -u ipa-adtrust-install.service -n 200 --no-pager
systemctl restart krb5kdc sssd httpd


---

🔎 17) Common DNS lookups

# IPA SRV
dig +short _ldap._tcp.ipa.local SRV
dig +short _kerberos._udp.ipa.local SRV

# AD from IPA (test.local)
dig +short dc1.test.local @127.0.0.1

# Delegation from AD view
dig +short NS ipa.test.local @10.20.20.11


---

References

FreeIPA DNS forward zones & forwarding (and policies). 

DNS troubleshooting (forward policy hints). 

Mermaid in GitHub README. 



---