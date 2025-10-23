# FreeIPA install with DNS + Microsoft AD integration

Two supported paths (same scenario, just organized clearly):

1. **FreeIPA → Keycloak → Active Directory** (OIDC for the FreeIPA UI; AD via LDAP)
2. **FreeIPA → Domain Trust → Active Directory** (use AD users on Linux with HBAC/Sudo)

> Notes:
> • Replace IPs, passwords, and tokens with your own. Never commit real secrets.
> • File name is `/etc/resolv.conf` (not `resolve.conf`). ([man7.org][1])
> • For AD trust, IPA realm must match its domain name. ([Debian Manpages][2])

---

## 0) Packages

```bash
# Server-side
dnf install -y freeipa-server freeipa-server-dns freeipa-client ipa-healthcheck \
  freeipa-server-trust-ad samba samba-client oddjob oddjob-mkhomedir

# Client/aux
dnf install -y ipa-client sssd samba-client oddjob oddjob-mkhomedir adcli realmd
```

---

## 1) Uninstall/Cleanup (when re-running)

```bash
ipa-server-install --uninstall -U || true
ipa-replica-install --uninstall -U || true
ipa-client-install  --uninstall -U || true

systemctl stop sssd || true
rm -rf /etc/ipa /var/lib/ipa /var/log/ipa* /var/lib/sss/db/* /var/lib/sss/mc/* /var/lib/ipa/sysrestore/* 2>/dev/null || true
rm -f  /etc/krb5.keytab /etc/krb5.conf.bak 2>/dev/null || true
```

---

## 2) Network & DNS

### 2.1 Set DNS on the NIC

```bash
nmcli connection modify ens33 ipv4.dns "192.168.126.51,192.168.150.55"
nmcli connection down ens33 && nmcli connection up ens33
```

### 2.2 Hostname & `/etc/hosts`

```bash
hostnamectl set-hostname ipa-mas.ipa.itgroup.org

# /etc/hosts (variant 1)
127.0.0.1   localhost
::1         localhost
192.168.1.150 ipa-mas.ipa.itgroup.org ipa-mas
192.168.1.151 ipa-rep.ipa.itgroup.org ipa-rep
192.168.1.152 log-srv.ipa.itgroup.org log-srv

# /etc/hosts (variant 2)
# FreeIPA
192.168.5.40  ipa-mas.ipa.local  ipa-mas
192.168.5.41  ipa-rep.ipa.local  ipa-rep
# AD
192.168.5.1   DC.matiran.local   DC
192.168.5.2   ADDC.matiran.local ADDC

# /etc/hosts (variant 3)
# IPA
192.168.126.51 ipa-master.ipa.local  ipa-master
192.168.126.52 ipa-replica.ipa.local ipa-replica
192.168.126.57 keycloak.ipa.local    keycloak
192.168.126.53 log-srv.ipa.local     log-srv
192.168.126.54 linuxclient.ipa.local linuxclient
# AD
192.168.126.55 dc1.dev.local         dc1
192.168.126.56 win-client.dev.local  win-client
# Nexus
192.168.11.100 nexus.itgroup.org
```

### 2.3 `/etc/resolv.conf` (DNS list & optional lock)

```bash
# /etc/resolv.conf
# IPA DNS
nameserver 192.168.5.40
nameserver 192.168.5.41
# AD DNS
nameserver 192.168.5.1
nameserver 192.168.5.2

# Optional lock/unlock (use with care)
sudo chattr +i /etc/resolv.conf
lsattr /etc/resolv.conf
sudo chattr -i /etc/resolv.conf
```

> If NetworkManager manages DNS, prefer setting DNS via `nmcli` rather than locking the file. ([Red Hat Docs][3])

---

## 3) Firewall

```bash
firewall-cmd --permanent --add-port={80/tcp,443/tcp,389/tcp,636/tcp,88/tcp,88/udp,464/tcp,464/udp,53/tcp,53/udp}
firewall-cmd --reload
firewall-cmd --list-ports

firewall-cmd --permanent \
  --add-service=http --add-service=https --add-service=ldap --add-service=ldaps \
  --add-service=kerberos --add-service=kpasswd \
  --add-service=freeipa-trust --add-service=freeipa-replication

firewall-cmd --reload
firewall-cmd --list-services
```

---

## 4) Active Directory (Windows Server) – setup

```powershell
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment
$safeModePassword = Read-Host -AsSecureString "Abcd12345"

Install-ADDSForest `
  -CreateDnsDelegation:$false `
  -DatabasePath "C:\Windows\NTDS" `
  -DomainName "dev.local" `
  -DomainNetbiosName "DEV" `
  -InstallDns:$true `
  -LogPath "C:\Windows\NTDS" `
  -NoRebootOnCompletion:$false `
  -SysvolPath "C:\Windows\SYSVOL" `
  -SafeModeAdministratorPassword $safeModePassword `
  -Force
```

---

## 5) Keycloak (for SSO path)

### 5.1 Docker Compose

```yaml
services:
  my-keycloak:
    image: quay.io/keycloak/keycloak:24.0
    environment:
      KC_HOSTNAME: localhost
      KC_HOSTNAME_PORT: 7080
      KC_HOSTNAME_STRICT_BACKCHANNEL: "true"
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
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
```

### 5.2 LDAP basics (AD as user store)

* Connection: `ldap://192.168.126.55:389`
* Bind Type: **simple**
* Bind DN: `CN=keycloak,CN=users,DC=dev,DC=local`
* Users DN: `DC=dev,DC=local`
* Username attr: `userPrincipalName`
* RDN attr: `cn`
* Scope: `subtree`
* Pagination / Import users / Sync registrations: **ON**

### 5.3 Mappers (examples)

* `group-ldap-mapper`

  * LDAP Groups DN: `DC=dev,DC=local`
  * Group Name attr: `cn`
  * Membership attr: `member` (Type = DN)
  * User LDAP filter: `(&(ObjectCategory=Person)(ObjectClass=User)(!(isCriticalSystemObject=TRUE)))`
  * Mode: `Read_Only`

---

## 6) Apache OIDC (FreeIPA UI protected by Keycloak)

> Uses **mod_auth_openidc** on Apache (official module). ([GitHub][4])

```bash
sudo dnf install -y mod_auth_openidc jq
sudo nano /etc/httpd/conf.d/05-oidc.conf
```

Put this in `05-oidc.conf` (client secret redacted):

```apache
OIDCProviderMetadataURL http://keycloak.ipa.local:7080/realms/master/.well-known/openid-configuration

OIDCClientID        freeipa
OIDCClientSecret    <REDACTED_CLIENT_SECRET>
OIDCRedirectURI     https://ipa-master.ipa.local/oidc_callback
OIDCCryptoPassphrase change_this_to_a_long_random_string

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
```

Restart & tail:

```bash
sudo systemctl restart httpd
sudo tail -n 50 -f /var/log/httpd/error_log
```

Optional token test (dev only):

```bash
curl -d "client_id=admin-cli" -d "username=admin" -d "password=YourAdminPassword" \
     -d "grant_type=password" \
     "http://localhost:7080/realms/master/protocol/openid-connect/token"
```

---

## 7) DNS Delegation (if used)

On the **AD** DNS (zone `itgroup.org`) create **New Delegation** for `ipa` pointing NS to:

* `ipa-mas.ipa.itgroup.org.` → A: `192.168.1.150`
* `ipa-rep.ipa.itgroup.org.` → A: `192.168.1.151`
  (Glue A records too.)

---

## 8) Install FreeIPA Master (with internal DNS)

**With forwarders**

```bash
ipa-server-install --unattended \
  --realm IPA.LOCAL \
  --domain ipa.local \
  --hostname ipa-mas.ipa.local \
  --ds-password 'Abcd12345' \
  --admin-password 'Abcd12345' \
  --setup-dns \
  --forwarder=192.168.5.1 \
  --forwarder=192.168.5.2 \
  --no-ntp
```

**Without forwarding**

```bash
ipa-server-install --unattended \
  --realm IPA.LOCAL \
  --domain ipa.local \
  --hostname ipa-master.ipa.local \
  --ds-password 'Abcd12345' \
  --admin-password 'Abcd12345' \
  --setup-dns \
  --no-forwarders \
  --ntp
```

**Alt profile**

```bash
ipa-server-install --unattended \
  --realm IPA.ITGROUP.ORG \
  --domain ipa.itgroup.org \
  --hostname ipa-mas.ipa.itgroup.org \
  --ds-password 'Abcd12345' \
  --admin-password 'Abcd12345' \
  --no-ntp
```

Post-check:

```bash
ipactl status
ipa-healthcheck
```

---

## 9) Conditional Forwarders

**On FreeIPA → forward AD**

```bash
ipa dnsforwardzone-add matiran.local \
  --forwarder=192.168.5.1 \
  --forwarder=192.168.5.2 \
  --forward-policy=only
```

Show & test:

```bash
ipa dnsforwardzone-show matiran.local
dig @127.0.0.1 +short _ldap._tcp.matiran.local SRV
dig @127.0.0.1 +short DC.matiran.local
```

(Forward zones in FreeIPA.) ([freeipa.org][5])

**On AD → forward IPA**

```powershell
Add-DnsServerConditionalForwarderZone -Name "ipa.local" -MasterServers "192.168.5.40","192.168.5.41" -ReplicationScope "Forest"

nslookup ipa-mas.ipa.local
nslookup ipa-rep.ipa.local
Get-DnsServerConditionalForwarderZone -Name "ipa.local" | fl *
Resolve-DnsName ipa-mas.ipa.local
Resolve-DnsName _ldap._tcp.ipa.local -Type SRV
```

---

## 10) Replica install (on `ipa-rep`)

Join as client (NTP untouched):

```bash
ipa-client-install -U \
  --domain=ipa.local \
  --server=ipa-mas.ipa.local \
  --realm=IPA.LOCAL \
  --mkhomedir -N \
  --principal=admin \
  --password 'Abcd12345'
```

Promote to replica + DNS:

```bash
ipa-replica-install -U \
  --hostname ipa-replica.ipa.local \
  --setup-dns \
  --no-ntp \
  --no-forwarders \
  --principal=admin \
  --admin-password 'Abcd12345'
```

Validate:

```bash
kinit admin
ipactl status
ipa-healthcheck

ipa trust-find
ipa trust-fetch-domain
systemctl restart sssd
sss_cache -E
```

SRV tests:

```bash
dig +short _ldap._tcp.dev.local SRV
dig +short _kerberos._tcp.dev.local SRV
host -t A dc1.dev.local
```

Topology:

```bash
ipa topologysegment-find domain
ipa topologysegment-find ca
ipa trust-fetch-domains
```

---

## 11) DNS/HA sanity tests

```bash
# A records
dig +short ipa-master.ipa.local A
dig +short ipa-rep.ipa.itgroup.org A

# SRV (after replica, should list both servers)
dig +short _ldap._tcp.ipa.itgroup.org SRV @127.0.0.1
dig +short _kerberos._tcp.ipa.itgroup.org SRV @127.0.0.1
```

From a machine using **AD** DNS:

```powershell
nslookup ipa-mas.ipa.itgroup.org IP_DC1
nslookup -type=NS ipa.itgroup.org IP_DC1
```

---

## 12) Build **AD Trust** (second path)

> Run on the IPA trust controller node. ([freeipa.org][6])

Enable trust components:

```bash
dnf install -y freeipa-server-trust-ad samba samba-winbind samba-winbind-clients
systemctl enable --now smb winbind sssd
ipa-adtrust-install -U --netbios-name=IPA --enable-compat --add-sids
firewall-cmd --add-service=freeipa-trust --permanent && firewall-cmd --reload
```

Create trust (choose one):

```bash
ipa trust-add --type=ad dev.local --trust-secret
# or:
ipa trust-add --type=ad dev.local --admin administrator --password
```

Refresh & verify:

```bash
kdestroy
kinit admin
systemctl restart smb winbind sssd
ipa trust-fetch-domains dev.local
wbinfo -m
wbinfo -D DEV
wbinfo --online-status
```

> AD trust setup references. ([freeipa.org][7])

---

## 13) HBAC & SUDO (AD groups)

Create external & POSIX proxy group; grant sudo & SSH:

```bash
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
```

Client-side sudo via SSSD:

```bash
sudo sed -i 's/^services = .*/services = nss, pam, ssh, sudo/' /etc/sssd/sssd.conf
sudo awk 'BEGIN{done=0} /^sudoers:/{print "sudoers: files sss"; done=1; next} {print} END{if(!done)print "sudoers: files sss"}' /etc/nsswitch.conf | sudo tee /etc/nsswitch.conf >/dev/null
sudo sss_cache -E
sudo systemctl restart sssd
```

---

## 14) Useful queries & checks

```bash
ipa group-show linux-admin --all | egrep 'Group name|Member groups|GID'
ipa group-show ad-linux-admin-ext1 --all | grep -E 'External member'

# Optional new admin rule
ipa sudorule-disable sudo_linux_sudo 2>/dev/null || true
ipa sudorule-del     sudo_linux_sudo 2>/dev/null || true
ipa sudorule-add sudo_linux_admin --hostcat=all --runasusercat=all 2>/dev/null || true
ipa sudorule-add-user sudo_linux_admin --groups=linux-admin
ipa sudorule-add-allow-command sudo_linux_admin --sudocmds=ALL
ipa sudorule-enable sudo_linux_admin
ipa sudorule-show sudo_linux_admin --all | egrep -i 'Enabled|User Groups|Host|Command'
```

HBAC admin rule:

```bash
ipa hbacrule-add allow_ssh_admin --servicecat=all 2>/dev/null || true
ipa hbacrule-add-user allow_ssh_admin --groups=linux-admin
ipa hbacrule-add-service allow_ssh_admin --hbacsvcs=sshd
ipa hbacrule-add-host allow_ssh_admin --hostcat=all
ipa hbacrule-enable allow_ssh_admin
ipa hbacrule-disable allow_all 2>/dev/null || true
```

---

## 15) Client tests

```bash
grep ^services /etc/sssd/sssd.conf
grep ^sudoers  /etc/nsswitch.conf

sssctl user-show 'MATIRAN\a.sheikhi'
id 'MATIRAN\a.sheikhi'
sudo -l -U 'MATIRAN\a.sheikhi'

sudo -l -U 'MATIRAN\m.hadadian'   # expect no sudo if not in group
```

Example outputs (as in your test):

```
getent group linux-admin
linux-admin:*:55000:m.feizabadi@matiran.local,a.beryani@matiran.local,a.sheikhi@matiran.local

User a.sheikhi@matiran.local may run the following commands on prometheus-srv:
(ALL : ALL) ALL
```

---

## 16) Logs & service restarts

```bash
journalctl -u ipa-adtrust-install.service -n 200 --no-pager
systemctl restart krb5kdc sssd httpd
```

---

## 17) Common SRV lookups

```bash
# IPA (typo fixed)
dig +short _ldap._tcp.ipa.local SRV
dig +short _kerberos._udp.ipa.local SRV

# AD from IPA
dig +short dc1.itgroup.org @127.0.0.1

# Delegation check from AD
dig +short NS ipa.itgroup.org @IP_DC1
```

---

## 18) Notes on DNS forwarding

If forwarding doesn’t work, verify the forward **policy** isn’t `none`, and use `first` or `only` as needed. ([freeipa.org][8])

---

## 19) Security reminder

* Do **not** publish `OIDCClientSecret`, tokens, or real passwords.
* Rotate any secrets that were ever committed.
* `mod_auth_openidc` is the official module for Apache OIDC; see its docs for advanced options. ([GitHub][4])

---

### References

FreeIPA AD Trust how-to, forward zones, and trust controller notes. ([freeipa.org][7])
https://www.freeipa.org/page/Active_Directory_trust_setup?utm_source=chatgpt.com
---

