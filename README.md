# 🔐 FreeIPA + DNS + Microsoft AD Integration

> [!NOTE]
> **Two integration paths**
> 1) **FreeIPA → Keycloak → AD** (OIDC for UI; AD via LDAP)  
> 2) **FreeIPA → Domain Trust → AD** (AD users on Linux via trust)

> [!WARNING]
> Replace sample **IPs**, **passwords**, and **tokens** with your own. **Never commit real secrets.**  
> Correct file name is `/etc/resolv.conf` (not `resolve.conf`).  
> Promote at least one IPA server as an **AD trust controller** for trust setup.

---

## ✨ What you get

> [!TIP]
> - ✅ Linux hosts join **IPA**; **AD** users sign in; **HBAC/SUDO** policies from IPA  
> - ✅ FreeIPA Web UI protected via **Keycloak (OIDC)**; Keycloak reads users/groups from **AD (LDAP)**  
> - ✅ Clean name-resolution with **conditional forwarders / delegation** between `ipa.local` and `test.local`  
> - ✅ Cross-forest **AD Trust** so Linux talks only to IPA while auth flows to AD

---

## 🖼️ Architecture (UML banner)

<p align="center">
  <img src="https://raw.githubusercontent.com/ahmadsheikhi89/Freeipa-AD-Trust-install/main/freeipa-ad-trust-keycloak.png"
       alt="FreeIPA ↔ AD (Keycloak / OIDC)" width="100%">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/ahmadsheikhi89/Freeipa-AD-Trust-install/main/freeipa-ad-trust.png"
       alt="FreeIPA + AD (Trust / Network)" width="100%">
</p>


---

## 🧭 Address plan (examples)

> [!NOTE]
> You can change these—kept consistent here for copy/paste testing.

| Zone / Role | Hostname (FQDN)             | IP            |
|---|---|---|
| FreeIPA | ipa-mas.ipa.test.local          | 10.10.10.11   |
| FreeIPA | ipa-rep.ipa.test.local          | 10.10.10.12   |
| FreeIPA | log-srv.ipa.test.local          | 10.10.10.13   |
| FreeIPA | keycloak.ipa.local              | 10.10.10.14   |
| FreeIPA | linuxclient.ipa.local           | 10.10.10.15   |
| AD      | dc1.test.local                  | 10.20.20.11   |
| AD      | dc2.test.local                  | 10.20.20.12   |
| AD      | win-client.test.local (sample)  | 10.20.20.31   |

---

<details>
<summary><b>📦 0) Packages</b></summary>

```bash
# Server-side
dnf install -y freeipa-server freeipa-server-dns freeipa-client ipa-healthcheck \
  freeipa-server-trust-ad samba samba-client oddjob oddjob-mkhomedir

# Client/aux
dnf install -y ipa-client sssd samba-client oddjob oddjob-mkhomedir adcli realmd
```
</details>

<details>
<summary><b>🧹 1) Uninstall / Cleanup (safe re-run)</b></summary>

```bash
ipa-server-install --uninstall -U || true
ipa-replica-install --uninstall -U || true
ipa-client-install  --uninstall -U || true

systemctl stop sssd || true
rm -rf /etc/ipa /var/lib/ipa /var/log/ipa* /var/lib/sss/db/* /var/lib/sss/mc/* /var/lib/ipa/sysrestore/* 2>/dev/null || true
rm -f  /etc/krb5.keytab /etc/krb5.conf.bak 2>/dev/null || true
```
</details>

<details>
<summary><b>🌐 2) Network & DNS</b></summary>

> [!TIP]
> If NetworkManager manages DNS, use `nmcli` instead of locking `/etc/resolv.conf`.

**2.1 NIC DNS**
```bash
nmcli connection modify ens33 ipv4.dns "10.10.10.11,10.10.10.12"
nmcli connection down ens33 && nmcli connection up ens33
```

**2.2 Hostname & `/etc/hosts`**
```bash
hostnamectl set-hostname ipa-mas.ipa.test.local

# /etc/hosts (IPA side)
127.0.0.1   localhost
::1         localhost
10.10.10.11 ipa-mas.ipa.test.local  ipa-mas
10.10.10.12 ipa-rep.ipa.test.local  ipa-rep
10.10.10.13 log-srv.ipa.test.local  log-srv

# Separate view (IPA vs AD)
10.10.10.11 ipa-mas.ipa.local   ipa-mas
10.10.10.12 ipa-rep.ipa.local   ipa-rep
10.20.20.11 dc1.test.local      dc1
10.20.20.12 dc2.test.local      dc2
```

**2.3 `/etc/resolv.conf`**
```bash
# IPA DNS
nameserver 10.10.10.11
nameserver 10.10.10.12
# AD DNS
nameserver 10.20.20.11
nameserver 10.20.20.12

# Optional lock/unlock
sudo chattr +i /etc/resolv.conf
lsattr /etc/resolv.conf
sudo chattr -i /etc/resolv.conf
```
</details>

<details>
<summary><b>🔥 3) Firewall</b></summary>

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
</details>

<details>
<summary><b>🖥️ 4) Active Directory (Windows Server) – setup</b></summary>

```powershell
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
```
</details>

<details>
<summary><b>☁️ 5) Keycloak (for SSO path)</b></summary>

**5.1 Docker Compose**
```yaml
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
```

**5.2 LDAP basics (AD as user store)**  
- Connection: `ldap://10.20.20.11:389`  
- Bind DN: `CN=keycloak,CN=users,DC=test,DC=local`  
- Users DN: `DC=test,DC=local`  
- Username attr: `userPrincipalName` | RDN: `cn` | Scope: `subtree`  
- Pagination / Import users / Sync registrations: **ON**

**5.3 Group mapper (example)**  
- LDAP Groups DN: `DC=test,DC=local`  
- Group Name attr: `cn`  
- Membership attr: `member` (Type = DN)  
- User filter: `(&(ObjectCategory=Person)(ObjectClass=User)(!(isCriticalSystemObject=TRUE)))`  
- Mode: `Read_Only`
</details>

<details>
<summary><b>🔐 6) Apache OIDC (protect FreeIPA UI via Keycloak)</b></summary>

```bash
sudo dnf install -y mod_auth_openidc jq
sudo nano /etc/httpd/conf.d/05-oidc.conf
```

```apache
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
```

```bash
sudo systemctl restart httpd
sudo tail -n 50 -f /var/log/httpd/error_log
```
</details>

<details>
<summary><b>🧭 7) DNS Delegation (if used)</b></summary>

On **AD DNS** (`test.local`) create **New Delegation** for `ipa` to:

- `ipa-mas.ipa.test.local.` → A: `10.10.10.11`  
- `ipa-rep.ipa.test.local.` → A: `10.10.10.12`  
*(Create Glue A records.)*
</details>

<details>
<summary><b>🏗️ 8) Install FreeIPA Master (with internal DNS)</b></summary>

**With forwarders**
```bash
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
```

**Without forwarding**
```bash
ipa-server-install --unattended \
  --realm IPA.LOCAL \
  --domain ipa.local \
  --hostname ipa-master.ipa.local \
  --ds-password '<DM_PASSWORD>' \
  --admin-password '<IPA_ADMIN_PASSWORD>' \
  --setup-dns \
  --no-forwarders \
  --ntp
```
</details>

<details>
<summary><b>🔁 9) Conditional Forwarders</b></summary>

**On IPA → forward AD (test.local)**
```bash
ipa dnsforwardzone-add test.local \
  --forwarder=10.20.20.11 \
  --forwarder=10.20.20.12 \
  --forward-policy=only

ipa dnsforwardzone-show test.local
dig @127.0.0.1 +short _ldap._tcp.test.local SRV
dig @127.0.0.1 +short dc1.test.local
```

**On AD → forward IPA (ipa.local)**
```powershell
Add-DnsServerConditionalForwarderZone -Name "ipa.local" -MasterServers "10.10.10.11","10.10.10.12" -ReplicationScope "Forest"

nslookup ipa-mas.ipa.local
nslookup ipa-rep.ipa.local
Get-DnsServerConditionalForwarderZone -Name "ipa.local" | fl *
Resolve-DnsName ipa-mas.ipa.local
Resolve-DnsName _ldap._tcp.ipa.local -Type SRV
```
</details>

<details>
<summary><b>🧬 10) Replica install (on ipa-rep)</b></summary>

```bash
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
```

**Validate**
```bash
kinit admin
ipactl status
ipa-healthcheck

ipa trust-find
ipa trust-fetch-domain
systemctl restart sssd
sss_cache -E
```

**SRV tests (test.local)**
```bash
dig +short _ldap._tcp.test.local SRV
dig +short _kerberos._tcp.test.local SRV
host -t A dc1.test.local
```

**Topology**
```bash
ipa topologysegment-find domain
ipa topologysegment-find ca
ipa trust-fetch-domains
```
</details>

<details>
<summary><b>🧪 11) DNS & HA sanity tests</b></summary>

```bash
# A records
dig +short ipa-master.ipa.local A
dig +short ipa-rep.ipa.test.local A

# SRV (after replica, should list both servers)
dig +short _ldap._tcp.ipa.test.local SRV @127.0.0.1
dig +short _kerberos._tcp.ipa.test.local SRV @127.0.0.1
```

From a machine using **AD DNS**:
```powershell
nslookup ipa-mas.ipa.test.local 10.20.20.11
nslookup -type=NS ipa.test.local 10.20.20.11
```
</details>

<details>
<summary><b>🛡️ 12) Build AD Trust</b></summary>

```bash
dnf install -y freeipa-server-trust-ad samba samba-winbind samba-winbind-clients
systemctl enable --now smb winbind sssd
ipa-adtrust-install -U --netbios-name=IPA --enable-compat --add-sids
firewall-cmd --add-service=freeipa-trust --permanent && firewall-cmd --reload

ipa trust-add --type=ad test.local --trust-secret
# OR:
ipa trust-add --type=ad test.local --admin Administrator --password
```

**Verify**
```bash
kdestroy
kinit admin
systemctl restart smb winbind sssd
ipa trust-fetch-domains test.local
wbinfo -m
wbinfo -D TEST
wbinfo --online-status
```
</details>

<details>
<summary><b>🧷 13) HBAC & SUDO (AD groups)</b></summary>

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

**Client-side sudo via SSSD**
```bash
sudo sed -i 's/^services = .*/services = nss, pam, ssh, sudo/' /etc/sssd/sssd.conf
sudo awk 'BEGIN{d=0}/^sudoers:/{print "sudoers: files sss";d=1;next}{print}END{if(!d)print "sudoers: files sss"}' \
  /etc/nsswitch.conf | sudo tee /etc/nsswitch.conf >/dev/null
sudo sss_cache -E
sudo systemctl restart sssd
```
</details>

<details>
<summary><b>🔍 14) Useful queries & checks</b></summary>

```bash
ipa group-show linux-admin --all | egrep 'Group name|Member groups|GID'
ipa group-show ad-linux-admin-ext1 --all | grep -E 'External member'

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
</details>

<details>
<summary><b>🧪 15) Client tests</b></summary>

```bash
grep ^services /etc/sssd/sssd.conf
grep ^sudoers  /etc/nsswitch.conf

sssctl user-show 'TEST\a.sheikhi'
id 'TEST\a.sheikhi'
sudo -l -U 'TEST\a.sheikhi'

sudo -l -U 'TEST\m.hadadian'   # expect no sudo if not in group
```
</details>

<details>
<summary><b>🧰 16) Logs & service restarts</b></summary>

```bash
journalctl -u ipa-adtrust-install.service -n 200 --no-pager
systemctl restart krb5kdc sssd httpd
```
</details>

<details>
<summary><b>🔎 17) Common DNS lookups</b></summary>

```bash
# IPA SRV
dig +short _ldap._tcp.ipa.local SRV
dig +short _kerberos._udp.ipa.local SRV

# AD from IPA (test.local)
dig +short dc1.test.local @127.0.0.1

# Delegation from AD view
dig +short NS ipa.test.local @10.20.20.11
```
</details>
