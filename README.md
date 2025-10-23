# FreeIPA + Active Directory — Two Integration Paths (GitHub‑ready)

> **Goal:** Production‑grade guide to install and operate **FreeIPA** on Rocky Linux with **two integration options**:
>
> 1. **OIDC SSO** via **Keycloak** (FreeIPA UI protected by Keycloak; AD as an LDAP user‑store)
>
> 2. **Domain Trust** between **FreeIPA ↔ Microsoft AD** (use AD users on Linux via IPA HBAC/Sudo)
>
> The doc is air‑gapped friendly, copy‑paste ready, and uses placeholders instead of secrets.

---

## Table of Contents

* [Architecture Options](#architecture-options)
* [Assumptions & IPs](#assumptions--ips)
* [Packages & Firewall](#packages--firewall)
* [DNS & Time (Critical)](#dns--time-critical)
* [Install FreeIPA Master](#install-freeipa-master)
* [Install FreeIPA Replica](#install-freeipa-replica)
* [Option A — Keycloak SSO (OIDC) + AD LDAP](#option-a--keycloak-sso-oidc--ad-ldap)
* [Option B — Domain Trust IPA ↔ AD](#option-b--domain-trust-ipa--ad)
* [HBAC & Sudo (AD groups → IPA)](#hbac--sudo-ad-groups--ipa)
* [Linux Clients Join & Tests](#linux-clients-join--tests)
* [Cleanup / Uninstall](#cleanup--uninstall)
* [Daily Health Checks](#daily-health-checks)
* [Troubleshooting Quick Hits](#troubleshooting-quick-hits)
* [Appendix: Ports, Glossary](#appendix-ports-glossary)

---

## Architecture Options

**Option A – Keycloak SSO**

* AD is connected to Keycloak using LDAP (read‑only).
* FreeIPA UI (Apache) is fronted by `mod_auth_openidc` → Keycloak.
* Users authenticate to Keycloak; Keycloak maps to AD; FreeIPA UI authorizes.

**Option B – IPA ↔ AD Trust**

* Build a forest/domain trust so Linux hosts joined to IPA can use **AD users**.
* **HBAC** controls SSH access; **Sudo rules** grant admin privileges to specific AD groups.
* Preferred when you want PAM/NSS on Linux to resolve AD identities via IPA.

> Choose **Option A** for SSO to the IPA Web UI without changing Linux auth model.
> Choose **Option B** if your Linux fleet must accept **AD users** directly for SSH/sudo.

---

## Assumptions & IPs

> Replace IPs/FQDNs with your own. Do **not** copy passwords/tokens into source control.

**FreeIPA**

* Master: `ipa-mas.ipa.local` → `192.168.5.40`
* Replica: `ipa-rep.ipa.local` → `192.168.5.41`

**Active Directory**

* DC1: `DC.matiran.local` → `192.168.5.1`
* DC2: `ADDC.matiran.local` → `192.168.5.2`

**Alt Example (itgroup.org)**

* IPA Master: `ipa-mas.ipa.itgroup.org` → `192.168.1.150`
* IPA Replica: `ipa-rep.ipa.itgroup.org` → `192.168.1.151`

> **Realms vs Domains**: Realm is uppercase Kerberos name (e.g., `IPA.LOCAL`), domain is DNS name (e.g., `ipa.local`). They **must not be identical** to the AD domain.

---

## Packages & Firewall

### Install packages (servers)

```bash
# IPA Master/Replica nodes
sudo dnf install -y \
  freeipa-server freeipa-server-dns freeipa-client ipa-healthcheck \
  freeipa-server-trust-ad samba samba-client samba-winbind samba-winbind-clients \
  oddjob oddjob-mkhomedir realmd adcli sssd
```

### Firewall (servers)

```bash
sudo firewall-cmd --permanent --add-port={80/tcp,443/tcp,389/tcp,636/tcp,88/tcp,88/udp,464/tcp,464/udp,53/tcp,53/udp}
sudo firewall-cmd --permanent --add-service={http,https,ldap,ldaps,kerberos,kpasswd,freeipa-trust,freeipa-replication}
sudo firewall-cmd --reload
sudo firewall-cmd --list-services
```

---

## DNS & Time (Critical)

* Ensure **chrony/NTP** sync for all nodes (Kerberos breaks if time skew > 5 minutes).
* Use **conditional forwarders** between IPA and AD zones.
* Do **not** hardcode AD hostnames in `/etc/hosts` on IPA nodes. Use DNS.

### Example resolv.conf handling

```bash
sudo bash -c 'cat >/etc/resolv.conf <<EOF
nameserver 192.168.5.40   # IPA
nameserver 192.168.5.41   # IPA
nameserver 192.168.5.1    # AD
nameserver 192.168.5.2    # AD
EOF'
# (Optional) lock file if your policy allows it
# sudo chattr +i /etc/resolv.conf
```

### Conditional Forwarders (create both ways)

**On IPA → forward AD**

```bash
ipa dnsforwardzone-add matiran.local \
  --forwarder=192.168.5.1 \
  --forwarder=192.168.5.2 \
  --forward-policy=only
```

**On AD → forward IPA** (PowerShell on DC)

```powershell
Add-DnsServerConditionalForwarderZone -Name "ipa.local" `
  -MasterServers "192.168.5.40","192.168.5.41" `
  -ReplicationScope "Forest"
```

**Quick checks**

```bash
dig +short _ldap._tcp.matiran.local SRV @127.0.0.1
dig +short DC.matiran.local @127.0.0.1
```

---

## Install FreeIPA Master

```bash
sudo hostnamectl set-hostname ipa-mas.ipa.local

sudo ipa-server-install -U \
  --realm IPA.LOCAL \
  --domain ipa.local \
  --hostname ipa-mas.ipa.local \
  --ds-password '<Directory_Manager_Password>' \
  --admin-password '<IPA_Admin_Password>' \
  --setup-dns \
  --forwarder=192.168.5.1 \
  --forwarder=192.168.5.2 \
  --no-ntp

ipactl status
ipa-healthcheck
```

> Alt (without forwarders): pass `--no-forwarders` if you don’t want IPA to forward DNS.

---

## Install FreeIPA Replica

### Join as client (with **-N** to avoid touching org NTP)

```bash
ipa-client-install -U \
  --domain=ipa.local \
  --server=ipa-mas.ipa.local \
  --realm=IPA.LOCAL \
  --mkhomedir -N \
  --principal=admin \
  --password '<IPA_Admin_Password>'
```

### Promote to replica

```bash
ipa-replica-install -U \
  --hostname ipa-rep.ipa.local \
  --setup-dns \
  --no-ntp \
  --no-forwarders \
  --principal=admin \
  --admin-password '<IPA_Admin_Password>'
```

**Validate**

```bash
kinit admin
ipactl status
ipa-healthcheck
ipa topologysegment-find domain
ipa topologysegment-find ca
```

---

## Option A — Keycloak SSO (OIDC) + AD LDAP

### Keycloak (Docker Compose)

```yaml
version: "3.8"
services:
  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    environment:
      KC_HOSTNAME: keycloak.ipa.local
      KC_HOSTNAME_PORT: 7080
      KC_HOSTNAME_STRICT_BACKCHANNEL: "true"
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: <ADMIN_PW>
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
```

### Connect AD as LDAP user‑federation

* **Connection URL**: `ldap://192.168.5.1:389`
* **Bind DN**: `CN=keycloak,CN=Users,DC=dev,DC=local`
* **Bind type**: `simple` (read‑only)
* **Users DN**: `DC=dev,DC=local`
* **Username attr**: `userPrincipalName`
* **RDN attr**: `cn`
* **Search scope**: `subtree`
* **Pagination/Import/Sync**: `ON`

**Group mapper (example)**

* Mapper type: `group-ldap-mapper`
* LDAP Groups DN: `DC=dev,DC=local`
* Group Name attr: `cn`
* Membership attr: `member` (Type=DN)
* User LDAP filter: `(&(ObjectCategory=Person)(ObjectClass=User)(!(isCriticalSystemObject=TRUE)))`
* Mode: `READ_ONLY`

### FreeIPA Apache ↔ Keycloak (mod_auth_openidc)

```bash
sudo dnf install -y mod_auth_openidc jq
sudo tee /etc/httpd/conf.d/05-oidc.conf >/dev/null <<'CONF'
OIDCProviderMetadataURL http://keycloak.ipa.local:7080/realms/master/.well-known/openid-configuration
OIDCClientID        freeipa
OIDCClientSecret    <CLIENT_SECRET>
OIDCRedirectURI     https://ipa-mas.ipa.local/oidc_callback
OIDCCryptoPassphrase <LONG_RANDOM>

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
CONF

sudo systemctl restart httpd
```

> Generate tokens only for testing via Keycloak’s token endpoint. **Do not** commit real tokens to Git.

---

## Option B — Domain Trust IPA ↔ AD

### Enable trust components on IPA

```bash
sudo ipa-adtrust-install --netbios-name=IPA --add-sids
sudo firewall-cmd --permanent --add-service=freeipa-trust && sudo firewall-cmd --reload
sudo systemctl enable --now smb winbind sssd
```

### Create the trust

**Method 1 — with AD admin creds**

```bash
ipa trust-add --type=ad dev.local --admin Administrator --password
```

**Method 2 — pre-shared secret** (when AD team creates the trust on their side)

```bash
ipa trust-add --type=ad dev.local --trust-secret
```

**Post‑trust refresh & verify**

```bash
ipa trust-fetch-domains
echo | wbinfo -p            # ping winbind
wbinfo -m                   # list trusted domains
wbinfo -D DEV               # details
systemctl restart sssd && sss_cache -E

id 'user@dev.local'        # should resolve
```

> If you expect **forest trust**, ensure AD creates forest‑level trust, not just external. SRV records must resolve both ways.

---

## HBAC & Sudo (AD groups → IPA)

**Pattern:** *AD group* → **External group in IPA** → **POSIX proxy group** → HBAC/Sudo rules.

```bash
# External group (represents an AD group)
ipa group-add ad-linux-sudo-ext --external
ipa group-add-member ad-linux-sudo-ext --external 'DEV\\Linux-Sudo'

# POSIX proxy group
ipa group-add linux-sudo --gid=55000 --desc="POSIX sudo group"
ipa group-add-member linux-sudo --groups=ad-linux-sudo-ext

# Sudo: ALL on all hosts for linux-sudo
ipa sudorule-add sudo_linux_sudo --hostcat=all --runasusercat=all
ipa sudorule-add-user sudo_linux_sudo --groups=linux-sudo
ipa sudorule-add-allow-command sudo_linux_sudo --sudocmds=ALL
ipa sudorule-enable sudo_linux_sudo

# HBAC: allow SSH for linux-sudo
ipa hbacrule-add allow_ssh_linux_sudo --servicecat=all
ipa hbacrule-add-user allow_ssh_linux_sudo --groups=linux-sudo
ipa hbacrule-add-service allow_ssh_linux_sudo --hbacsvcs=sshd
ipa hbacrule-add-host allow_ssh_linux_sudo --hostcat=all
ipa hbacrule-enable allow_ssh_linux_sudo
```

**Client‑side SSSD sudo integration**

```bash
sudo sed -i 's/^services = .*/services = nss, pam, ssh, sudo/' /etc/sssd/sssd.conf
sudo awk 'BEGIN{d=0}/^sudoers:/{print "sudoers: files sss";d=1;next}{print}END{if(!d)print "sudoers: files sss"}' \
  /etc/nsswitch.conf | sudo tee /etc/nsswitch.conf >/dev/null
sudo sss_cache -E && sudo systemctl restart sssd
```

---

## Linux Clients Join & Tests

```bash
ipa-client-install -U \
  --domain=ipa.local \
  --server=ipa-mas.ipa.local \
  --realm=IPA.LOCAL \
  --mkhomedir -N \
  --principal=admin \
  --password '<IPA_Admin_Password>'

# After trust
systemctl restart sssd
sss_cache -E

# Checks
sssctl user-show 'DEV\\a.sheikhi'
id 'DEV\\a.sheikhi'
sudo -l -U 'DEV\\a.sheikhi'
```

---

## Cleanup / Uninstall

```bash
ipa-server-install  --uninstall -U || true
ipa-replica-install --uninstall -U || true
ipa-client-install  --uninstall -U || true
systemctl stop sssd || true
rm -rf /etc/ipa /var/lib/ipa /var/log/ipa* /var/lib/sss/db/* /var/lib/sss/mc/* /var/lib/ipa/sysrestore/* 2>/dev/null || true
rm -f  /etc/krb5.keytab /etc/krb5.conf.bak 2>/dev/null || true
```

---

## Daily Health Checks

```bash
ipactl status
ipa-healthcheck
ipa trust-find
ipa trust-fetch-domains
systemctl status sssd smb winbind --no-pager

kinit -V admin

dig +short _ldap._tcp.ipa.local SRV @127.0.0.1
dig +short _ldap._tcp.dev.local SRV @127.0.0.1
```

---

## Troubleshooting Quick Hits

* **Time/NTP:** Always verify `chronyc sources -v` on all nodes.
* **DNS:** From IPA, AD SRV must resolve; from AD, IPA SRV must resolve.
* **Trust fails:** Open `freeipa-trust` service on IPA firewall; confirm AD created **forest** trust if required.
* **`Cannot contact LDAP server`:** Check 389‑DS, FQDN entries, and that you didn’t put IPA FQDN next to `127.0.0.1` in `/etc/hosts`.
* **Users visible but SSH denied:** Missing/incorrect **HBAC** rules.
* **Sudo not applying:** Ensure `services = ... sudo` in `sssd.conf` and `sudoers: files sss` in `nsswitch.conf`.

---

## Appendix: Ports, Glossary

**Open Ports (server side)**

* **LDAP** 389/636, **Kerberos** 88/464 (TCP/UDP)
* **HTTP/HTTPS** 80/443, **Dogtag** 8443
* **Samba/Winbind** 135, 137–139, 445, **GC** 3268, **EPMAP range** 1024–1300
* **DNS** 53 (TCP/UDP)

**Glossary**

* **Realm** (Kerberos) vs **Domain** (DNS) — Not the same; keep IPA realm/domain different from AD.
* **HBAC** — Host‑Based Access Control rules for SSH access.
* **External group** — IPA group whose members come from AD.
* **POSIX proxy group** — IPA POSIX group that includes an external group to grant Unix IDs.

---

## Repo Layout Suggestion

```
freeipa-ad-integration/
├─ README.md                 # This file
├─ keycloak/
│  └─ docker-compose.yml     # Keycloak for OIDC SSO
├─ scripts/
│  ├─ ipa-install-master.sh  # Parameterized installer
│  ├─ ipa-install-replica.sh
│  ├─ ipa-trust-setup.sh
│  ├─ ipa-cleanup.sh
│  └─ checks.sh              # Health/DNS/trust checks
└─ examples/
   ├─ httpd-oidc.conf        # 05-oidc.conf sample
   └─ ad-powershell.ps1      # AD install / forwarders / tests
```

> ⚠️ **Security**: replace `<...>` placeholders; never commit real passwords, tokens, or secrets.

---

## scripts/ipa-install-master.sh (example)

```bash
#!/usr/bin/env bash
set -euo pipefail
REALM=${REALM:-IPA.LOCAL}
DOMAIN=${DOMAIN:-ipa.local}
HOSTNAME=${HOSTNAME:-ipa-mas.ipa.local}
DM_PW=${DM_PW:?set Directory Manager PW}
ADMIN_PW=${ADMIN_PW:?set IPA admin PW}
FWD1=${FWD1:-192.168.5.1}
FWD2=${FWD2:-192.168.5.2}

ipa-server-install -U \
  --realm "$REALM" \
  --domain "$DOMAIN" \
  --hostname "$HOSTNAME" \
  --ds-password "$DM_PW" \
  --admin-password "$ADMIN_PW" \
  --setup-dns \
  --forwarder="$FWD1" \
  --forwarder="$FWD2" \
  --no-ntp
```

## scripts/ipa-trust-setup.sh (example)

```bash
#!/usr/bin/env bash
set -euo pipefail
TRUST_DOMAIN=${TRUST_DOMAIN:?e.g. dev.local}
METHOD=${METHOD:-secret}  # secret|admin

ipa-adtrust-install --netbios-name=IPA --add-sids
firewall-cmd --permanent --add-service=freeipa-trust || true
firewall-cmd --reload || true

case "$METHOD" in
  admin)
    ipa trust-add --type=ad "$TRUST_DOMAIN" --admin Administrator --password ;;
  secret)
    ipa trust-add --type=ad "$TRUST_DOMAIN" --trust-secret ;;
  *) echo "Unknown METHOD"; exit 1;;
esac

ipa trust-fetch-domains
systemctl restart sssd
sss_cache -E
```

---

**License:** MIT (docs/examples only). Contribution PRs welcome.
