حاضره! این **README** نسخه‌ی خوشگل‌تر، یک‌دست و آمادهٔ GitHub ـه — با ایموجی، سکشن‌های واضح، و بلاک‌های کپی-پیست. می‌تونی همینو کامل جایگزین `README.md` کنی.

---

# FreeIPA ↔ Active Directory — **SSO via Keycloak** ☁️ یا **Domain Trust** 🛡️

> راهنمای Production-grade برای نصب FreeIPA روی Rocky/RedHat و اتصال به Microsoft AD با دو مسیر:
>
> **A)** SSO با Keycloak (AD به عنوان LDAP User-store)
> **B)** Trust بین IPA↔AD برای استفاده از کاربران AD روی لینوکس (HBAC/Sudo)

Air-gapped-friendly · Copy-paste-ready · بدون رمز/توکن واقعی ✅

---

## 🧭 فهرست

* [معماری و انتخاب مسیر](#-معماری-و-انتخاب-مسیر)
* [پیش‌فرض‌ها و متغیرها](#-پیشفرضها-و-متغیرها)
* [نصب پکیج‌ها و فایروال](#-نصب-پکیجها-و-فایروال)
* [DNS و زمان (حیاتی)](#-dns-و-زمان-حیاتی)
* [نصب FreeIPA Master](#-نصب-freeipa-master)
* [نصب FreeIPA Replica](#-نصب-freeipa-replica)
* [مسیر A: Keycloak OIDC + AD LDAP](#-مسیر-a-keycloak-oidc--ad-ldap)
* [مسیر B: Trust بین IPA ↔ AD](#-مسیر-b-trust-بین-ipa--ad)
* [نقشهٔ دسترسی: External Group → POSIX → HBAC/Sudo](#-نقشهٔ-دسترسی-external-group--posix--hbacsudo)
* [Join و تست روی کلاینت‌های لینوکسی](#-join-و-تست-روی-کلاینتهای-لینوکسی)
* [Healthcheck روزانه](#-healthcheck-روزانه)
* [Troubleshooting سریع](#-troubleshooting-سریع)
* [License](#license)

---

## 🧩 معماری و انتخاب مسیر

* **A) Keycloak SSO**: فقط لاگین UI فری‌IPA را OIDC می‌کنیم؛ هویت از AD (LDAP) می‌آید؛ مناسب وقتی که Auth لینوکس را دست نمی‌زنیم. تنظیم با `mod_auth_openidc` روی Apache انجام می‌شود. ([mod-auth-openidc.org][1])
* **B) IPA↔AD Trust**: اعتماد بین جنگل‌ها/دامین‌ها برقرار می‌شود تا **کلاینت‌های لینوکسی عضو IPA** کاربران AD را برای SSH/Sudo ببینند. Trust باید طبق راهنمای FreeIPA ایجاد شود (cross-forest). ([freeipa.org][2])

> نکتهٔ مهم Trust: نام Realm فری‌IPA باید با نام Domain آن هم‌ارزش (uppercase/lowercase) باشد؛ پیش‌نیاز `ipa-adtrust-install` هم رعایت شود. ([Debian Manpages][3])

---

## ⚙️ پیش‌فرض‌ها و متغیرها

| Var                | Sample              | Notes                         |
| ------------------ | ------------------- | ----------------------------- |
| `IPA_REALM`        | `IPA.LOCAL`         | Kerberos realm (UPPER)        |
| `IPA_DOMAIN`       | `ipa.local`         | DNS domain (lower)            |
| `IPA_MASTER_FQDN`  | `ipa-mas.ipa.local` |                               |
| `IPA_REPLICA_FQDN` | `ipa-rep.ipa.local` |                               |
| `AD_DOMAIN`        | `matiran.local`     | یک نمونه انتخاب و همه‌جا ثابت |
| `AD_NETBIOS`       | `MATIRAN`           | برای `wbinfo -D`              |
| `AD_DC1`/`AD_DC2`  | `192.168.5.1/5.2`   |                               |

> آدرس‌ها و پسوردها را با مقادیر واقعی جایگزین کنید—هیچ راز/توکنی داخل ریپو نگذارید.

---

## 📦 نصب پکیج‌ها و فایروال

```bash
sudo dnf install -y \
  freeipa-server freeipa-server-dns freeipa-client ipa-healthcheck \
  freeipa-server-trust-ad samba samba-client samba-winbind samba-winbind-clients \
  oddjob oddjob-mkhomedir realmd adcli sssd

# Firewall
sudo firewall-cmd --permanent --add-port={80/tcp,443/tcp,389/tcp,636/tcp,88/tcp,88/udp,464/tcp,464/udp,53/tcp,53/udp}
sudo firewall-cmd --permanent --add-service={http,https,ldap,ldaps,kerberos,kpasswd,freeipa-trust,freeipa-replication}
sudo firewall-cmd --reload && sudo firewall-cmd --list-services
```

---

## ⏱️ DNS و زمان (حیاتی)

* اختلاف زمان >۵ دقیقه = شکست Kerberos. از NTP/Chrony سازمانی استفاده کنید.
* **Conditional Forwarders** دوطرفه میان IPA و AD بسازید. **Forward policy = only** برای زون‌های هدف توصیه می‌شود. ([freeipa.org][4])

**روی IPA → Forward به AD:**

```bash
ipa dnsforwardzone-add ${AD_DOMAIN} \
  --forwarder=${AD_DC1} \
  --forwarder=${AD_DC2} \
  --forward-policy=only
```

**روی AD → Forward به IPA (PowerShell روی DC):**

```powershell
Add-DnsServerConditionalForwarderZone -Name "ipa.local" `
  -MasterServers "192.168.5.40","192.168.5.41" `
  -ReplicationScope "Forest"
```

**نمونهٔ resolv.conf (مدیریت با NMCLI بهتر است):**

```bash
nmcli con mod <IFNAME> ipv4.dns "192.168.5.40,192.168.5.41"
nmcli con mod <IFNAME> ipv4.ignore-auto-dns yes
nmcli con down <IFNAME> && nmcli con up <IFNAME>
```

---

## 🚀 نصب FreeIPA Master

```bash
sudo hostnamectl set-hostname ${IPA_MASTER_FQDN}

ipa-server-install -U \
  --realm ${IPA_REALM} \
  --domain ${IPA_DOMAIN} \
  --hostname ${IPA_MASTER_FQDN} \
  --ds-password '<Directory_Manager_Password>' \
  --admin-password '<IPA_Admin_Password>' \
  --setup-dns \
  --forwarder=${AD_DC1} \
  --forwarder=${AD_DC2} \
  --no-ntp

ipactl status
ipa-healthcheck
```

---

## ➕ نصب FreeIPA Replica

```bash
# Join به‌عنوان کلاینت (NTP سازمانی را دست‌نزن: -N)
ipa-client-install -U \
  --domain=${IPA_DOMAIN} \
  --server=${IPA_MASTER_FQDN} \
  --realm=${IPA_REALM} \
  --mkhomedir -N \
  --principal=admin \
  --password '<IPA_Admin_Password>'

# Promote به Replica + DNS
ipa-replica-install -U \
  --hostname ${IPA_REPLICA_FQDN} \
  --setup-dns \
  --no-ntp \
  --no-forwarders \
  --principal=admin \
  --admin-password '<IPA_Admin_Password>'

kinit admin
ipa-healthcheck
```

---

## 🔐 مسیر A: Keycloak OIDC + AD LDAP

**Keycloak (Docker Compose – Dev use only):**

```yaml
version: "3.8"
services:
  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    environment:
      KC_HOSTNAME: keycloak.ipa.local
      KC_HOSTNAME_PORT: 7080
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: CHANGE_ME
      KC_HEALTH_ENABLED: "true"
    command: ["start-dev","--http-port","7080","--https-port","7443"]
    ports: ["7080:7080","7443:7443"]
```

**Apache OIDC روی FreeIPA UI** (خلاصه؛ به مستند رسمی مراجعه کنید):
`mod_auth_openidc` ماژول رسمی OIDC برای Apache است؛ با Keycloak سازگار است. ([mod-auth-openidc.org][1])

```bash
sudo dnf install -y mod_auth_openidc jq
sudo tee /etc/httpd/conf.d/05-oidc.conf >/dev/null <<'CONF'
OIDCProviderMetadataURL http://keycloak.ipa.local:7080/realms/master/.well-known/openid-configuration
OIDCClientID        freeipa
OIDCClientSecret    <CLIENT_SECRET>
OIDCRedirectURI     https://ipa-mas.ipa.local/oidc_callback
OIDCCryptoPassphrase <LONG_RANDOM>

OIDCScope "openid profile email"
OIDCRemoteUserClaim preferred_username
OIDCOAuthAcceptTokenAs header
OIDCClaimPrefix ""
OIDCPassIDTokenAs serialized
OIDCPassUserInfoAs claims

OIDCSessionType server-cache
OIDCSessionInactivityTimeout 3600
OIDCStripCookies On
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

---

## 🛡️ مسیر B: Trust بین IPA ↔ AD

**گام 1 — آماده‌سازی Trust Controller در IPA:**

```bash
ipa-adtrust-install --netbios-name=IPA --add-sids
# این نود Trust Controller می‌شود؛ لازم نیست روی همهٔ مسترها اجرا شود. :contentReference[oaicite:5]{index=5}
firewall-cmd --permanent --add-service=freeipa-trust && firewall-cmd --reload
```

**گام 2 — ساخت Trust (یکی از دو روش):**

```bash
# روش Admin (با اکانت AD)
ipa trust-add --type=ad ${AD_DOMAIN} --admin Administrator --password
# روش Secret (وقتی از سمت AD هم تنظیم می‌کنند)
ipa trust-add --type=ad ${AD_DOMAIN} --trust-secret
```

> فرمان رسمی `trust-add` و سناریوهای تست: مستند FreeIPA. ([freeipa.readthedocs.io][5])

**گام 3 — تازه‌سازی و تأیید:**

```bash
ipa trust-fetch-domains
echo | wbinfo -p
wbinfo -m
wbinfo -D ${AD_NETBIOS}
systemctl restart sssd && sss_cache -E
id 'user@'${AD_DOMAIN}
```

---

## 🧷 نقشهٔ دسترسی: External Group → POSIX → HBAC/Sudo

الگو: گروه AD ←(**external**)← گروه IPA ←(**POSIX proxy**)← اعمال در **HBAC/Sudo**.

```bash
# External group (نمایندهٔ گروه AD)
ipa group-add ad-linux-sudo-ext --external
ipa group-add-member ad-linux-sudo-ext --external "${AD_NETBIOS}\\Linux-Sudo"

# POSIX proxy group
ipa group-add linux-sudo --gid=55000 --desc="POSIX sudo group"
ipa group-add-member linux-sudo --groups=ad-linux-sudo-ext

# Sudo: ALL
ipa sudorule-add sudo_linux_sudo --hostcat=all --runasusercat=all
ipa sudorule-add-user sudo_linux_sudo --groups=linux-sudo
ipa sudorule-add-allow-command sudo_linux_sudo --sudocmds=ALL
ipa sudorule-enable sudo_linux_sudo

# HBAC: اجازهٔ SSH
ipa hbacrule-add allow_ssh_linux_sudo --servicecat=all
ipa hbacrule-add-user allow_ssh_linux_sudo --groups=linux-sudo
ipa hbacrule-add-service allow_ssh_linux_sudo --hbacsvcs=sshd
ipa hbacrule-add-host allow_ssh_linux_sudo --hostcat=all
ipa hbacrule-enable allow_ssh_linux_sudo
```

**SSSD + sudo روی کلاینت‌ها (حداقل لازم):**

```bash
# /etc/sssd/sssd.conf  → سرویسی به sudo هم بده
# [sssd]
# services = nss, pam, ssh, sudo

# /etc/nsswitch.conf
sudoers: files sss
```

(مرجع RHEL/SSSD برای sudo از طریق SSSD.) ([Red Hat Docs][6])

---

## 🖥️ Join و تست روی کلاینت‌های لینوکسی

```bash
ipa-client-install -U \
  --domain=${IPA_DOMAIN} \
  --server=${IPA_MASTER_FQDN} \
  --realm=${IPA_REALM} \
  --mkhomedir -N \
  --principal=admin \
  --password '<IPA_Admin_Password>'

systemctl restart sssd
sss_cache -E

# تست‌ها
sssctl user-show "${AD_NETBIOS}\\a.sheikhi"
id "${AD_NETBIOS}\\a.sheikhi"
sudo -l -U "${AD_NETBIOS}\\a.sheikhi"
```

---

## 🩺 Healthcheck روزانه

```bash
ipactl status
ipa-healthcheck

ipa trust-find
ipa trust-fetch-domains

systemctl status sssd smb winbind --no-pager

# DNS sanity
dig +short _ldap._tcp.${IPA_DOMAIN} SRV @127.0.0.1
dig +short _ldap._tcp.${AD_DOMAIN} SRV @127.0.0.1
```

---

## 🧯 Troubleshooting سریع

* **Time/Skew**: اول Chrony/NTP را چک کن.
* **DNS**: SRV های هر دو طرف باید از طرف مقابل resolve شوند؛ forward-policy را روی `only`/`first` درست بگذار. ([freeipa.org][7])
* **Trust نمی‌سازد**: مطمئن شو `ipa-adtrust-install` روی حداقل یک مستر اجرا شده و همین نود Trust Controller است. سپس `ipa trust-add ...`، بعد `trust-fetch-domains` و `wbinfo -m/-D`. ([Red Hat Docs][8])
* **کاربر AD دیده می‌شود ولی SSH نمی‌شود**: HBAC درست نیست.
* **sudo اعمال نمی‌شود**: `services = ... sudo` در `sssd.conf` و `sudoers: files sss` در `nsswitch.conf`. ([Red Hat Docs][6])

---

## License

MIT — اسکریپت‌ها/مستندات آموزشی.
**⚠️ امنیت:** هرگز رمز/توکن واقعی را در Git نگذار؛ secrets را rotate کن.

---

### 🧱 ساختار پیشنهادی ریپو

```
.
├─ README.md
├─ LICENSE
├─ .gitignore
├─ keycloak/
│  └─ docker-compose.yml
├─ scripts/
│  ├─ ipa-install-master.sh
│  ├─ ipa-install-replica.sh
│  ├─ ipa-trust-setup.sh
│  └─ checks.sh
└─ examples/
   └─ ad-powershell.ps1
```

---

اگه خواستی، همین رو به چند فایل (اسکریپت‌ها + compose + نمونهٔ conf) برات **zip** کنم تا مستقیم آپلود کنی—بگو «زیپ بساز».

[1]: https://www.mod-auth-openidc.org/?utm_source=chatgpt.com "mod_auth_openidc"
[2]: https://www.freeipa.org/page/Active_Directory_trust_setup?utm_source=chatgpt.com "Active_Directory_trust_setup — FreeIPA documentation"
[3]: https://manpages.debian.org/experimental/freeipa-server-trust-ad/ipa-adtrust-install.1.en.html?utm_source=chatgpt.com "ipa-adtrust-install(1) — freeipa-server-trust-ad"
[4]: https://www.freeipa.org/page/V4/Forward_zones?utm_source=chatgpt.com "Forward_zones — FreeIPA documentation"
[5]: https://freeipa.readthedocs.io/en/ipa-4-11/api/trust_add.html?utm_source=chatgpt.com "trust_add — FreeIPA 4.11-dev documentation"
[6]: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/linux_domain_identity_authentication_and_policy_guide/sudo-configuration-database?utm_source=chatgpt.com "30.3. Configuring the Location for Looking up sudo Policies"
[7]: https://www.freeipa.org/page/Troubleshooting/DNS?utm_source=chatgpt.com "DNS — FreeIPA documentation"
[8]: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/installing_trust_between_idm_and_ad/setting-up-a-trust_installing-trust-between-idm-and-ad?utm_source=chatgpt.com "Chapter 9. Setting up a trust | Installing trust between IdM ..."
