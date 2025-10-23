🔐 FreeIPA install with DNS + Microsoft AD integration

[!NOTE]
Two integration paths

FreeIPA → Keycloak → AD (OIDC for UI; AD via LDAP)

FreeIPA → Domain Trust → AD (AD users on Linux via trust)

[!WARNING]
Replace sample IPs, passwords, and tokens with your own. Never commit real secrets.
Correct file name is /etc/resolv.conf (not resolve.conf).
For AD trust, promote at least one IPA server as an AD trust controller.

✨ What this repo gives you

[!TIP]

✅ Linux hosts join IPA; AD users log in; HBAC/SUDO policies from IPA

✅ FreeIPA Web UI protected by Keycloak (OIDC); Keycloak reads users/groups from AD (LDAP)

✅ Clean name-resolution via conditional forwarders / delegation between ipa.local and test.local

✅ Cross-forest AD Trust so Linux talks to IPA while authentication flows to AD

🖼️ Architecture banner (GitHub-native Mermaid)
