# Vendored from PSPkinit

The files in this folder are vendored from [PSPkinit](https://github.com/Semperis-Community/PSPkinit)
(MIT License with Commons Clause), Jake Hildreth's pure-PowerShell RFC 4556 PKINIT
implementation. They replace ESCalator's former dependency on Rubeus.exe for the
certificate-authentication step.

| File | Upstream path | Purpose |
|------|---------------|---------|
| `Asn1.ps1` | `Private/Asn1.ps1` | DER encode/decode |
| `CertEnroll.ps1` | `Private/CertEnroll.ps1` | Certificate enrollment helpers (IX509 / COM) |
| `KerberosCrypto.ps1` | `Private/KerberosCrypto.ps1` | RFC 3961/3962 Kerberos crypto (AES-CTS, key derivation) |
| `Pkinit.ps1` | `Private/Pkinit.ps1` | MODP DH (Oakley 14), AuthPack, CMS SignedData, KDC reply parsing |
| `PkinitModPow.ps1` | ESCalator addition | NetFX-4.8.1-safe big-integer `ModPow` (upstream uses `BigInteger.ModPow`, broken on NetFX); `Pkinit.ps1` is patched to call it |
| `PkinitMessages.ps1` | `Private/PkinitMessages.ps1` | AS-REQ/AS-REP/KRB-ERROR structures |

`Invoke-PkinitAuthentication.ps1` and `New-PkinitCertificateRequest.ps1` (the public
cmdlets) are vendored alongside but **adapted** for ESCalator's verify-only posture:
the TGT and session key are zeroed and discarded after display, never returned live
or injected.

Do not hand-edit the five helper files to add ESCalator-specific behavior; fixes
should flow from upstream PSPkinit where possible. The adapted public cmdlets carry
ESCalator-specific discard logic and may diverge.

Vendored 2026-10-05 against the PSPkinit working tree at C:/Code/PSpkinit.
