# ESCalator PKINIT — Full Handoff (state as of 2026-10-04)

## Objective (unchanged)

Replace Rubeus.exe / Certify.exe with pure PowerShell + embedded C# (`Add-Type`) that:
1. Requests a cert with enrollee-supplied SAN (like Certify).
2. Does PKINIT → gets a TGT for the cert's SAN principal, verifies it, displays it, discards it (verify-only, no LSA injection, no ticket on disk).

**Success criterion:** successful PKINIT against the lab DC returning + decrypting a TGT for `Administrator@adcs.goat`.

**Constraints:** PowerShell 5.1 first (`powershell.exe`, not pwsh); .NET Framework 4.8.1 inbox; no external deps / no compiled DLLs; source visible in files.

---

## Where it stands (the wall)

- Custom PKINIT fails at **KRB-ERROR code 41 (KRB_ERR_MODIFIED)** against the Server 2025 KDC.
- Stock Rubeus (net472 build) fails at **error 60 (KRB_ERR_GENERIC)**; a **true 4.6.2 build of Rubeus ALSO fails at 60** — so no working reference client can be produced on this box, and the #196 CMS bug is NOT my current blocker.
- **KDC side produces ZERO events (no Security 4768/4771) for our attempts** — the KDC rejects the PKINIT preauth *before* account lookup, i.e. during cert/DH validation.
- EKU hypothesis **disproven**: certs with Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2) still get 41. So client-cert EKU validation passes; the failure is the DH/ECDH key agreement.
- Every client-side encoding variant has been tried and none moved 41: CMS digest SHA-256 vs SHA-1, signedAttrs present/absent, `supportedCMSTypes` added, empty `clientDHNonce`, EKU, CA publish.

**Decision made with user:** stand down the 2025 ECDH fight; **rebuild lab on Windows Server 2022** and use **MODP DH (Oakley 14) — Rubeus parity** for the PowerShell PKINIT. Rubeus/MODP is the proven-good client shape; ECDH encoding against a strict KDC is the unproven piece.

---

## Code state — `C:/Code/ESCalator/Private/`

### Invoke-PkinitVerify.cs  (~2276 lines embedded C#) — COMPILES CLEAN
Namespaces/types (all `internal` unless noted):
- `AsnElt` — ASN.1 DER encode/decode. `MakeBitString`, `MakeInteger`, `MakeOID`, `MakeImplicit/Explicit`, `Decode`, etc.
- `DhBigInteger` — custom big-int (little-endian uint[], Knuth division). **DO NOT use System.Numerics.BigInteger.ModPow on NetFX 4.8.1 — wrong answers.**
- `OakleyGroup14` — MODP prime (RFC 3526 group 14) + generator 2.
- `DhKeyExchange` — MODP DH. `PublicValueBytes`, `ComputeSharedSecret(kdcPublicKeyBytes)` (ModPow, left-pad to prime len). **This is the path to use for MODP parity.**
- `EcdhKeyExchange : IDisposable` — ECDiffieHellmanCng P-256. `PublicKeyPointBytes` = 0x04||X||Y (65B). `ComputeSharedSecret(point)` builds ECK1 CNG blob, `DeriveKeyMaterial` = raw 32-byte x-coord (correct per RFC 5349). ECDH math verified correct (two-party test passes) — the failure is KDC-side acceptance, not math.
- `KerberosCrypto` — AES-CTS via `cryptdll.dll` `CDLocateCSystem` P/Invoke. `KerberosDecrypt(etype, usage, key, data)`.
- `KrbPkAuthenticator`, `KrbAuthPack` (now has `SupportedCMSTypeOids` field [2], emits `clientDHNonce`[3] only if non-empty), `KrbDHRepInfo` (**hard-codes reply as dhSignedData choice [0]; has NO encKeyPack [1] path** — needed if KDC ever uses EnvelopedData), `KrbEncKdcRepPart`, `KrbPrincipalName`, req-body builders.
- `KdcKeyAgreement` — **currently wraps `EcdhKeyExchange`** (field `_ecdh`, `Y => PublicKeyPointBytes`, `GenerateKey` calls `_ecdh.ComputeSharedSecret`). `CalculateIntegrity` + `KTruncate` (SHA1-based, Rubeus port) are correct and reused by both paths.
- `PkinitClient` (public static):
  - `VerifyTgt(X509Certificate2 cert, string userName, string domain, string dcIp)` — entry point.
  - `BuildPkinitSignedData(byte[] authPackDer, X509Certificate2 cert)` — **manual CMS SignedData** (replaces NetFX SignedCms). Current form: SignedData **v1**, SHA-1 digest (`oidDigest` 1.3.14.3.2.26), signedAttrs [contentType=id-pkinit-authData(1.3.6.1.5.2.3.1), messageDigest=SHA1(authPack)], signerInfo v1 issuerAndSerial, signatureAlgorithm rsaEncryption(1.2.840.113549.1.1.1), certificates[0] IMPLICIT. Handles CAPI (`RSACryptoServiceProvider.SignHash`) and CNG (`RSACng.SignHash`) keys. **Correctly wraps eContent as `[0] EXPLICIT OCTET STRING(authPackDer)`** — this fixed the #196 defect.
  - AuthPack ECDH build at ~line 1933: `clientPublicValue` = SEQUENCE{ SEQUENCE{OID id-ecPublicKey, OID prime256v1}, BIT STRING(0x04||X||Y) }.

### TO SWITCH TO MODP (next task) — edit `KdcKeyAgreement`
Replace the `_ecdh` field/usage with `DhKeyExchange`:
- `private readonly DhKeyExchange _dh = new DhKeyExchange();`
- `public byte[] Y => _dh.PublicValueBytes;`
- `GenerateKey`: `byte[] sharedSecret = _dh.ComputeSharedSecret(kdcPublicKey);`
- Also add MODP params exposure: Rubeus sends `SubjectPublicKeyInfo { algorithm = AlgorithmIdentifier(1.2.840.10046.2.1 /*dhKeyAgreement*/, DomainParameters{p=Prime, g=Generator, q=0}), subjectPublicKey = INTEGER(Y) }`. The AuthPack `clientPublicValue` build (line ~1933) must change from the ECDH SPKI to this MODP SPKI. See Rubeus `PA_DATA.cs:114` + `KDCKeyAgreement.cs` (P/G/Q = Oakley.Group14).
- `KrbDHRepInfo` MODP branch already handles DER-INTEGER `subjectPublicKey` (line ~1494-1502).

### Request-ESC1Certificate.ps1 — WORKS
CSR with UPN SAN + optional SID extension; COM submission via `New-Object -ComObject CertificateAuthority.Request` (manual `[ComImport]` of ICertRequest2 fails E_NOINTERFACE — do not retry). Uses persisted `RSACryptoServiceProvider` machine-store container `ESCalator_<guid>`; returns live `RsaKey` + `KeyContainerName`; caller disposes.

### ConvertTo-NtdsSidExtension.ps1 — WORKS
Builds szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2), openssl-validated. `-TargetSid` on Request-ESC1Certificate. **Required for Server 2025 strong mapping (KB5014754).**

### ConvertTo-Pkcs8PrivateKey.ps1 — WORKS

### Test-ESC1Certificate.ps1 — WORKS (orchestrator)
Takes `-Certificate` (X509Certificate2 w/ PrivateKey), `-UserName`, `-Domain`, `-KeyContainerName`. Displays TGT fields; cleans key container in `finally`.

### Invoke-PkinitNative.cs — DEFERRED / DO NOT PURSUE
Native LsaLogonUser/KERB_CERTIFICATE_LOGON wrapper; `BuildCertificateLogon` has buggy offset math; needs SeTcbPrivilege. Only revisit if custom PKINIT proves impossible.

---

## Lab state (ADCSGoat) — Server 2025, being torn down

- DC: `ADCSGoat-DC.adcs.goat` (192.168.7.3). CA: `ADCSGoat-CA.adcs.goat`, CA name `LabRootCA1`.
- Admin SID: `S-1-5-21-2867300067-1926923562-3614575963-500`.
- LabRootCA1 thumb `2EE9E9E250962B191731B21D0E3FE2E30C2AA3B2` is in DC LocalMachine\Root. CRL published (`certutil -CRL`).
- DC has valid Kerberos Authentication cert (thumb `385B960ABA25E487E0066F6403446C8BE20C0F73`, KDC-Auth EKU 1.3.6.1.5.2.3.5 + Smart Card Logon, NotAfter 2027-10-04). `KdcUseCachedCertificates=0`. `StrongCertificateBindingEnforcement` REMOVED (do not weaken).
- **CA template publish:** live store = AD `CN=LabRootCA1,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=adcs,DC=goat`, attribute `certificateTemplates`. ADSI from the workstation works; ADSI inside PSRemoting to the CA fails (null array / operations error); AD module not on workstation. After editing, `Restart-Service CertSvc` on the CA. Publish does NOT reliably persist across restarts — if 0x80094800 recurs, re-add + restart.
  - Last set value (22 templates): User4ESCalator, Administrator, SubCA, User, Machine, WebServer, DomainController, EFS, EFSRecovery, KerberosAuthentication, DomainControllerAuthentication, DirectoryEmailReplication, Computer, EnrollmentAgent, OfflineRouter, CAExchange, CEPEncryption, IPSECIntermediateOffline, IPSECIntermediateOnline, Router, SmartcardLogon, SmartcardUser, Workstation, **User5ESCalator**.
  - NOTE: I once clobbered the registry `HKLM:\...\CertSvc\Configuration\LabRootCA1\CertificateTemplates` (read empty, wrote only User5ESCalator), then restored the full list. Registry and AD must both contain the template.

## Templates
- `User4ESCalator` — NameFlag 0x1 (ENROLLEE_SUPPLIES_SUBJECT). Issues certs with EKU = Client Auth + Secure Email + EFS (NO KPClientAuth).
- `User5ESCalator` — duplicate of `User` template; same EKUs (Client Auth + Secure Email + EFS), still NO KPClientAuth.
- `SmartcardLogon` / `SmartcardUser` — have Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2); still got error 41 → **EKU not the blocker**.

## Error ladder (each fix peeled a layer)
77 (digest) → 66 (can't verify cert; CA into DC root) → 62 (client not trusted; SID ext) → 60 (generic; was SignedCms eContent defect AND MODP) → **41 (KRB_ERR_MODIFIED — current)**.

## Rubeus #196 (why manual CMS exists)
NetFX 4.7.2/4.8 `SignedCms`/`CmsSigner` mis-encodes `encapsulatedContentInfo.eContent` (omits the OCTET STRING wrapper). Server 2025 KDCs reject; 2022 tolerates. openssl asn1parse of the SignedCms output showed `cont [0]` holding the AuthPack SEQUENCE directly (no OCTET STRING) at offset 55. My manual builder wraps correctly.

## Key files outside repo
- `C:/temp/rubeus-src/Rubeus` — Rubeus source.
- `C:/temp/Rubeus.exe` — net472 build (gets error 60). `C:/temp/Rubeus.exe.config` forces 4.6.2 runtime quirks (did NOT help).
- `C:/temp/Rubeus462.exe` — true 4.6.2 reference-assembly build (gets error 60). `C:/temp/Rubeus462.exe.config` sku 4.6.2.
- `C:/temp/build-rubeus2.ps1` — net472 build script. 4.6.2 refs: `C:/temp/net462-refs/build/.NETFramework/v4.6.2` (from NuGet `Microsoft.NETFramework.ReferenceAssemblies.net462` 1.0.3, nupkg at `C:/temp/net462-refs.nupkg`).
- `C:/temp/esc.pfx` — exported SID-ext cert (password `pass`).
- `%TEMP%\esccms.der` — CMS dump (currently STALE SignedCms output; live runs stopped overwriting after the manual-CMS edit dropped WriteAllBytes).
- `C:/temp/ms-pkca.pdf` — [MS-PKCA] spec.

## Reference client (MODP, known-good shape) — PKINITtools gettgtpkinit.py
- MODP DH group 14, SHA-1 CMS, SignedData **v3**, `subjectPublicKey` = INTEGER(Y), `DomainParameters{p,g,q=0}` (q mandatory-but-unused), `clientDHNonce` random, kTruncate SHA1 for AS-REP key.

---

## Next steps (on Server 2022 lab)
1. Rebuild ADCSGoat on 2022. Recreate CA (LabRootCA1), publish templates, recreate a ESC1-style template (ENROLLEE_SUPPLIES_SUBJECT) + SID extension support, DC Kerberos Auth cert, CA in DC root store.
2. Port `KdcKeyAgreement` to MODP (see edit recipe above). Change AuthPack `clientPublicValue` to MODP SPKI. Reuse `DhKeyExchange` + `KrbDHRepInfo` MODP branch.
3. Test: request cert (Request-ESC1Certificate, SAN+SID) → Test-ESC1Certificate → expect AS-REP (tag 0x6B), decrypt enc-part, verify nonce + cname=Administrator@adcs.goat, display TGT, discard.
4. On success: remove debug output, close GitHub #6, update map #2, then #7 (wire module into Invoke-ESC1Attack) and #8 (remove Binaries/).

## GitHub issues (jakehildreth/ESCalator)
- Map = #2. Children #3–#8. #3,#4,#5 closed. #6 = PKINIT (in progress — do NOT close until success). `gh` authenticated as jakehildreth.

## Full test invocation (powershell.exe -NoProfile -Command)
Dot-source in order: ConvertTo-Pkcs8PrivateKey.ps1, ConvertTo-NtdsSidExtension.ps1, Request-ESC1Certificate.ps1, Test-ESC1Certificate.ps1. Then:
`$cr = Request-ESC1Certificate -TemplateName '<tmpl>' -CertificateAuthority 'ADCSGoat-CA\LabRootCA1' -TargetUPN 'Administrator@adcs.goat' -TargetSid $sid`
attach `$cr.RsaKey` to cert, then `Test-ESC1Certificate -Certificate $cert -UserName 'Administrator' -Domain 'adcs.goat' -KeyContainerName $cr.KeyContainerName`.
