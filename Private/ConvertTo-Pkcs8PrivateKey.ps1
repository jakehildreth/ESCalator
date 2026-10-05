function ConvertTo-Pkcs8PrivateKey {
    <#
        .SYNOPSIS
        Exports an RSA private key as PKCS#8 DER on .NET Framework 4.8.1.

        .DESCRIPTION
        RSA.ExportPkcs8PrivateKey() was added in .NET Core 3.0 and is unavailable on
        NetFX 4.8.1. This helper builds the PKCS#8 PrivateKeyInfo structure (RFC 5208)
        manually from RSA.ExportParameters():

            PrivateKeyInfo ::= SEQUENCE {
                version                   INTEGER (0),
                privateKeyAlgorithm       AlgorithmIdentifier (rsaEncryption, NULL),
                privateKey                OCTET STRING (PKCS#1 RSAPrivateKey DER)
            }

            RSAPrivateKey ::= SEQUENCE {
                version           INTEGER (0),
                modulus           INTEGER (n),
                publicExponent    INTEGER (e),
                privateExponent   INTEGER (d),
                prime1            INTEGER (p),
                prime2            INTEGER (q),
                exponent1         INTEGER (d mod p-1),
                exponent2         INTEGER (d mod q-1),
                coefficient       INTEGER (q^-1 mod p)
            }

        DER encoding is done with a minimal local writer (no external dependencies).

        .PARAMETER Rsa
        An System.Security.Cryptography.RSA instance containing a private key.

        .OUTPUTS
        System.Byte[] — PKCS#8 DER bytes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.RSA]$Rsa
    )

    # Minimal DER writer. Handles lengths up to 64KB (sufficient for 4096-bit keys).
    function Write-DerLength([System.IO.MemoryStream]$Stream, [int]$Length) {
        if ($Length -lt 0x80) {
            $Stream.WriteByte([byte]$Length)
        } elseif ($Length -lt 0x100) {
            $Stream.WriteByte(0x81)
            $Stream.WriteByte([byte]$Length)
        } else {
            $Stream.WriteByte(0x82)
            $Stream.WriteByte([byte]($Length -shr 8))
            $Stream.WriteByte([byte]($Length -band 0xFF))
        }
    }

    function Write-DerElement([System.IO.MemoryStream]$Stream, [byte]$Tag, [byte[]]$Value) {
        $Stream.WriteByte($Tag)
        Write-DerLength $Stream $Value.Length
        $Stream.Write($Value, 0, $Value.Length)
    }

    function ConvertTo-DerInteger([byte[]]$BigEndianBytes) {
        # Strip leading zeros, then prepend 0x00 if the high bit would be set
        # (DER integers are signed two's complement).
        $i = 0
        while ($i -lt ($BigEndianBytes.Length - 1) -and $BigEndianBytes[$i] -eq 0) { $i++ }
        $trimmed = $BigEndianBytes[$i..($BigEndianBytes.Length - 1)]
        if ($trimmed[0] -band 0x80) {
            return ,([byte]0x00) + $trimmed
        }
        return ,$trimmed
    }

    $params = $Rsa.ExportParameters($true)

    # Build PKCS#1 RSAPrivateKey
    $pkcs1 = [System.IO.MemoryStream]::new()
    $pkcs1Body = [System.IO.MemoryStream]::new()
    Write-DerElement $pkcs1Body 0x02 ([byte[]]@(0x00))                                  # version
    Write-DerElement $pkcs1Body 0x02 (ConvertTo-DerInteger $params.Modulus)             # n
    Write-DerElement $pkcs1Body 0x02 (ConvertTo-DerInteger $params.Exponent)            # e
    Write-DerElement $pkcs1Body 0x02 (ConvertTo-DerInteger $params.D)                   # d
    Write-DerElement $pkcs1Body 0x02 (ConvertTo-DerInteger $params.P)                   # p
    Write-DerElement $pkcs1Body 0x02 (ConvertTo-DerInteger $params.Q)                   # q
    Write-DerElement $pkcs1Body 0x02 (ConvertTo-DerInteger $params.DP)                  # d mod (p-1)
    Write-DerElement $pkcs1Body 0x02 (ConvertTo-DerInteger $params.DQ)                  # d mod (q-1)
    Write-DerElement $pkcs1Body 0x02 (ConvertTo-DerInteger $params.InverseQ)            # q^-1 mod p
    $pkcs1BodyBytes = $pkcs1Body.ToArray()
    Write-DerElement $pkcs1 0x30 $pkcs1BodyBytes                                        # SEQUENCE

    # Build AlgorithmIdentifier: rsaEncryption OID (1.2.840.113549.1.1.1) + NULL
    $rsaOid = [byte[]]@(0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01)
    $algId = [System.IO.MemoryStream]::new()
    $algIdBody = [System.IO.MemoryStream]::new()
    Write-DerElement $algIdBody 0x06 $rsaOid                                            # OID
    Write-DerElement $algIdBody 0x05 ([byte[]]@())                                      # NULL
    $algIdBodyBytes = $algIdBody.ToArray()
    Write-DerElement $algId 0x30 $algIdBodyBytes                                        # SEQUENCE

    # Build PrivateKeyInfo
    $pkcs8Body = [System.IO.MemoryStream]::new()
    Write-DerElement $pkcs8Body 0x02 ([byte[]]@(0x00))                                  # version
    $pkcs8Body.Write($algId.ToArray(), 0, $algId.Length)                                # algorithm
    Write-DerElement $pkcs8Body 0x04 $pkcs1.ToArray()                                   # OCTET STRING
    $pkcs8 = [System.IO.MemoryStream]::new()
    Write-DerElement $pkcs8 0x30 $pkcs8Body.ToArray()                                   # SEQUENCE

    return $pkcs8.ToArray()
}
