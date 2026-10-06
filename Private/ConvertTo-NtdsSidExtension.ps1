function ConvertTo-NtdsSidExtension {
    <#
        .SYNOPSIS
        Builds the szOID_NTDS_CA_SECURITY_EXT extension value for a given SID.

        .DESCRIPTION
        Encodes the NTDS CA security extension (OID 1.3.6.1.4.1.311.25.2) value bytes.
        This extension carries the target account's objectSid so the CA embeds it in the
        issued certificate, enabling strong certificate-to-account mapping on Server 2025
        KDCs (KB5014754).

        The value is a DER-encoded structure (matching Certify's EncodeSidExtension):

            ExtensionValue ::= SEQUENCE {                -- OtherName wrap
                type-id    OBJECT IDENTIFIER (1.3.6.1.4.1.311.25.2.1 -- szOID_NTDS_OBJECTSID),
                value      [0] OCTET STRING (ASCII SID string, e.g. "S-1-5-21-...-500")
            }

        Specifically the bytes are (Certify EncodeSidExtension layout):
            SEQUENCE {
              [0] EXPLICIT {  -- context tag 0, constructed (OtherName content, no inner SEQUENCE)
                OID 1.3.6.1.4.1.311.25.2.1,
                [0] EXPLICIT { OCTET STRING (sid ascii) }
              }
            }

        .PARAMETER Sid
        The SID string of the target account (e.g. 'S-1-5-21-...-500').

        .OUTPUTS
        System.Byte[] — DER bytes for the X509Extension RawData.

        .NOTES
        Format reference: MS-WCCE szOID_NTDS_CA_SECURITY_EXT. Matches Certify's
        CertSidExtension.EncodeSidExtension() output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^S-\d+-\d+(-\d+)+$')]
        [string]$Sid
    )

    $sidBytes = [System.Text.Encoding]::ASCII.GetBytes($Sid)

    # Minimal DER writer helpers
    function Write-Len([int]$len) {
        if ($len -lt 0x80) { return [byte[]]@([byte]$len) }
        if ($len -lt 0x100) { return [byte[]]@(0x81, [byte]$len) }
        return [byte[]]@(0x82, [byte]($len -shr 8), [byte]($len -band 0xFF))
    }
    function Add-Element([System.Collections.Generic.List[byte]]$buf, [byte]$tag, [byte[]]$val) {
        $buf.Add($tag)
        $buf.AddRange([byte[]](Write-Len $val.Length))
        $buf.AddRange([byte[]]$val)
    }

    # OID 1.3.6.1.4.1.311.25.2.1 encoded bytes
    $oidBytes = [byte[]]@(0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x19, 0x02, 0x01)

    # Inner OCTET STRING wrapping the SID ascii:  04 <len> <sid>
    $sidOctet = [System.Collections.Generic.List[byte]]::new()
    Add-Element $sidOctet 0x04 $sidBytes

    # [0] EXPLICIT around the octet string:  A0 <len> <sidOctet>
    $explicitOctet = [System.Collections.Generic.List[byte]]::new()
    Add-Element $explicitOctet 0xA0 $sidOctet.ToArray()

    # [0] EXPLICIT OtherName content: OID (type-id) + [0] EXPLICIT OCTET STRING (value).
    # Certify's EncodeSidExtension puts the OID and value DIRECTLY inside the outer [0],
    # with no intermediate SEQUENCE. (A previous version wrapped them in 0x30 SEQUENCE,
    # producing a 2-byte-longer value the KDC's strong-mapping parser rejected with
    # KRB-ERROR 60.)
    $otherNameContent = [System.Collections.Generic.List[byte]]::new()
    Add-Element $otherNameContent 0x06 $oidBytes
    $otherNameContent.AddRange([byte[]]$explicitOctet.ToArray())

    # Outer [0] EXPLICIT wraps the OtherName content directly.
    $outerExplicit = [System.Collections.Generic.List[byte]]::new()
    Add-Element $outerExplicit 0xA0 $otherNameContent.ToArray()

    # Outer SEQUENCE wrapping the OtherName
    $outerSeq = [System.Collections.Generic.List[byte]]::new()
    Add-Element $outerSeq 0x30 $outerExplicit.ToArray()

    return $outerSeq.ToArray()
}
