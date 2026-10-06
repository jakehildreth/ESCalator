<#
    ESCalator addition (not upstream PSPkinit): a correct big-integer ModPow for
    Windows PowerShell 5.1 / .NET Framework 4.8.1.

    System.Numerics.BigInteger.ModPow returns wrong answers on NetFX 4.8.1 (known
    NetFX bug), which breaks the PKINIT MODP Diffie-Hellman exchange under 5.1.
    The custom little-endian big-integer below (Knuth Algorithm D division +
    square-and-multiply) is ported from ESCalator's abandoned embedded-C# PKINIT
    prototype and produces correct results on both NetFX and .NET (Core).

    Loads ESCalator.Pkinit.DhBigInteger via Add-Type once per session.
#>

if (-not ([System.Management.Automation.PSTypeName]'ESCalator.Pkinit.DhBigInteger').Type) {
    Add-Type -TypeDefinition @'
using System;

namespace ESCalator.Pkinit
{
    // Minimal big-integer: unsigned, little-endian uint[] (data[0] = least significant).
    // Only what PKINIT DH needs: construction from big-endian bytes, ToBigEndianBytes,
    // Compare/Subtract/Multiply/Divide(Knuth D)/Mod/ModMultiply/ModPow.
    public sealed class DhBigInteger
    {
        private uint[] _data;
        private int _length;

        public DhBigInteger(byte[] bigEndianBytes)
        {
            if (bigEndianBytes == null || bigEndianBytes.Length == 0)
            {
                _data = new uint[1];
                _length = 1;
                return;
            }
            int len = (bigEndianBytes.Length + 3) / 4;
            _data = new uint[len];
            for (int i = 0; i < bigEndianBytes.Length; i++)
            {
                int byteIndex = bigEndianBytes.Length - 1 - i;
                _data[i / 4] |= (uint)bigEndianBytes[byteIndex] << ((i % 4) * 8);
            }
            _length = len;
            Normalize();
        }

        private DhBigInteger(uint[] data, int length)
        {
            _data = data;
            _length = length;
            Normalize();
        }

        public static DhBigInteger Zero { get { return new DhBigInteger(new byte[1]); } }
        public static DhBigInteger One { get { return new DhBigInteger(new byte[] { 1 }); } }
        public bool IsZero { get { return _length == 1 && _data[0] == 0; } }

        private void Normalize()
        {
            while (_length > 1 && _data[_length - 1] == 0) _length--;
        }

        public int BitLength
        {
            get
            {
                if (IsZero) return 0;
                uint top = _data[_length - 1];
                int bits = (_length - 1) * 32;
                while (top != 0) { bits++; top >>= 1; }
                return bits;
            }
        }

        public bool TestBit(int bit)
        {
            int word = bit / 32;
            if (word >= _length) return false;
            return (_data[word] & (1u << (bit % 32))) != 0;
        }

        public byte[] ToBigEndianBytes()
        {
            if (IsZero) return new byte[1];
            int bits = BitLength;
            int numBytes = (bits + 7) / 8;
            byte[] result = new byte[numBytes];
            for (int i = 0; i < numBytes; i++)
            {
                int wordIndex = i / 4;
                int shift = (i % 4) * 8;
                uint w = wordIndex < _length ? _data[wordIndex] : 0;
                result[numBytes - 1 - i] = (byte)(w >> shift);
            }
            return result;
        }

        public static int Compare(DhBigInteger a, DhBigInteger b)
        {
            if (a._length != b._length) return a._length < b._length ? -1 : 1;
            for (int i = a._length - 1; i >= 0; i--)
            {
                if (a._data[i] != b._data[i]) return a._data[i] < b._data[i] ? -1 : 1;
            }
            return 0;
        }

        public static DhBigInteger Subtract(DhBigInteger a, DhBigInteger b)
        {
            int maxLen = a._length;
            uint[] r = new uint[maxLen];
            long borrow = 0;
            for (int i = 0; i < maxLen; i++)
            {
                long ai = a._data[i];
                long bi = i < b._length ? b._data[i] : 0;
                long diff = ai - bi - borrow;
                if (diff < 0) { diff += (1L << 32); borrow = 1; } else { borrow = 0; }
                r[i] = (uint)diff;
            }
            return new DhBigInteger(r, maxLen);
        }

        public static DhBigInteger Multiply(DhBigInteger a, DhBigInteger b)
        {
            if (a.IsZero || b.IsZero) return Zero;
            uint[] r = new uint[a._length + b._length];
            for (int i = 0; i < a._length; i++)
            {
                ulong carry = 0;
                for (int j = 0; j < b._length; j++)
                {
                    ulong cur = r[i + j] + (ulong)a._data[i] * b._data[j] + carry;
                    r[i + j] = (uint)cur;
                    carry = cur >> 32;
                }
                int k = i + b._length;
                while (carry != 0 && k < r.Length)
                {
                    ulong cur = (ulong)r[k] + carry;
                    r[k] = (uint)cur;
                    carry = cur >> 32;
                    k++;
                }
            }
            return new DhBigInteger(r, r.Length);
        }

        public static void Divide(DhBigInteger dividend, DhBigInteger divisor, out DhBigInteger quotient, out DhBigInteger remainder)
        {
            if (divisor.IsZero) throw new DivideByZeroException();
            if (Compare(dividend, divisor) < 0)
            {
                quotient = Zero;
                remainder = new DhBigInteger(dividend.ToBigEndianBytes());
                return;
            }
            quotient = KnuthDivide(dividend, divisor, out remainder);
        }

        private static DhBigInteger KnuthDivide(DhBigInteger u, DhBigInteger v, out DhBigInteger remainder)
        {
            int n = v._length;
            int m = u._length - n;

            uint topWord = v._data[n - 1];
            int shift = 0;
            while ((topWord & 0x80000000u) == 0) { topWord <<= 1; shift++; }

            uint[] un = new uint[u._length + 1];
            uint[] vn = new uint[n];
            if (shift > 0)
            {
                ulong carry = 0;
                for (int i = 0; i < n; i++)
                {
                    ulong cur = ((ulong)(i < v._length ? v._data[i] : 0) << shift) | carry;
                    vn[i] = (uint)cur;
                    carry = cur >> 32;
                }
                carry = 0;
                for (int i = 0; i < u._length; i++)
                {
                    ulong cur = ((ulong)u._data[i] << shift) | carry;
                    un[i] = (uint)cur;
                    carry = cur >> 32;
                }
                un[u._length] = (uint)carry;
            }
            else
            {
                Array.Copy(v._data, vn, n);
                Array.Copy(u._data, un, u._length);
                un[u._length] = 0;
            }

            uint[] q = new uint[m + 1];

            for (int j = m; j >= 0; j--)
            {
                ulong num = ((ulong)un[j + n] << 32) | un[j + n - 1];
                ulong qhat = num / vn[n - 1];
                ulong rhat = num % vn[n - 1];

                if (n > 1)
                {
                    while (qhat >= (1UL << 32) ||
                           qhat * vn[n - 2] > ((rhat << 32) | un[j + n - 2]))
                    {
                        qhat--;
                        rhat += vn[n - 1];
                        if (rhat >= (1UL << 32)) break;
                    }
                }

                long borrow = 0;
                for (int i = 0; i < n; i++)
                {
                    ulong p = qhat * vn[i];
                    long sub = (long)un[j + i] - borrow - (long)(p & 0xFFFFFFFF);
                    un[j + i] = (uint)sub;
                    borrow = (long)(p >> 32) - (sub >> 32);
                }
                long subTop = (long)un[j + n] - borrow;
                un[j + n] = (uint)subTop;

                if (subTop < 0)
                {
                    qhat--;
                    ulong carry = 0;
                    for (int i = 0; i < n; i++)
                    {
                        ulong cur = (ulong)un[j + i] + vn[i] + carry;
                        un[j + i] = (uint)cur;
                        carry = cur >> 32;
                    }
                    un[j + n] += (uint)carry;
                }

                q[j] = (uint)qhat;
            }

            uint[] remArr = new uint[n];
            if (shift > 0)
            {
                for (int i = 0; i < n; i++)
                {
                    uint lo = un[i] >> shift;
                    uint hi = (i + 1 < un.Length) ? un[i + 1] << (32 - shift) : 0;
                    remArr[i] = lo | hi;
                }
            }
            else
            {
                Array.Copy(un, remArr, n);
            }

            remainder = new DhBigInteger(remArr, n);
            return new DhBigInteger(q, q.Length);
        }

        public static DhBigInteger Mod(DhBigInteger a, DhBigInteger m)
        {
            DhBigInteger q, r;
            Divide(a, m, out q, out r);
            return r;
        }

        public static DhBigInteger ModMultiply(DhBigInteger a, DhBigInteger b, DhBigInteger m)
        {
            return Mod(Multiply(a, b), m);
        }

        public static DhBigInteger ModPow(DhBigInteger b, DhBigInteger exp, DhBigInteger m)
        {
            DhBigInteger result = One;
            DhBigInteger baseVal = Mod(b, m);
            int bits = exp.BitLength;
            for (int i = 0; i < bits; i++)
            {
                if (exp.TestBit(i))
                    result = ModMultiply(result, baseVal, m);
                if (i < bits - 1)
                    baseVal = ModMultiply(baseVal, baseVal, m);
            }
            return result;
        }

        // --- PowerShell-facing byte[] wrapper (avoids exposing BigInteger interop) ---

        // baseBytes/exponentBytes/modulusBytes are UNSIGNED big-endian. Returns UNSIGNED big-endian.
        public static byte[] ModPowBytes(byte[] baseBytes, byte[] exponentBytes, byte[] modulusBytes)
        {
            var b = new DhBigInteger(baseBytes);
            var e = new DhBigInteger(exponentBytes);
            var m = new DhBigInteger(modulusBytes);
            return ModPow(b, e, m).ToBigEndianBytes();
        }
    }
}
'@ -ReferencedAssemblies 'System' -ErrorAction Stop
}
