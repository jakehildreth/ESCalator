// ESCalator PKINIT verify-only implementation
// Embedded C# for Add-Type -TypeDefinition
// Sources: Rubeus (BSD-3-Clause), Kerberos.NET (MIT), Mono BigInteger (MIT)
// No ticket injection, no LSA, no disk. Verify-only.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ESCalator.Pkinit
{
    // ============================================================
    // ASN.1 DER encoding/decoding (port of Rubeus AsnElt)
    // ============================================================

    public class AsnException : Exception
    {
        public AsnException(string message) : base(message) { }
        public AsnException(string message, Exception inner) : base(message, inner) { }
    }

    public class AsnElt
    {
        public const int BOOLEAN = 1;
        public const int INTEGER = 2;
        public const int BIT_STRING = 3;
        public const int OCTET_STRING = 4;
        public const int NULL = 5;
        public const int OBJECT_IDENTIFIER = 6;
        public const int ENUMERATED = 10;
        public const int UTF8String = 12;
        public const int SEQUENCE = 16;
        public const int SET = 17;
        public const int PrintableString = 19;
        public const int IA5String = 22;
        public const int UTCTime = 23;
        public const int GeneralizedTime = 24;

        public const int UNIVERSAL = 0;
        public const int APPLICATION = 1;
        public const int CONTEXT = 2;
        public const int PRIVATE = 3;

        byte[] objBuf;
        int objOff;
        int objLen;
        int valOff;
        int valLen;
        bool hasEncodedHeader;

        AsnElt() { }

        public int TagClass { get; private set; }
        public int TagValue { get; private set; }
        public AsnElt[] Sub { get; private set; }

        public bool Constructed
        {
            get { return Sub != null; }
        }

        public int EncodedLength
        {
            get
            {
                if (objLen >= 0) return objLen;
                int vlen = ValueLength;
                return TagLength(TagValue) + LengthLength(vlen) + vlen;
            }
        }

        public int ValueLength
        {
            get
            {
                if (valLen >= 0) return valLen;
                if (Sub == null) { valLen = 0; return 0; }
                int vlen = 0;
                foreach (AsnElt a in Sub) vlen += a.EncodedLength;
                valLen = vlen;
                return vlen;
            }
        }

        public byte[] GetValue(out int off, out int len)
        {
            if (objBuf != null)
            {
                off = valOff;
                len = valLen;
                return objBuf;
            }
            // compute from subs
            int vlen = ValueLength;
            byte[] buf = new byte[vlen];
            int pos = 0;
            foreach (AsnElt a in Sub)
            {
                int elen = a.EncodedLength;
                a.Encode(buf, pos);
                pos += elen;
            }
            off = 0;
            len = vlen;
            return buf;
        }

        public byte[] CopyValue()
        {
            int off, len;
            byte[] buf = GetValue(out off, out len);
            byte[] r = new byte[len];
            Array.Copy(buf, off, r, 0, len);
            return r;
        }

        public void CheckConstructed()
        {
            if (!Constructed) throw new AsnException("not constructed");
        }

        public void CheckPrimitive()
        {
            if (Constructed) throw new AsnException("not primitive");
        }

        public AsnElt GetSub(int n)
        {
            CheckConstructed();
            if (n < 0 || n >= Sub.Length) throw new AsnException("no such sub-object: n=" + n);
            return Sub[n];
        }

        public void CheckTag(int tv) { CheckTag(UNIVERSAL, tv); }

        public void CheckTag(int tc, int tv)
        {
            if (TagClass != tc || TagValue != tv)
                throw new AsnException("unexpected tag: " + TagString);
        }

        public string TagString
        {
            get { return TagToString(TagClass, TagValue); }
        }

        static string TagToString(int tc, int tv)
        {
            switch (tc)
            {
                case UNIVERSAL: break;
                case APPLICATION: return "APPLICATION:" + tv;
                case CONTEXT: return "CONTEXT:" + tv;
                case PRIVATE: return "PRIVATE:" + tv;
                default: return String.Format("INVALID:{0}/{1}", tc, tv);
            }
            switch (tv)
            {
                case BOOLEAN: return "BOOLEAN";
                case INTEGER: return "INTEGER";
                case BIT_STRING: return "BIT_STRING";
                case OCTET_STRING: return "OCTET_STRING";
                case NULL: return "NULL";
                case OBJECT_IDENTIFIER: return "OBJECT_IDENTIFIER";
                case ENUMERATED: return "ENUMERATED";
                case UTF8String: return "UTF8String";
                case SEQUENCE: return "SEQUENCE";
                case SET: return "SET";
                case PrintableString: return "PrintableString";
                case IA5String: return "IA5String";
                case UTCTime: return "UTCTime";
                case GeneralizedTime: return "GeneralizedTime";
                default: return "UNIVERSAL:" + tv;
            }
        }

        static int TagLength(int tv)
        {
            if (tv <= 0x1F) return 1;
            int z = 1;
            while (tv > 0) { z++; tv >>= 7; }
            return z;
        }

        static int LengthLength(int len)
        {
            if (len < 0x80) return 1;
            int z = 1;
            while (len > 0) { z++; len >>= 8; }
            return z;
        }

        public static AsnElt Decode(byte[] buf)
        {
            return Decode(buf, 0, buf.Length, true);
        }

        public static AsnElt Decode(byte[] buf, int off, int len)
        {
            return Decode(buf, off, len, true);
        }

        public static AsnElt Decode(byte[] buf, bool exactLength)
        {
            return Decode(buf, 0, buf.Length, exactLength);
        }

        public static AsnElt Decode(byte[] buf, int off, int len, bool exactLength)
        {
            int tc, tv, valOff, valLen, objLen;
            bool cons;
            objLen = Decode(buf, off, len, out tc, out tv, out cons, out valOff, out valLen);
            if (exactLength && objLen != len) throw new AsnException("trailing garbage");
            byte[] nbuf = new byte[objLen];
            Array.Copy(buf, off, nbuf, 0, objLen);
            return DecodeNoCopy(nbuf, 0, objLen);
        }

        static AsnElt DecodeNoCopy(byte[] buf, int off, int len)
        {
            int tc, tv, valOff, valLen, objLen;
            bool cons;
            objLen = Decode(buf, off, len, out tc, out tv, out cons, out valOff, out valLen);
            AsnElt a = new AsnElt();
            a.TagClass = tc;
            a.TagValue = tv;
            a.objBuf = buf;
            a.objOff = off;
            a.objLen = objLen;
            a.valOff = valOff;
            a.valLen = valLen;
            a.hasEncodedHeader = true;
            if (cons)
            {
                List<AsnElt> subs = new List<AsnElt>();
                off = valOff;
                int lim = valOff + valLen;
                while (off < lim)
                {
                    AsnElt b = DecodeNoCopy(buf, off, lim - off);
                    off += b.objLen;
                    subs.Add(b);
                }
                a.Sub = subs.ToArray();
            }
            else
            {
                a.Sub = null;
            }
            return a;
        }

        static int Decode(byte[] buf, int off, int maxLen,
            out int tc, out int tv, out bool cons,
            out int valOff, out int valLen)
        {
            int lim = off + maxLen;
            int orig = off;

            CheckOff(off, lim);
            tv = buf[off++];
            cons = (tv & 0x20) != 0;
            tc = tv >> 6;
            tv &= 0x1F;
            if (tv == 0x1F)
            {
                tv = 0;
                for (;;)
                {
                    CheckOff(off, lim);
                    int c = buf[off++];
                    if (tv > 0xFFFFFF) throw new AsnException("tag value overflow");
                    tv = (tv << 7) | (c & 0x7F);
                    if ((c & 0x80) == 0) break;
                }
            }

            CheckOff(off, lim);
            int vlen = buf[off++];
            if (vlen == 0x80)
            {
                vlen = -1;
                if (!cons) throw new AsnException("indefinite length but not constructed");
            }
            else if (vlen > 0x80)
            {
                int lenlen = vlen - 0x80;
                CheckOff(off + lenlen - 1, lim);
                vlen = 0;
                while (lenlen-- > 0)
                {
                    if (vlen > 0x7FFFFF) throw new AsnException("length overflow");
                    vlen = (vlen << 8) + buf[off++];
                }
            }

            valOff = off;

            if (vlen < 0)
            {
                for (;;)
                {
                    int tc2, tv2, valOff2, valLen2;
                    bool cons2;
                    int slen;
                    slen = Decode(buf, off, lim - off, out tc2, out tv2, out cons2, out valOff2, out valLen2);
                    if (tc2 == 0 && tv2 == 0)
                    {
                        if (cons2 || valLen2 != 0) throw new AsnException("invalid null tag");
                        valLen = off - valOff;
                        off += slen;
                        break;
                    }
                    else
                    {
                        off += slen;
                    }
                }
            }
            else
            {
                if (vlen > (lim - off)) throw new AsnException("value overflow");
                off += vlen;
                valLen = off - valOff;
            }

            return off - orig;
        }

        static void CheckOff(int off, int lim)
        {
            if (off >= lim) throw new AsnException("offset overflow");
        }

        public byte[] Encode()
        {
            byte[] r = new byte[EncodedLength];
            Encode(r, 0);
            return r;
        }

        public int Encode(byte[] dst, int off)
        {
            return Encode(0, Int32.MaxValue, dst, off);
        }

        int Encode(int start, int end, byte[] dst, int dstOff)
        {
            if (hasEncodedHeader)
            {
                int from = objOff + Math.Max(0, start);
                int to = objOff + Math.Min(objLen, end);
                int len = to - from;
                if (len > 0)
                {
                    Array.Copy(objBuf, from, dst, dstOff, len);
                    return len;
                }
                return 0;
            }

            int off = 0;
            int fb = (TagClass << 6) + (Constructed ? 0x20 : 0x00);
            if (TagValue < 0x1F)
            {
                fb |= (TagValue & 0x1F);
                if (start <= off && off < end) dst[dstOff++] = (byte)fb;
                off++;
            }
            else
            {
                fb |= 0x1F;
                if (start <= off && off < end) dst[dstOff++] = (byte)fb;
                off++;
                int k = 0;
                for (int v = TagValue; v > 0; v >>= 7, k += 7) ;
                while (k > 0)
                {
                    k -= 7;
                    int v = (TagValue >> k) & 0x7F;
                    if (k != 0) v |= 0x80;
                    if (start <= off && off < end) dst[dstOff++] = (byte)v;
                    off++;
                }
            }

            int vlen = ValueLength;
            if (vlen < 0x80)
            {
                if (start <= off && off < end) dst[dstOff++] = (byte)vlen;
                off++;
            }
            else
            {
                int k = 0;
                for (int v = vlen; v > 0; v >>= 8, k += 8) ;
                if (start <= off && off < end) dst[dstOff++] = (byte)(0x80 + (k >> 3));
                off++;
                while (k > 0)
                {
                    k -= 8;
                    if (start <= off && off < end) dst[dstOff++] = (byte)(vlen >> k);
                    off++;
                }
            }

            if (objBuf != null)
            {
                Array.Copy(objBuf, valOff, dst, dstOff, vlen);
                off += vlen;
            }
            else
            {
                foreach (AsnElt a in Sub)
                {
                    int slen = a.EncodedLength;
                    a.Encode(dst, dstOff);
                    dstOff += slen;
                    off += slen;
                }
            }

            return off;
        }

        public long GetInteger()
        {
            CheckPrimitive();
            return GetInteger(0, Int64.MaxValue);
        }

        public long GetInteger(long min, long max)
        {
            CheckPrimitive();
            int off, len;
            byte[] buf = GetValue(out off, out len);
            if (len == 0) throw new AsnException("invalid integer (empty)");
            long v = 0;
            bool neg = buf[off] >= 0x80;
            if (neg) v = -1;
            for (int i = 0; i < len; i++)
            {
                if (v >= 0 && v > ((Int64.MaxValue - 0xFF) >> 8))
                    throw new AsnException("integer overflow");
                v = (v << 8) + buf[off + i];
            }
            if (neg) v += 1;
            if (v < min || v > max)
                throw new AsnException("integer out of allowed range");
            return v;
        }

        public byte[] GetOctetString()
        {
            CheckTag(OCTET_STRING);
            CheckPrimitive();
            return CopyValue();
        }

        public byte[] GetBitString()
        {
            return GetBitString(0);
        }

        public byte[] GetBitString(int unusedBits)
        {
            CheckTag(BIT_STRING);
            CheckPrimitive();
            int off, len;
            byte[] buf = GetValue(out off, out len);
            if (len < 1) throw new AsnException("empty BIT STRING");
            if (buf[off] != unusedBits)
                throw new AsnException("unexpected number of unused bits");
            byte[] r = new byte[len - 1];
            Array.Copy(buf, off + 1, r, 0, len - 1);
            return r;
        }

        public DateTime GetTime()
        {
            CheckPrimitive();
            int off, len;
            byte[] buf = GetValue(out off, out len);
            string s = DecodeMono(buf, off, len);
            int type = TagValue;
            if (type == UTCTime) return GetTimeUtc(s);
            if (type == GeneralizedTime) return GetTimeGen(s);
            throw new AsnException("GetTime: not a time");
        }

        static DateTime GetTimeUtc(string s)
        {
            int year = Dec2(s, 0);
            if (year < 50) year += 2000; else year += 1900;
            return ParseTime(year, Dec2(s, 2), Dec2(s, 4), Dec2(s, 6), Dec2(s, 8), Dec2(s, 10));
        }

        static DateTime GetTimeGen(string s)
        {
            int year = Dec2(s, 0) * 100 + Dec2(s, 2);
            return ParseTime(year, Dec2(s, 4), Dec2(s, 6), Dec2(s, 8), Dec2(s, 10), Dec2(s, 12));
        }

        static DateTime ParseTime(int year, int month, int day, int hour, int min, int sec)
        {
            return new DateTime(year, month, day, hour, min, sec, DateTimeKind.Utc);
        }

        static int Dec2(string s, int off)
        {
            if (off < 0 || off >= s.Length - 1) throw new AsnException("invalid time string");
            return 10 * (s[off] - '0') + (s[off + 1] - '0');
        }

        static string DecodeMono(byte[] buf, int off, int len)
        {
            char[] tc = new char[len];
            for (int i = 0; i < len; i++) tc[i] = (char)buf[off + i];
            return new string(tc);
        }

        public string GetString()
        {
            CheckPrimitive();
            int off, len;
            byte[] buf = GetValue(out off, out len);
            switch (TagValue)
            {
                case NumericString:
                case PrintableString:
                case IA5String:
                case UTCTime:
                case GeneralizedTime:
                    return DecodeMono(buf, off, len);
                case UTF8String:
                    return Encoding.UTF8.GetString(buf, off, len);
                default:
                    throw new AsnException("GetString: unsupported type " + TagString);
            }
        }

        public const int NumericString = 18;

        // Factory methods

        public static AsnElt MakePrimitive(int tagValue, byte[] val)
        {
            return MakePrimitive(UNIVERSAL, tagValue, val, 0, val.Length);
        }

        public static AsnElt MakePrimitive(int tagClass, int tagValue, byte[] val)
        {
            return MakePrimitive(tagClass, tagValue, val, 0, val.Length);
        }

        public static AsnElt MakePrimitive(int tagClass, int tagValue, byte[] val, int off, int len)
        {
            byte[] nval = new byte[len];
            Array.Copy(val, off, nval, 0, len);
            return MakePrimitiveInner(tagClass, tagValue, nval, 0, len);
        }

        static AsnElt MakePrimitiveInner(int tagValue, byte[] val)
        {
            return MakePrimitiveInner(UNIVERSAL, tagValue, val, 0, val.Length);
        }

        static AsnElt MakePrimitiveInner(int tagClass, int tagValue, byte[] val, int off, int len)
        {
            AsnElt a = new AsnElt();
            a.objBuf = new byte[len];
            Array.Copy(val, off, a.objBuf, 0, len);
            a.objOff = 0;
            a.objLen = -1;
            a.valOff = 0;
            a.valLen = len;
            a.hasEncodedHeader = false;
            if (tagClass < 0 || tagClass > 3) throw new AsnException("invalid tag class");
            if (tagValue < 0) throw new AsnException("invalid tag value");
            a.TagClass = tagClass;
            a.TagValue = tagValue;
            a.Sub = null;
            return a;
        }

        public static AsnElt MakeInteger(long x)
        {
            if (x >= 0) return MakeInteger((ulong)x);
            int k = 1;
            for (long w = x; w <= -(long)0x80; w >>= 8) k++;
            byte[] v = new byte[k];
            for (long w = x; k > 0; w >>= 8) v[--k] = (byte)w;
            return MakePrimitiveInner(INTEGER, v);
        }

        public static AsnElt MakeInteger(ulong x)
        {
            int k = 1;
            for (ulong w = x; w >= 0x80; w >>= 8) k++;
            byte[] v = new byte[k];
            for (ulong w = x; k > 0; w >>= 8) v[--k] = (byte)w;
            return MakePrimitiveInner(INTEGER, v);
        }

        public static AsnElt MakeInteger(byte[] x)
        {
            int xLen = x.Length;
            int j = 0;
            while (j < xLen && x[j] == 0x00) j++;
            if (j == xLen) return MakePrimitiveInner(INTEGER, new byte[] { 0x00 });
            byte[] v;
            if (x[j] < 0x80)
            {
                v = new byte[xLen - j];
                Array.Copy(x, j, v, 0, v.Length);
            }
            else
            {
                v = new byte[1 + xLen - j];
                Array.Copy(x, j, v, 1, v.Length - 1);
            }
            return MakePrimitiveInner(INTEGER, v);
        }

        public static AsnElt MakeBlob(byte[] buf)
        {
            return MakeBlob(buf, 0, buf.Length);
        }

        public static AsnElt MakeBlob(byte[] buf, int off, int len)
        {
            return MakePrimitive(UNIVERSAL, OCTET_STRING, buf, off, len);
        }

        public static AsnElt Make(int tagValue, params AsnElt[] subs)
        {
            return Make(UNIVERSAL, tagValue, subs);
        }

        public static AsnElt Make(int tagClass, int tagValue, params AsnElt[] subs)
        {
            AsnElt a = new AsnElt();
            a.objBuf = null;
            a.objOff = 0;
            a.objLen = -1;
            a.valOff = 0;
            a.valLen = -1;
            a.hasEncodedHeader = false;
            if (tagClass < 0 || tagClass > 3) throw new AsnException("invalid tag class");
            if (tagValue < 0) throw new AsnException("invalid tag value");
            a.TagClass = tagClass;
            a.TagValue = tagValue;
            if (subs == null) a.Sub = new AsnElt[0];
            else
            {
                a.Sub = new AsnElt[subs.Length];
                Array.Copy(subs, 0, a.Sub, 0, subs.Length);
            }
            return a;
        }

        public static AsnElt MakeExplicit(int tagClass, int tagValue, AsnElt x)
        {
            return Make(tagClass, tagValue, x);
        }

        public static AsnElt MakeExplicit(int tagValue, AsnElt x)
        {
            return Make(CONTEXT, tagValue, x);
        }

        public static AsnElt MakeImplicit(int tagClass, int tagValue, AsnElt x)
        {
            if (x.Constructed) return Make(tagClass, tagValue, x.Sub);
            AsnElt a = new AsnElt();
            a.objBuf = x.GetValue(out a.valOff, out a.valLen);
            a.objOff = 0;
            a.objLen = -1;
            a.hasEncodedHeader = false;
            a.TagClass = tagClass;
            a.TagValue = tagValue;
            a.Sub = null;
            return a;
        }

        public static AsnElt MakeString(int type, string str)
        {
            byte[] buf;
            switch (type)
            {
                case NumericString:
                case PrintableString:
                case UTCTime:
                case GeneralizedTime:
                case IA5String:
                case 27: // GeneralString
                    buf = EncodeMono(str);
                    break;
                case UTF8String:
                    buf = Encoding.UTF8.GetBytes(str);
                    break;
                default:
                    throw new AsnException("unsupported string type: " + type);
            }
            return MakePrimitiveInner(type, buf);
        }

        static byte[] EncodeMono(string str)
        {
            byte[] r = new byte[str.Length];
            for (int i = 0; i < str.Length; i++) r[i] = (byte)str[i];
            return r;
        }

        public static AsnElt MakeOID(string str)
        {
            List<long> r = new List<long>();
            int n = str.Length;
            long x = -1;
            for (int i = 0; i < n; i++)
            {
                int c = str[i];
                if (c == '.')
                {
                    if (x < 0) throw new AsnException("invalid OID");
                    r.Add(x);
                    x = -1;
                    continue;
                }
                if (c < '0' || c > '9') throw new AsnException("invalid OID char");
                if (x < 0) x = 0;
                else if (x > ((Int64.MaxValue - 9) / 10)) throw new AsnException("OID overflow");
                x = x * 10 + (c - '0');
            }
            if (x < 0) throw new AsnException("invalid OID");
            r.Add(x);
            if (r.Count < 2) throw new AsnException("OID too short");
            if (r[0] > 2 || r[1] > 40) throw new AsnException("OID out of range");

            MemoryStream ms = new MemoryStream();
            ms.WriteByte((byte)(40 * (int)r[0] + (int)r[1]));
            for (int i = 2; i < r.Count; i++)
            {
                long v = r[i];
                if (v < 0x80) { ms.WriteByte((byte)v); continue; }
                int k = -7;
                for (long w = v; w != 0; w >>= 7, k += 7) ;
                ms.WriteByte((byte)(0x80 + (int)(v >> k)));
                for (k -= 7; k >= 0; k -= 7)
                {
                    int z = (int)(v >> k) & 0x7F;
                    if (k > 0) z |= 0x80;
                    ms.WriteByte((byte)z);
                }
            }
            byte[] buf = ms.ToArray();
            return MakePrimitiveInner(UNIVERSAL, OBJECT_IDENTIFIER, buf, 0, buf.Length);
        }

        public static AsnElt MakeBitString(byte[] buf)
        {
            return MakeBitString(buf, 0, buf.Length);
        }

        public static AsnElt MakeBitString(byte[] buf, int off, int len)
        {
            byte[] tmp = new byte[len + 1];
            Array.Copy(buf, off, tmp, 1, len);
            return MakePrimitiveInner(BIT_STRING, tmp);
        }
    }
}

namespace ESCalator.Pkinit
{
    // ============================================================
    // Minimal BigInteger for Diffie-Hellman (unsigned, big-endian)
    // Replaces Mono.BigInteger; schoolbook arithmetic is fast enough
    // for a single 2048-bit DH exchange (<100ms).
    // ============================================================

    internal class DhBigInteger
    {
        // Little-endian uint array internally (data[0] = least significant)
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
            // Requires a >= b
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

        // Long division via Knuth Algorithm D: computes quotient and remainder
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

        private DhBigInteger ShiftLeft1()
        {
            uint[] r = new uint[_length + 1];
            uint carry = 0;
            for (int i = 0; i < _length; i++)
            {
                r[i] = (_data[i] << 1) | carry;
                carry = _data[i] >> 31;
            }
            if (carry != 0) { r[_length] = carry; return new DhBigInteger(r, _length + 1); }
            return new DhBigInteger(r, _length);
        }

        private DhBigInteger OrOne()
        {
            _data[0] |= 1;
            return this;
        }

        // Knuth Algorithm D (division of multi-word numbers)
        private static DhBigInteger KnuthDivide(DhBigInteger u, DhBigInteger v, out DhBigInteger remainder)
        {
            int n = v._length;
            int m = u._length - n;

            // Normalize: compute shift so divisor's top word has its high bit set
            uint topWord = v._data[n - 1];
            int shift = 0;
            while ((topWord & 0x80000000u) == 0) { topWord <<= 1; shift++; }

            // Allocate normalized arrays
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

                // Multiply and subtract
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
                    // Add back
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

            // Denormalize remainder: shift right by 'shift', pulling bits from the next word
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
            // Square-and-multiply, right-to-left over exponent bits
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
    }

    // ============================================================
    // Diffie-Hellman (Oakley Group 14, RFC 3526)
    // Port of Kerberos.NET ManagedDiffieHellman — MODP only
    // ============================================================

    internal static class OakleyGroup14
    {
        public static readonly byte[] Prime = new byte[]
        {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
            0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
            0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
            0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
            0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
            0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
            0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
            0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
            0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
            0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
            0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
            0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
            0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
            0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
            0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
            0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        public static readonly byte[] Generator = new byte[] { 0x02 };
    }

    internal class DhKeyExchange
    {
        private readonly DhBigInteger _prime;
        private readonly DhBigInteger _generator;
        private readonly DhBigInteger _privateExponent;
        private readonly DhBigInteger _publicValue;

        public DhKeyExchange()
        {
            _prime = new DhBigInteger(OakleyGroup14.Prime);
            _generator = new DhBigInteger(OakleyGroup14.Generator);

            // Random private exponent: 2048 random bits, then mod prime
            byte[] privBytes = new byte[OakleyGroup14.Prime.Length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(privBytes);
            }
            privBytes[0] &= 0x7F; // keep it below prime with high probability
            _privateExponent = new DhBigInteger(privBytes);

            _publicValue = DhBigInteger.ModPow(_generator, _privateExponent, _prime);
        }

        public byte[] PrimeBytes { get { return OakleyGroup14.Prime; } }
        public byte[] GeneratorBytes { get { return OakleyGroup14.Generator; } }
        public byte[] PublicValueBytes { get { return _publicValue.ToBigEndianBytes(); } }

        public byte[] ComputeSharedSecret(byte[] kdcPublicKeyBytes)
        {
            var kdcPublic = new DhBigInteger(kdcPublicKeyBytes);
            var shared = DhBigInteger.ModPow(kdcPublic, _privateExponent, _prime);
            byte[] raw = shared.ToBigEndianBytes();
            // Left-pad to prime length
            int keyLen = OakleyGroup14.Prime.Length;
            if (raw.Length >= keyLen) return raw;
            byte[] padded = new byte[keyLen];
            Array.Copy(raw, 0, padded, keyLen - raw.Length, raw.Length);
            return padded;
        }
    }

    // ============================================================
    // ECDH key agreement (RFC 5349) using inbox ECDiffieHellmanCng.
    // Server 2025 KDCs require ECDH for PKINIT; MODP DH is rejected
    // with KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED (60).
    // ============================================================

    internal class EcdhKeyExchange : IDisposable
    {
        private readonly ECDiffieHellmanCng _ecdh;

        // P-256 (secp256r1) — RFC 5349 mandatory-to-implement
        public EcdhKeyExchange()
        {
            _ecdh = new ECDiffieHellmanCng(256);
        }

        // Uncompressed EC point: 0x04 || X || Y (65 bytes for P-256)
        public byte[] PublicKeyPointBytes
        {
            get
            {
                var p = _ecdh.ExportParameters(false);
                // Uncompressed point: 0x04 || X || Y
                byte[] full = new byte[1 + p.Q.X.Length + p.Q.Y.Length];
                full[0] = 0x04;
                Array.Copy(p.Q.X, 0, full, 1, p.Q.X.Length);
                Array.Copy(p.Q.Y, 0, full, 1 + p.Q.X.Length, p.Q.Y.Length);
                return full;
            }
        }

        // Derive the raw shared secret (x-coordinate of the shared point) per RFC 5349.
        public byte[] ComputeSharedSecret(byte[] kdcPublicPoint)
        {
            // kdcPublicPoint is 0x04 || X || Y; strip the 0x04 for the CNG blob
            int pointLen = kdcPublicPoint.Length - 1;
            byte[] blob = new byte[pointLen + 8];
            blob[0] = 0x45; blob[1] = 0x43; blob[2] = 0x4B; blob[3] = 0x31; // "ECK1" (P-256 public)
            blob[4] = (byte)(pointLen / 2); blob[5] = 0; blob[6] = 0; blob[7] = 0; // cbKey = 32 (per-coordinate)
            Array.Copy(kdcPublicPoint, 1, blob, 8, pointLen);

            using (var kdcKey = ECDiffieHellmanCngPublicKey.FromByteArray(blob, CngKeyBlobFormat.EccPublicBlob))
            {
                // Raw secret agreement = x-coordinate of shared point, big-endian, fixed width.
                return _ecdh.DeriveKeyMaterial(kdcKey);
            }
        }

        public void Dispose()
        {
            if (_ecdh != null) _ecdh.Dispose();
        }
    }
}

namespace ESCalator.Pkinit
{
    // ============================================================
    // Kerberos crypto via Windows cryptdll.dll (CNG-backed)
    // Port of Rubeus Crypto.cs — CDLocateCSystem P/Invoke
    // ============================================================

    internal static class KerberosCrypto
    {
        public const int ETYPE_AES256_CTS_HMAC_SHA1 = 18;
        public const int ETYPE_AES128_CTS_HMAC_SHA1 = 17;
        public const int KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY = 3;

        [DllImport("cryptdll.dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int CDLocateCSystem(int type, out IntPtr pCSystem);

        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_ECRYPT
        {
            private int Type0;
            public int BlockSize;
            private int Type1;
            public int KeySize;
            public int Size;
            private int unk2;
            private int unk3;
            public IntPtr AlgName;
            public IntPtr Initialize;
            public IntPtr Encrypt;
            public IntPtr Decrypt;
            public IntPtr Finish;
            public IntPtr HashPassword;
            private IntPtr RandomKey;
            private IntPtr Control;
            private IntPtr unk0;
            private IntPtr unk1;
            private IntPtr unk2b;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int KERB_ECRYPT_Initialize(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int KERB_ECRYPT_Decrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int KERB_ECRYPT_Finish(ref IntPtr pContext);

        // Decrypt data encrypted with the given etype using the given key and usage.
        // Returns plaintext bytes.
        public static byte[] KerberosDecrypt(int eType, int keyUsage, byte[] key, byte[] data)
        {
            IntPtr pCSystemPtr;
            int status = CDLocateCSystem(eType, out pCSystemPtr);
            if (status != 0)
                throw new System.ComponentModel.Win32Exception(status, "CDLocateCSystem failed");

            KERB_ECRYPT pCSystem = (KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(KERB_ECRYPT));

            var init = (KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(KERB_ECRYPT_Initialize));
            var decrypt = (KERB_ECRYPT_Decrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Decrypt, typeof(KERB_ECRYPT_Decrypt));
            var finish = (KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(KERB_ECRYPT_Finish));

            IntPtr pContext;
            status = init(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new System.ComponentModel.Win32Exception(status, "KERB_ECRYPT Initialize failed");

            int outputSize = data.Length;
            if (data.Length % pCSystem.BlockSize != 0)
                outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);
            outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];

            status = decrypt(pContext, data, data.Length, output, ref outputSize);
            finish(ref pContext);
            if (status != 0)
                throw new System.ComponentModel.Win32Exception(status, "KERB_ECRYPT Decrypt failed");

            byte[] result = new byte[outputSize];
            Array.Copy(output, result, outputSize);
            return result;
        }
    }

    // ============================================================
    // KDC key agreement: SHA1-based kTruncate key derivation
    // Port of Rubeus KDCKeyAgreement.cs
    // ============================================================

    internal class KdcKeyAgreement
    {
        // MODP DH (Oakley Group 14) — Rubeus parity. Server 2022 KDCs accept MODP;
        // the ECDH path was rejected with KRB-ERROR 41 on Server 2025.
        private readonly DhKeyExchange _dh = new DhKeyExchange();

        // MODP public value Y = g^x mod p (big-endian, prime length)
        public byte[] Y { get { return _dh.PublicValueBytes; } }
        public byte[] P { get { return _dh.PrimeBytes; } }
        public byte[] G { get { return _dh.GeneratorBytes; } }

        private static byte[] CalculateIntegrity(byte count, byte[] data)
        {
            byte[] input = new byte[data.Length + 1];
            input[0] = count;
            Buffer.BlockCopy(data, 0, input, 1, data.Length);
            using (SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider())
            {
                return sha1.ComputeHash(input);
            }
        }

        private static byte[] KTruncate(int k, byte[] x)
        {
            byte[] result = new byte[k];
            int count = 0;
            byte[] filler = CalculateIntegrity((byte)count, x);
            int position = 0;
            for (int i = 0; i < k; i++)
            {
                if (position < filler.Length)
                {
                    result[i] = filler[position++];
                }
                else
                {
                    count++;
                    filler = CalculateIntegrity((byte)count, x);
                    position = 0;
                    result[i] = filler[position++];
                }
            }
            return result;
        }

        // Derive the AS-REP decryption key from the KDC's DH public key.
        // clientNonce: empty for the basic flow. serverNonce from PA-PK-AS-REP.
        public byte[] GenerateKey(byte[] kdcPublicKey, byte[] clientNonce, byte[] serverNonce, int size)
        {
            byte[] sharedSecret = _dh.ComputeSharedSecret(kdcPublicKey);
            byte[] x = new byte[sharedSecret.Length + clientNonce.Length + serverNonce.Length];
            Buffer.BlockCopy(sharedSecret, 0, x, 0, sharedSecret.Length);
            Buffer.BlockCopy(clientNonce, 0, x, sharedSecret.Length, clientNonce.Length);
            Buffer.BlockCopy(serverNonce, 0, x, sharedSecret.Length + clientNonce.Length, serverNonce.Length);
            return KTruncate(size, x);
        }
    }

    // ============================================================
    // Kerberos structures (minimal, PKINIT-only)
    // ============================================================

    internal class KrbPrincipalName
    {
        public int NameType;
        public List<string> NameString = new List<string>();

        public AsnElt Encode()
        {
            // Match Rubeus PrincipalName.Encode() nesting exactly:
            // name-type[0] Int32
            AsnElt nameTypeElt = AsnElt.MakeInteger(NameType);
            AsnElt nameTypeSeq = AsnElt.Make(AsnElt.SEQUENCE, nameTypeElt);
            nameTypeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, nameTypeSeq);

            // name-string[1] SEQUENCE OF KerberosString (GeneralString on the wire)
            AsnElt[] strings = new AsnElt[NameString.Count];
            for (int i = 0; i < NameString.Count; i++)
            {
                AsnElt s = AsnElt.MakeString(AsnElt.UTF8String, NameString[i]);
                strings[i] = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, 27, s); // re-tag as GeneralString
            }
            AsnElt stringSeq = AsnElt.Make(AsnElt.SEQUENCE, strings);
            AsnElt stringSeq2 = AsnElt.Make(AsnElt.SEQUENCE, stringSeq);
            stringSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, stringSeq2);

            AsnElt seq = AsnElt.Make(AsnElt.SEQUENCE, nameTypeSeq, stringSeq2);
            AsnElt seq2 = AsnElt.Make(AsnElt.SEQUENCE, seq);
            return seq2;
        }

        public static KrbPrincipalName Parse(AsnElt body)
        {
            var p = new KrbPrincipalName();
            p.NameType = (int)body.Sub[0].Sub[0].GetInteger();
            int count = body.Sub[1].Sub[0].Sub.Length;
            for (int i = 0; i < count; i++)
                p.NameString.Add(body.Sub[1].Sub[0].Sub[i].GetString());
            return p;
        }
    }

    internal class KrbEncryptedData
    {
        public int EType;
        public int Kvno;
        public byte[] Cipher;

        public static KrbEncryptedData Parse(AsnElt body)
        {
            var e = new KrbEncryptedData();
            foreach (AsnElt sub in body.Sub)
            {
                switch (sub.TagValue)
                {
                    case 0: e.EType = (int)sub.Sub[0].GetInteger(); break;
                    case 1: e.Kvno = (int)sub.Sub[0].GetInteger(); break;
                    case 2: e.Cipher = sub.Sub[0].GetOctetString(); break;
                }
            }
            return e;
        }
    }

    internal class KrbTicket
    {
        public int TktVno;
        public string Realm;
        public KrbPrincipalName SName;
        public KrbEncryptedData EncPart;

        public static KrbTicket Parse(AsnElt body)
        {
            // Ticket ::= [APPLICATION 1] SEQUENCE { ... }
            AsnElt seq = body;
            if (body.TagClass == AsnElt.APPLICATION) seq = body.Sub[0];
            var t = new KrbTicket();
            foreach (AsnElt sub in seq.Sub)
            {
                switch (sub.TagValue)
                {
                    case 0: t.TktVno = (int)sub.Sub[0].GetInteger(); break;
                    case 1: t.Realm = sub.Sub[0].GetString(); break;
                    case 2: t.SName = KrbPrincipalName.Parse(sub.Sub[0]); break;
                    case 3: t.EncPart = KrbEncryptedData.Parse(sub.Sub[0]); break;
                }
            }
            return t;
        }
    }

    internal class KrbPaData
    {
        public int Type;
        public byte[] ValueBytes;
        public KrbDHRepInfo DHRepInfo; // only for PK_AS_REP

        public static KrbPaData Parse(AsnElt body)
        {
            var p = new KrbPaData();
            p.Type = (int)body.Sub[0].Sub[0].GetInteger();
            p.ValueBytes = body.Sub[1].Sub[0].GetOctetString();
            if (p.Type == 17) // PK_AS_REP
            {
                AsnElt decoded = AsnElt.Decode(p.ValueBytes);
                // PA-PK-AS-REP ::= CHOICE { dhInfo [0] ..., encKeyPack [1] ... }
                if (decoded.TagClass == AsnElt.CONTEXT && decoded.TagValue == 0)
                    p.DHRepInfo = new KrbDHRepInfo(decoded.Sub[0]);
            }
            return p;
        }
    }

    internal class KrbDHRepInfo
    {
        public byte[] ServerDHNonce;
        public byte[] KdcPublicKey;

        public KrbDHRepInfo(AsnElt asnElt)
        {
            foreach (AsnElt seq in asnElt.Sub)
            {
                switch (seq.TagValue)
                {
                    case 0: // dhSignedData: SignedData CMS containing KDCDHKeyInfo
                        {
                            byte[] dhSignedData = seq.Sub[0].GetOctetString();
                            SignedCms cms = new SignedCms();
                            cms.Decode(dhSignedData);
                            // Parse KDCDHKeyInfo from the CMS content
                            AsnElt keyInfo = AsnElt.Decode(cms.ContentInfo.Content);
                            foreach (AsnElt sub in keyInfo.Sub)
                            {
                                if (sub.TagValue == 0)
                                {
                                    // subjectPublicKey [0] BIT STRING
                                    // ECDH: raw uncompressed EC point (0x04||X||Y) directly.
                                    // MODP DH: DER-encoded INTEGER (legacy path).
                                    byte[] bitString = sub.Sub[0].GetBitString();
                                    if (bitString.Length > 0 && bitString[0] == 0x04)
                                    {
                                        KdcPublicKey = bitString; // ECDH point
                                    }
                                    else
                                    {
                                        AsnElt pubInt = AsnElt.Decode(bitString);
                                        KdcPublicKey = pubInt.CopyValue(); // MODP DH INTEGER
                                    }
                                }
                            }
                            break;
                        }
                    case 1: // serverDHNonce [1] OCTET STRING OPTIONAL
                        ServerDHNonce = seq.Sub[0].GetOctetString();
                        break;
                }
            }
            if (ServerDHNonce == null) ServerDHNonce = new byte[0];
        }
    }

    internal class KrbEncKdcRepPart
    {
        public int KeyType;
        public byte[] KeyValue;
        public uint Nonce;
        public uint Flags;
        public DateTime AuthTime;
        public DateTime StartTime;
        public DateTime EndTime;
        public DateTime RenewTill;
        public string Realm;
        public KrbPrincipalName SName;

        public static KrbEncKdcRepPart Parse(AsnElt body)
        {
            var e = new KrbEncKdcRepPart();
            foreach (AsnElt sub in body.Sub)
            {
                switch (sub.TagValue)
                {
                    case 0: // key [0] EncryptionKey
                        e.KeyType = (int)sub.Sub[0].Sub[0].Sub[0].GetInteger();
                        e.KeyValue = sub.Sub[0].Sub[1].Sub[0].GetOctetString();
                        break;
                    case 2: // nonce [2] UInt32
                        e.Nonce = (uint)sub.Sub[0].GetInteger();
                        break;
                    case 4: // flags [4] TicketFlags (BIT STRING)
                        {
                            byte[] flagBytes = sub.Sub[0].GetBitString();
                            uint f = 0;
                            for (int i = 0; i < flagBytes.Length && i < 4; i++)
                                f |= (uint)flagBytes[i] << (8 * (3 - i));
                            e.Flags = f;
                            break;
                        }
                    case 5: e.AuthTime = sub.Sub[0].GetTime(); break;
                    case 6: e.StartTime = sub.Sub[0].GetTime(); break;
                    case 7: e.EndTime = sub.Sub[0].GetTime(); break;
                    case 8: e.RenewTill = sub.Sub[0].GetTime(); break;
                    case 9: e.Realm = sub.Sub[0].GetString(); break;
                    case 10: e.SName = KrbPrincipalName.Parse(sub.Sub[0]); break;
                }
            }
            return e;
        }
    }

    internal class KrbAsRep
    {
        public List<KrbPaData> PaData = new List<KrbPaData>();
        public string CRealm;
        public KrbPrincipalName CName;
        public KrbTicket Ticket;
        public KrbEncryptedData EncPart;

        public static KrbAsRep Parse(AsnElt asnAsRep)
        {
            // AS-REP ::= [APPLICATION 11] KDC-REP
            if (asnAsRep.TagClass != AsnElt.APPLICATION || asnAsRep.TagValue != 11)
                throw new AsnException("Not an AS-REP");

            AsnElt kdcRep = asnAsRep.Sub[0];
            var rep = new KrbAsRep();
            foreach (AsnElt sub in kdcRep.Sub)
            {
                switch (sub.TagValue)
                {
                    case 0: break; // pvno
                    case 1: break; // msg-type
                    case 2: // padata [2] SEQUENCE OF PA-DATA
                        foreach (AsnElt pa in sub.Sub[0].Sub)
                            rep.PaData.Add(KrbPaData.Parse(pa));
                        break;
                    case 3: rep.CRealm = sub.Sub[0].GetString(); break;
                    case 4: rep.CName = KrbPrincipalName.Parse(sub.Sub[0]); break;
                    case 5: rep.Ticket = KrbTicket.Parse(sub.Sub[0]); break;
                    case 6: rep.EncPart = KrbEncryptedData.Parse(sub.Sub[0]); break;
                }
            }
            return rep;
        }
    }
}

namespace ESCalator.Pkinit
{
    // ============================================================
    // AS-REQ builder with PKINIT pre-auth
    // ============================================================

    internal class KrbKdcReqBody
    {
        public uint KdcOptions;
        public KrbPrincipalName CName;
        public string Realm;
        public KrbPrincipalName SName;
        public DateTime Till;
        public DateTime RTime;         // rtime [6] — Rubeus sets this = till
        public uint Nonce;
        public List<int> ETypes = new List<int>();
        public string NetBiosHostName; // addresses [9] — Rubeus includes this

        public AsnElt Encode()
        {
            // Match Rubeus KDC_REQ_BODY.Encode() exactly.
            List<AsnElt> allNodes = new List<AsnElt>();

            // kdc-options [0] KDCOptions (BIT STRING)
            byte[] kdcOptBytes = BitConverter.GetBytes((uint)KdcOptions);
            if (BitConverter.IsLittleEndian) Array.Reverse(kdcOptBytes);
            AsnElt kdcOptionsAsn = AsnElt.MakeBitString(kdcOptBytes);
            AsnElt kdcOptionsSeq = AsnElt.Make(AsnElt.SEQUENCE, kdcOptionsAsn);
            kdcOptionsSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, kdcOptionsSeq);
            allNodes.Add(kdcOptionsSeq);

            // cname [1] PrincipalName (already double-wrapped by Encode)
            AsnElt cnameElt = CName.Encode();
            cnameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, cnameElt);
            allNodes.Add(cnameElt);

            // realm [2] Realm: UTF8String content re-tagged as GeneralString
            AsnElt realmAsn = AsnElt.MakeString(AsnElt.UTF8String, Realm);
            realmAsn = AsnElt.MakeImplicit(AsnElt.UNIVERSAL, 27, realmAsn);
            AsnElt realmSeq = AsnElt.Make(AsnElt.SEQUENCE, realmAsn);
            realmSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, realmSeq);
            allNodes.Add(realmSeq);

            // sname [3] PrincipalName
            AsnElt snameElt = SName.Encode();
            snameElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3, snameElt);
            allNodes.Add(snameElt);

            // till [5] KerberosTime
            AsnElt tillAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, Till.ToString("yyyyMMddHHmmssZ"));
            AsnElt tillSeq = AsnElt.Make(AsnElt.SEQUENCE, tillAsn);
            tillSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 5, tillSeq);
            allNodes.Add(tillSeq);
            // rtime [6] KerberosTime (Rubeus includes it, set = till)
            if (RTime.Year > 1)
            {
                AsnElt rtimeAsn = AsnElt.MakeString(AsnElt.GeneralizedTime, RTime.ToString("yyyyMMddHHmmssZ"));
                AsnElt rtimeSeq = AsnElt.Make(AsnElt.SEQUENCE, rtimeAsn);
                rtimeSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 6, rtimeSeq);
                allNodes.Add(rtimeSeq);
            }


            // nonce [7] UInt32
            AsnElt nonceAsn = AsnElt.MakeInteger((long)Nonce);
            AsnElt nonceSeq = AsnElt.Make(AsnElt.SEQUENCE, nonceAsn);
            nonceSeq = AsnElt.MakeImplicit(AsnElt.CONTEXT, 7, nonceSeq);
            allNodes.Add(nonceSeq);

            // etype [8] SEQUENCE OF Int32 — double-wrapped
            AsnElt[] etypeElts = new AsnElt[ETypes.Count];
            for (int i = 0; i < ETypes.Count; i++)
                etypeElts[i] = AsnElt.MakeInteger(ETypes[i]);
            AsnElt etypeSeqTotal1 = AsnElt.Make(AsnElt.SEQUENCE, etypeElts);
            AsnElt etypeSeqTotal2 = AsnElt.Make(AsnElt.SEQUENCE, etypeSeqTotal1);
            etypeSeqTotal2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 8, etypeSeqTotal2);
            allNodes.Add(etypeSeqTotal2);

            // addresses [9] HostAddresses: NetBIOS hostname, addr-type 20, padded to 16 bytes
            if (!string.IsNullOrEmpty(NetBiosHostName))
            {
                string nbName = NetBiosHostName.ToUpperInvariant();
                if (nbName.Length > 16) nbName = nbName.Substring(0, 16);
                nbName = nbName.PadRight(16, ' ');
                byte[] nbBytes = Encoding.ASCII.GetBytes(nbName);

                // HostAddress ::= SEQUENCE { addr-type [0] Int32, address [1] OCTET STRING }
                AsnElt addrType = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0,
                    AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeInteger(20)));
                AsnElt addrVal = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                    AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeBlob(nbBytes)));
                AsnElt hostAddr = AsnElt.Make(AsnElt.SEQUENCE, addrType, addrVal);
                AsnElt addrSeq1 = AsnElt.Make(AsnElt.SEQUENCE, hostAddr);
                AsnElt addrSeq2 = AsnElt.Make(AsnElt.SEQUENCE, addrSeq1);
                addrSeq2 = AsnElt.MakeImplicit(AsnElt.CONTEXT, 9, addrSeq2);
                allNodes.Add(addrSeq2);
            }

            return AsnElt.Make(AsnElt.SEQUENCE, allNodes.ToArray());
        }
    }

    internal class KrbPkAuthenticator
    {
        public uint CuSec;
        public DateTime CTime;
        public int Nonce;
        public byte[] PaChecksum;

        public AsnElt Encode()
        {
            return AsnElt.Make(AsnElt.SEQUENCE,
                AsnElt.Make(AsnElt.CONTEXT, 0, AsnElt.MakeInteger(CuSec)),
                AsnElt.Make(AsnElt.CONTEXT, 1, AsnElt.MakeString(AsnElt.GeneralizedTime, CTime.ToString("yyyyMMddHHmmssZ"))),
                AsnElt.Make(AsnElt.CONTEXT, 2, AsnElt.MakeInteger(Nonce)),
                AsnElt.Make(AsnElt.CONTEXT, 3, AsnElt.MakeBlob(PaChecksum))
            );
        }
    }

    internal class KrbAuthPack
    {
        public KrbPkAuthenticator Authenticator;
        public byte[] ClientPublicValue; // DER-encoded DH public key info
        public byte[] ClientDHNonce;
        public byte[][] SupportedCMSTypeOids; // optional; DER OID list for supportedCMSTypes[2]

        public AsnElt Encode()
        {
            var nodes = new System.Collections.Generic.List<AsnElt>
            {
                AsnElt.Make(AsnElt.CONTEXT, 0, Authenticator.Encode()),
                AsnElt.Make(AsnElt.CONTEXT, 1, AsnElt.Decode(ClientPublicValue))
            };
            if (SupportedCMSTypeOids != null && SupportedCMSTypeOids.Length > 0)
            {
                // supportedCMSTypes [2] SEQUENCE OF AlgorithmIdentifier
                AsnElt[] algs = new AsnElt[SupportedCMSTypeOids.Length];
                for (int i = 0; i < SupportedCMSTypeOids.Length; i++)
                    algs[i] = AsnElt.Decode(SupportedCMSTypeOids[i]);
                nodes.Add(AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, AsnElt.Make(AsnElt.SEQUENCE, algs)));
            }
            if (ClientDHNonce != null && ClientDHNonce.Length > 0)
                nodes.Add(AsnElt.Make(AsnElt.CONTEXT, 3, AsnElt.MakeBlob(ClientDHNonce)));
            return AsnElt.Make(AsnElt.SEQUENCE, nodes.ToArray());
        }
    }

    // ============================================================
    // Top-level PKINIT client — verify-only
    // ============================================================

    public class PkinitResult
    {
        public bool Success;
        public string PrincipalName;
        public string Realm;
        public DateTime AuthTime;
        public DateTime StartTime;
        public DateTime EndTime;
        public DateTime RenewTill;
        public uint Flags;
        public int SessionKeyType;
        public byte[] SessionKey;
        public string Error;
    }

    public static class PkinitClient
    {
        // RFC 4556 OID for id-pkinit-authData
        private static readonly Oid IdPkInitAuthData = new Oid("1.3.6.1.5.2.3.1");
        private static readonly Oid DiffieHellmanOid = new Oid("1.2.840.10046.2.1");

        // Build a CMS SignedData for PKINIT (id-pkinit-authData) manually.
        // NetFX 4.7.2/4.8 SignedCms mis-encodes the eContent (Rubeus issue #196);
        // Server 2025 KDCs reject it with KRB_ERR_GENERIC. We build it correctly:
        //   SignedData { version, digestAlgorithms, encapContentInfo{eContentType, [0] OCTET STRING(authPack)}, certificates[0], signerInfos }
        // Includes signed attributes (contentType + messageDigest) like SignedCms, since
        // Microsoft's KDC CMS verifier may require the messageDigest attribute.
        private static byte[] BuildPkinitSignedData(byte[] authPackDer, X509Certificate2 cert)
        {
            Oid oidSignedData = new Oid("1.2.840.113549.1.7.2");
            // Known-good PKINIT clients (PKINITtools, Heimdal, MIT) use SHA-1 CMS digests and
            // SignedData version 3. Match working clients exactly to isolate error 41.
            Oid oidDigest = new Oid("1.3.14.3.2.26"); // sha1
            HashAlgorithmName digestAlgName = HashAlgorithmName.SHA1;
            Oid oidRsaEncryption = new Oid("1.2.840.113549.1.1.1");
            Oid oidContentType = new Oid("1.2.840.113549.1.9.3");
            Oid oidMessageDigest = new Oid("1.2.840.113549.1.9.4");

            byte[] contentHash;
            using (var sha1 = SHA1.Create()) { contentHash = sha1.ComputeHash(authPackDer); }

            // signedAttrs [0] IMPLICIT: { contentType=id-pkinit-authData, messageDigest=SHA1(authPack) }
            AsnElt attrContentType = AsnElt.Make(AsnElt.SEQUENCE,
                AsnElt.MakeOID(oidContentType.Value),
                AsnElt.Make(AsnElt.SET, AsnElt.MakeOID(IdPkInitAuthData.Value)));
            AsnElt attrMessageDigest = AsnElt.Make(AsnElt.SEQUENCE,
                AsnElt.MakeOID(oidMessageDigest.Value),
                AsnElt.Make(AsnElt.SET, AsnElt.MakeBlob(contentHash)));
            AsnElt signedAttrsSet = AsnElt.Make(AsnElt.SET, attrContentType, attrMessageDigest);

            // With signedAttrs present, CMS signs the DER encoding of the SET OF Attributes
            // (SET tag), NOT the AuthPack content. Handles CAPI (RSACryptoServiceProvider) and
            // CNG (RSACng) keys.
            byte[] signature;
            using (var sha1 = SHA1.Create())
            {
                byte[] attrsHash = sha1.ComputeHash(signedAttrsSet.Encode());
                var rsaCapi = cert.PrivateKey as RSACryptoServiceProvider;
                if (rsaCapi != null)
                    signature = rsaCapi.SignHash(attrsHash, digestAlgName.Name);
                else
                    signature = ((RSACng)cert.PrivateKey).SignHash(attrsHash, digestAlgName, RSASignaturePadding.Pkcs1);
            }

            // digestAlgorithms SET OF AlgorithmIdentifier { sha256, NULL }
            AsnElt digestAlg = AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeOID(oidDigest.Value), AsnElt.MakePrimitive(AsnElt.NULL, new byte[0]));
            AsnElt digestAlgorithms = AsnElt.Make(AsnElt.SET, digestAlg);

            // encapContentInfo { eContentType OID, eContent [0] EXPLICIT OCTET STRING(authPackDer) }
            AsnElt eContent = AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, AsnElt.MakeBlob(authPackDer));
            AsnElt encapContentInfo = AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeOID(IdPkInitAuthData.Value), eContent);

            // certificates [0] IMPLICIT CertificateSet { cert }
            AsnElt certSet = AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, AsnElt.Decode(cert.RawData));

            // SignerInfo {
            //   version 1 (issuerAndSerialNumber sid),
            //   sid = IssuerAndSerialNumber { issuer Name, serialNumber INTEGER },
            //   digestAlgorithm sha256,
            //   signedAttrs [0] IMPLICIT,
            //   signatureAlgorithm rsaEncryption,
            //   signature OCTET STRING
            // }
            AsnElt issuer = AsnElt.Decode(cert.IssuerName.RawData);
            byte[] serialLE = cert.GetSerialNumber(); // little-endian; reverse to big-endian
            Array.Reverse(serialLE);
            AsnElt serial = AsnElt.MakeInteger(serialLE);
            AsnElt issuerAndSerial = AsnElt.Make(AsnElt.SEQUENCE, issuer, serial);

            AsnElt sigDigestAlg = AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeOID(oidDigest.Value), AsnElt.MakePrimitive(AsnElt.NULL, new byte[0]));
            AsnElt sigAlg = AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeOID(oidRsaEncryption.Value), AsnElt.MakePrimitive(AsnElt.NULL, new byte[0]));

            AsnElt signerInfo = AsnElt.Make(AsnElt.SEQUENCE,
                AsnElt.MakeInteger(1),
                issuerAndSerial,
                sigDigestAlg,
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, signedAttrsSet),
                sigAlg,
                AsnElt.MakeBlob(signature));

            AsnElt signerInfos = AsnElt.Make(AsnElt.SET, signerInfo);

            // SignedData { version 1, digestAlgorithms, encapContentInfo, certificates[0], signerInfos }
            AsnElt signedData = AsnElt.Make(AsnElt.SEQUENCE,
                AsnElt.MakeInteger(1),
                digestAlgorithms,
                encapContentInfo,
                certSet,
                signerInfos);

            // ContentInfo { signedData OID, [0] EXPLICIT SignedData }
            AsnElt contentInfo = AsnElt.Make(AsnElt.SEQUENCE,
                AsnElt.MakeOID(oidSignedData.Value),
                AsnElt.MakeExplicit(AsnElt.CONTEXT, 0, signedData));

            return contentInfo.Encode();
        }

        // Perform PKINIT AS-REQ/AS-REP and return verification result.
        // cert: X509Certificate2 with private key already attached (from cert store).
        // userName: the user to request a TGT for (e.g. "Administrator").
        // domain: the realm (e.g. "LAB.LOCAL").
        // dcIp: IP or hostname of the domain controller.
        public static PkinitResult VerifyTgt(X509Certificate2 cert, string userName, string domain, string dcIp)
        {
            var result = new PkinitResult();

            try
            {
                if (!cert.HasPrivateKey)
                {
                    result.Error = "Certificate does not contain a private key";
                    return result;
                }

                // Build DH key agreement
                var agreement = new KdcKeyAgreement();

                // Build KDC-REQ-BODY
                var reqBody = new KrbKdcReqBody();
                reqBody.KdcOptions = 0x40810010; // FORWARDABLE | RENEWABLE | RENEWABLEOK | CANONICALIZE
                reqBody.CName = new KrbPrincipalName { NameType = 1 }; // NT_PRINCIPAL
                foreach (string part in userName.Split('/'))
                    reqBody.CName.NameString.Add(part);
                reqBody.Realm = domain.ToLowerInvariant(); // Rubeus sends lowercase realm
                reqBody.SName = new KrbPrincipalName { NameType = 2 }; // NT_SRV_INST
                reqBody.SName.NameString.Add("krbtgt");
                reqBody.SName.NameString.Add(domain.ToLowerInvariant());
                DateTime till = DateTime.UtcNow.AddHours(10);
                reqBody.Till = till;
                reqBody.RTime = till;
                reqBody.Nonce = (uint)new Random().Next();
                reqBody.ETypes.Add(18); // aes256-cts-hmac-sha1
                reqBody.ETypes.Add(17); // aes128-cts-hmac-sha1
                reqBody.ETypes.Add(23); // rc4_hmac
                reqBody.ETypes.Add(-135); // rc4_md4
                reqBody.ETypes.Add(3);  // des_cbc_md5
                reqBody.NetBiosHostName = System.Net.Dns.GetHostName().ToUpperInvariant();

                // Build PKINIT pre-auth
                byte[] reqBodyBytes = reqBody.Encode().Encode();

                var now = DateTime.UtcNow;
                var authenticator = new KrbPkAuthenticator
                {
                    CuSec = (uint)now.Millisecond,
                    CTime = now,
                    Nonce = (int)reqBody.Nonce,
                    PaChecksum = null // set below
                };

                // PA-PK-AS-REQ checksum: SHA1 of the KDC-REQ-BODY
                using (var sha1 = new SHA1CryptoServiceProvider())
                {
                    authenticator.PaChecksum = sha1.ComputeHash(reqBodyBytes);
                }

                // Build ECDH public key info (RFC 5349): id-ecPublicKey + namedCurve P-256,
                // subjectPublicKey = uncompressed EC point (0x04 || X || Y).
                var authPack = new KrbAuthPack
                {
                    Authenticator = authenticator,
                    ClientPublicValue = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                        AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                            AsnElt.MakeOID("1.2.840.10045.2.1"),   // id-ecPublicKey
                            AsnElt.MakeOID("1.2.840.10045.3.1.7")  // secp256r1 (P-256)
                        }),
                        AsnElt.MakeBitString(agreement.Y)           // uncompressed EC point
                    }).Encode(),
                    SupportedCMSTypeOids = new byte[][] {
                        // AlgorithmIdentifier { id-pkinit-authData }
                        AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeOID("1.3.6.1.5.2.3.1")).Encode()
                    },
                    ClientDHNonce = new byte[0]
                };

                // Sign the auth pack with the client certificate.
                // NOTE: NetFX 4.7.2/4.8 SignedCms produces a malformed eContent that
                // Server 2025 KDCs reject (Rubeus issue #196). Build the CMS SignedData
                // manually with correct OCTET STRING wrapping.
                byte[] authPackDer = authPack.Encode().Encode();
                byte[] cmsBytes = BuildPkinitSignedData(authPackDer, cert);
                Console.WriteLine("[DEBUG] CMS SignedData length: " + cmsBytes.Length);

                // Build PA-PK-AS-REQ
                AsnElt paPkAsReq = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 0, AsnElt.MakeBlob(cmsBytes))
                });

                // Build PA-DATA list: PA_PK_AS_REQ (16) + PA_PAC_REQUEST (128)
                AsnElt paData = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeInteger(16))), // PK_AS_REQ = 16
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeBlob(paPkAsReq.Encode())))
                });

                // PA-PAC-REQUEST (include-pac = true), Rubeus encodes BOOLEAN TRUE as 0x01
                AsnElt pacRequest = AsnElt.Make(AsnElt.SEQUENCE,
                    AsnElt.Make(AsnElt.CONTEXT, 0, AsnElt.MakePrimitive(AsnElt.BOOLEAN, new byte[] { 0x01 })));
                AsnElt pacPaData = AsnElt.Make(AsnElt.SEQUENCE, new AsnElt[] {
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeInteger(128))),
                    AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeBlob(pacRequest.Encode())))
                });

                // Build AS-REQ
                AsnElt pvnoElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                    AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeInteger(5)));
                AsnElt msgTypeElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                    AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeInteger(10)));
                // [3] padata: SEQUENCE OF PA-DATA, wrapped in SEQUENCE-OF (Rubeus convention)
                AsnElt padataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                    AsnElt.Make(AsnElt.SEQUENCE, AsnElt.Make(AsnElt.SEQUENCE, pacPaData, paData)));
                AsnElt reqBodyElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4,
                    AsnElt.Make(AsnElt.SEQUENCE, reqBody.Encode()));

                AsnElt asReq = AsnElt.Make(AsnElt.SEQUENCE, pvnoElt, msgTypeElt, padataElt, reqBodyElt);
                AsnElt asReqApp = AsnElt.MakeImplicit(AsnElt.APPLICATION, 10,
                    AsnElt.Make(AsnElt.SEQUENCE, asReq));

                // Send to KDC
                byte[] requestBytes = asReqApp.Encode();
                byte[] responseBytes = SendToKdc(dcIp, 88, requestBytes);
                if (responseBytes == null || responseBytes.Length == 0)
                {
                    result.Error = "No response from KDC";
                    return result;
                }

                // Parse AS-REP
                AsnElt responseAsn = AsnElt.Decode(responseBytes);
                if (responseAsn.TagClass != AsnElt.APPLICATION || responseAsn.TagValue != 11)
                {
                    if (responseAsn.TagClass == AsnElt.APPLICATION && responseAsn.TagValue == 30)
                    {
                        // KRB-ERROR — extract error-code [6] and e-text [11]
                        int errCode = -1;
                        string eText = "";
                        try
                        {
                            AsnElt errSeq = responseAsn.Sub[0];
                            foreach (AsnElt f in errSeq.Sub)
                            {
                                if (f.TagValue == 6) errCode = (int)f.Sub[0].GetInteger();
                                if (f.TagValue == 11) eText = f.Sub[0].GetString();
                            }
                        }
                        catch { }
                        result.Error = "KRB-ERROR code " + errCode + (eText.Length > 0 ? ": " + eText : "");
                        Console.WriteLine("[DEBUG] KRB-ERROR hex: " + BitConverter.ToString(responseBytes));
                        return result;
                    }
                    result.Error = "Unexpected response type: " + responseAsn.TagValue;
                    return result;
                }

                var asRep = KrbAsRep.Parse(responseAsn);

                // Find PK_AS_REP padata
                KrbPaData pkAsRep = null;
                foreach (var pa in asRep.PaData)
                {
                    if (pa.Type == 17) { pkAsRep = pa; break; }
                }
                if (pkAsRep == null || pkAsRep.DHRepInfo == null)
                {
                    result.Error = "No PK-AS-REP in response";
                    return result;
                }

                // Generate decryption key from DH shared secret
                byte[] replyKey = agreement.GenerateKey(
                    pkAsRep.DHRepInfo.KdcPublicKey,
                    new byte[0],
                    pkAsRep.DHRepInfo.ServerDHNonce,
                    32 // AES-256 key size
                );

                // Decrypt the enc-part
                byte[] plainBytes = KerberosCrypto.KerberosDecrypt(
                    KerberosCrypto.ETYPE_AES256_CTS_HMAC_SHA1,
                    KerberosCrypto.KRB_KEY_USAGE_AS_REP_EP_SESSION_KEY,
                    replyKey,
                    asRep.EncPart.Cipher
                );

                // Parse EncASRepPart
                AsnElt encAsRepPart = AsnElt.Decode(plainBytes, false);
                if (encAsRepPart.TagValue != 25)
                {
                    result.Error = "Failed to decrypt AS-REP enc-part (unexpected tag: " + encAsRepPart.TagValue + ")";
                    return result;
                }

                var encPart = KrbEncKdcRepPart.Parse(encAsRepPart.Sub[0]);

                // Verify nonce matches
                if (encPart.Nonce != reqBody.Nonce)
                {
                    result.Error = "Nonce mismatch: sent " + reqBody.Nonce + ", got " + encPart.Nonce;
                    return result;
                }

                // Success — populate result
                result.Success = true;
                result.PrincipalName = string.Join("/", asRep.CName.NameString);
                result.Realm = asRep.CRealm;
                result.AuthTime = encPart.AuthTime;
                result.StartTime = encPart.StartTime;
                result.EndTime = encPart.EndTime;
                result.RenewTill = encPart.RenewTill;
                result.Flags = encPart.Flags;
                result.SessionKeyType = encPart.KeyType;
                result.SessionKey = encPart.KeyValue;

                // Zero the key material
                if (replyKey != null) Array.Clear(replyKey, 0, replyKey.Length);

                return result;
            }
            catch (Exception ex)
            {
                result.Error = ex.GetType().FullName + ": " + ex.Message;
                return result;
            }
        }

        // Debug: build a minimal AS-REQ without pre-auth and send it to the KDC.
        // Returns the raw response bytes or null.
        public static byte[] SendMinimalAsReq(string userName, string domain, string dcIp, uint kdcOptions = 0x40000010, bool useUdp = false)
        {
            var reqBody = new KrbKdcReqBody();
            reqBody.KdcOptions = kdcOptions;
            reqBody.CName = new KrbPrincipalName { NameType = 1 };
            reqBody.CName.NameString.Add(userName);
            reqBody.Realm = domain.ToLowerInvariant(); // Rubeus sends lowercase realm
            reqBody.SName = new KrbPrincipalName { NameType = 2 };
            reqBody.SName.NameString.Add("krbtgt");
            reqBody.SName.NameString.Add(domain.ToLowerInvariant());
            DateTime till = DateTime.UtcNow.AddHours(10);
            reqBody.Till = till;
            reqBody.RTime = till; // Rubeus includes rtime = till
            reqBody.Nonce = (uint)new Random().Next();
            // Rubeus offers aes256, aes128, rc4_hmac, rc4_md4(-135), des_cbc_md5
            reqBody.ETypes.Add(18);
            reqBody.ETypes.Add(17);
            reqBody.ETypes.Add(23);
            reqBody.ETypes.Add(-135);
            reqBody.ETypes.Add(3);
            // addresses [9]: NetBIOS hostname padded to 16 bytes, addr-type 20
            reqBody.NetBiosHostName = System.Net.Dns.GetHostName().ToUpperInvariant();
            AsnElt pvnoElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 1,
                AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeInteger(5)));
            AsnElt msgTypeElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 2,
                AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeInteger(10)));
            AsnElt reqBodyElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 4,
                AsnElt.Make(AsnElt.SEQUENCE, reqBody.Encode()));

            // PA-PAC-REQUEST (include-pac = true) — required by Windows KDC
            // Rubeus encodes BOOLEAN TRUE as 0x01 (not DER-canonical 0xFF)
            AsnElt pacRequest = AsnElt.Make(AsnElt.SEQUENCE,
                AsnElt.Make(AsnElt.CONTEXT, 0, AsnElt.MakePrimitive(AsnElt.BOOLEAN, new byte[] { 0x01 })));
            AsnElt pacPaData = AsnElt.Make(AsnElt.SEQUENCE,
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 1, AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeInteger(128))), // PA_PAC_REQUEST = 128
                AsnElt.MakeImplicit(AsnElt.CONTEXT, 2, AsnElt.Make(AsnElt.SEQUENCE, AsnElt.MakeBlob(pacRequest.Encode()))));
            // [3] padata: Rubeus wraps in SEQUENCE OF SEQUENCE
            AsnElt padataElt = AsnElt.MakeImplicit(AsnElt.CONTEXT, 3,
                AsnElt.Make(AsnElt.SEQUENCE, AsnElt.Make(AsnElt.SEQUENCE, pacPaData)));

            AsnElt asReq = AsnElt.Make(AsnElt.SEQUENCE, pvnoElt, msgTypeElt, padataElt, reqBodyElt);
            AsnElt asReqApp = AsnElt.MakeImplicit(AsnElt.APPLICATION, 10,
                AsnElt.Make(AsnElt.SEQUENCE, asReq));

            byte[] requestBytes = asReqApp.Encode();
            Console.WriteLine("[DEBUG] Minimal AS-REQ length: " + requestBytes.Length);
            Console.WriteLine(DumpAsReqStructure(requestBytes));

            return useUdp ? SendToKdcUdp(dcIp, 88, requestBytes) : SendToKdc(dcIp, 88, requestBytes);
        }

        // Debug: dump AS-REQ structure in readable format
        public static string DumpAsReqStructure(byte[] asReqBytes)
        {
            try
            {
                AsnElt root = AsnElt.Decode(asReqBytes);
                return DumpAsn(root, 0);
            }
            catch (Exception ex)
            {
                return "Decode failed: " + ex.Message;
            }
        }

        private static string DumpAsn(AsnElt elt, int depth)
        {
            string indent = new string(' ', depth * 2);
            string tag;
            switch (elt.TagClass)
            {
                case 0: tag = "UNIVERSAL"; break;
                case 1: tag = "APPLICATION"; break;
                case 2: tag = "CONTEXT"; break;
                case 3: tag = "PRIVATE"; break;
                default: tag = "?"; break;
            }
            string result = indent + tag + " " + elt.TagValue;
            if (elt.Constructed)
            {
                result += " (constructed, " + elt.Sub.Length + " subs)\n";
                foreach (var sub in elt.Sub)
                {
                    result += DumpAsn(sub, depth + 1);
                }
            }
            else
            {
                byte[] val = elt.CopyValue();
                result += " (primitive, " + val.Length + " bytes)";
                if (val.Length <= 32)
                {
                    result += " " + BitConverter.ToString(val);
                }
                result += "\n";
            }
            return result;
        }
        private static byte[] SendToKdc(string host, int port, byte[] data)
        {
            using (var client = new TcpClient())
            {
                client.ReceiveTimeout = 10000;
                client.SendTimeout = 10000;
                client.Connect(host, port);
                Console.WriteLine("[DEBUG] Connected to " + host + ":" + port);
                using (var stream = client.GetStream())
                {
                    byte[] lengthPrefix = new byte[4];
                    lengthPrefix[0] = (byte)(data.Length >> 24);
                    lengthPrefix[1] = (byte)(data.Length >> 16);
                    lengthPrefix[2] = (byte)(data.Length >> 8);
                    lengthPrefix[3] = (byte)data.Length;
                    stream.Write(lengthPrefix, 0, 4);
                    stream.Write(data, 0, data.Length);
                    stream.Flush();
                    Console.WriteLine("[DEBUG] Sent " + (data.Length + 4) + " bytes");

                    // Read response length — log each step
                    byte[] respLenBytes = new byte[4];
                    int read = 0;
                    try
                    {
                        while (read < 4)
                        {
                            int r = stream.Read(respLenBytes, read, 4 - read);
                            Console.WriteLine("[DEBUG] Read " + r + " bytes (total " + (read + r) + "/4)");
                            if (r == 0) { Console.WriteLine("[DEBUG] Connection closed by KDC"); return null; }
                            read += r;
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("[DEBUG] Read exception: " + ex.GetType().Name + ": " + ex.Message);
                        return null;
                    }
                    int respLen = (respLenBytes[0] << 24) | (respLenBytes[1] << 16) | (respLenBytes[2] << 8) | respLenBytes[3];
                    Console.WriteLine("[DEBUG] Response length prefix: " + respLen);
                    if (respLen == 0) return new byte[0];
                    if (respLen > 1024 * 1024) { Console.WriteLine("[DEBUG] Response length insane, aborting"); return null; }

                    byte[] response = new byte[respLen];
                    read = 0;
                    while (read < respLen)
                    {
                        int r = stream.Read(response, read, respLen - read);
                        if (r == 0) return null;
                        read += r;
                    }
                    Console.WriteLine("[DEBUG] Read full response: " + read + " bytes");
                    return response;
                }
            }
        }

        private static byte[] SendToKdcUdp(string host, int port, byte[] data)
        {
            using (var client = new UdpClient())
            {
                client.Connect(host, port);
                client.Send(data, data.Length);

                client.Client.ReceiveTimeout = 5000;
                try
                {
                    var remoteEP = new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0);
                    return client.Receive(ref remoteEP);
                }
                catch (System.Net.Sockets.SocketException)
                {
                    return null;
                }
            }
        }
    }
}
