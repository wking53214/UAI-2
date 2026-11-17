import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/** Strict Ed25519 verification (UAI-1.md section 2, Signature), written out from RFC 8032 with BigInteger.
 *  Refuses: non-canonical A or R (y >= p, or sign bit set where x = 0), s >= L, small-order A.
 *  Uses the cofactorless equation [s]B = R + [k]A. */
final class Ed25519Strict {
    static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    static final BigInteger D = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    static final BigInteger SQRT_M1 = BigInteger.TWO.modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);
    static final BigInteger[] ID = {BigInteger.ZERO, BigInteger.ONE};
    static final BigInteger[] B;
    static {
        BigInteger y = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P);
        B = new BigInteger[]{recoverX(y, 0), y};
    }

    private static BigInteger recoverX(BigInteger y, int sign) {
        if (y.compareTo(P) >= 0) return null;
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger num = y2.subtract(BigInteger.ONE).mod(P);
        BigInteger den = D.multiply(y2).add(BigInteger.ONE).mod(P);
        BigInteger x2 = num.multiply(den.modInverse(P)).mod(P);
        if (x2.signum() == 0) return sign == 0 ? BigInteger.ZERO : null; // sign bit with x = 0 is non-canonical
        BigInteger x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).mod(P).equals(x2)) x = x.multiply(SQRT_M1).mod(P);
        if (!x.multiply(x).mod(P).equals(x2)) return null; // not on the curve
        if (x.testBit(0) != (sign == 1)) x = P.subtract(x);
        return x;
    }

    /** null when the encoding is not a canonical point */
    static BigInteger[] decode(byte[] enc) {
        byte[] r = new byte[32];
        for (int i = 0; i < 32; i++) r[i] = enc[31 - i];
        int sign = (r[0] >> 7) & 1;
        r[0] &= 0x7f;
        BigInteger y = new BigInteger(1, r);
        BigInteger x = recoverX(y, sign);
        return x == null ? null : new BigInteger[]{x, y};
    }

    static BigInteger[] add(BigInteger[] a, BigInteger[] b) {
        BigInteger x1 = a[0], y1 = a[1], x2 = b[0], y2 = b[1];
        BigInteger dxy = D.multiply(x1).multiply(x2).mod(P).multiply(y1).multiply(y2).mod(P);
        BigInteger x3 = x1.multiply(y2).add(x2.multiply(y1)).mod(P).multiply(BigInteger.ONE.add(dxy).mod(P).modInverse(P)).mod(P);
        BigInteger y3 = y1.multiply(y2).add(x1.multiply(x2)).mod(P).multiply(BigInteger.ONE.subtract(dxy).mod(P).modInverse(P)).mod(P);
        return new BigInteger[]{x3, y3};
    }

    static BigInteger[] mul(BigInteger k, BigInteger[] p) {
        BigInteger[] q = ID;
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            q = add(q, q);
            if (k.testBit(i)) q = add(q, p);
        }
        return q;
    }

    static boolean eq(BigInteger[] a, BigInteger[] b) { return a[0].equals(b[0]) && a[1].equals(b[1]); }

    private static BigInteger le(byte[] b, int off, int len) {
        byte[] r = new byte[len];
        for (int i = 0; i < len; i++) r[i] = b[off + len - 1 - i];
        return new BigInteger(1, r);
    }

    static boolean verify(byte[] pub, byte[] msg, byte[] sig) {
        try {
            if (pub.length != 32 || sig.length != 64) return false;
            BigInteger[] a = decode(pub);
            if (a == null) return false;
            if (eq(mul(BigInteger.valueOf(8), a), ID)) return false; // small order: never verifies
            byte[] rb = Arrays.copyOfRange(sig, 0, 32);
            BigInteger[] r = decode(rb);
            if (r == null) return false;
            BigInteger s = le(sig, 32, 32);
            if (s.compareTo(L) >= 0) return false;
            MessageDigest sha = MessageDigest.getInstance("SHA-512");
            sha.update(rb); sha.update(pub); sha.update(msg);
            BigInteger k = le(sha.digest(), 0, 64).mod(L);
            return eq(mul(s, B), add(r, mul(k, a)));
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    static byte[] unhex(String h) {
        byte[] b = new byte[h.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static byte[] signingMessage(String digestHex) {
        return ("uai/1 sig\n" + digestHex).getBytes(StandardCharsets.US_ASCII);
    }
}
