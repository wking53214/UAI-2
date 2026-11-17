import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** The CNS subject digest: SHA-256 over the length-prefixed canonical rendering (UAI-1.md section 1). */
final class Digest {
    static final class Unrenderable extends RuntimeException { Unrenderable(String m) { super(m); } }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(Character.forDigit((x >> 4) & 15, 16)).append(Character.forDigit(x & 15, 16));
        return sb.toString();
    }

    static String digest(Object v) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(render(v).getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    static String render(Object v) { StringBuilder sb = new StringBuilder(); render(v, sb); return sb.toString(); }

    static boolean hasLoneSurrogate(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) i++; else return true;
            } else if (Character.isLowSurrogate(c)) return true;
        }
        return false;
    }

    /** ascending code point order (not UTF-16 unit order) */
    static final Comparator<String> BY_CODE_POINT = (a, b) -> {
        int i = 0, j = 0;
        while (i < a.length() && j < b.length()) {
            int ca = a.codePointAt(i), cb = b.codePointAt(j);
            if (ca != cb) return Integer.compare(ca, cb);
            i += Character.charCount(ca); j += Character.charCount(cb);
        }
        return Integer.compare(a.length() - i, b.length() - j);
    };

    @SuppressWarnings("unchecked")
    private static void render(Object v, StringBuilder sb) {
        if (v == null) sb.append("n:");
        else if (v instanceof Boolean b) sb.append(b ? "b:1" : "b:0");
        else if (v instanceof BigInteger n) sb.append("i:").append(n.toString()).append(':');
        else if (v instanceof Json.JFloat f) sb.append("f:").append(pyRepr(f.value())).append(':');
        else if (v instanceof String s) {
            if (hasLoneSurrogate(s)) throw new Unrenderable("lone surrogate");
            sb.append("s:").append(s.codePointCount(0, s.length())).append(':').append(s);
        } else if (v instanceof List<?> l) {
            sb.append("l:").append(l.size()).append(':');
            for (Object o : l) render(o, sb);
        } else if (v instanceof Map<?, ?> m) {
            List<String> keys = new ArrayList<>((Set<String>) m.keySet());
            keys.sort(BY_CODE_POINT);
            sb.append("d:").append(keys.size()).append(':');
            for (String k : keys) { render(k, sb); render(m.get(k), sb); }
        } else throw new Unrenderable("unsupported value " + v.getClass());
    }

    /** Python repr(float): shortest round trip digits, fixed notation for 1e-4 <= |x| < 1e16, else d.ddde+XX. */
    static String pyRepr(double d) {
        if (Double.isNaN(d) || Double.isInfinite(d)) throw new Unrenderable("NaN or infinity");
        if (d == 0.0) return "0.0"; // -0.0 renders as 0.0
        String sign = d < 0 ? "-" : "";
        double ad = Math.abs(d);
        BigDecimal bd = null; // fewest significant digits that read back as the same double (closest of that length)
        for (int p = 1; p <= 17 && bd == null; p++) {
            BigDecimal c = new BigDecimal(ad).round(new java.math.MathContext(p, java.math.RoundingMode.HALF_EVEN));
            if (c.doubleValue() == ad) bd = c.stripTrailingZeros();
        }
        String digits = bd.unscaledValue().toString();
        int decpt = digits.length() - bd.scale(); // value = 0.DIGITS x 10^decpt
        StringBuilder sb = new StringBuilder(sign);
        if (decpt > 16 || decpt < -3) {
            sb.append(digits.charAt(0));
            if (digits.length() > 1) sb.append('.').append(digits, 1, digits.length());
            int e = decpt - 1;
            sb.append('e').append(e < 0 ? '-' : '+');
            int ae = Math.abs(e);
            if (ae < 10) sb.append('0');
            sb.append(ae);
        } else if (decpt <= 0) {
            sb.append("0.");
            for (int k = 0; k < -decpt; k++) sb.append('0');
            sb.append(digits);
        } else if (decpt >= digits.length()) {
            sb.append(digits);
            for (int k = digits.length(); k < decpt; k++) sb.append('0');
            sb.append(".0");
        } else {
            sb.append(digits, 0, decpt).append('.').append(digits, decpt, digits.length());
        }
        return sb.toString();
    }
}
