import java.math.BigInteger;
import java.util.*;

/** Strict JSON reader for UAI-1. Syntax errors, duplicate keys and non-objects are Refusal("malformed");
 *  floats, exponents and integers beyond +/-(2^53-1) are Refusal("profile"). Values: null, Boolean, String,
 *  BigInteger, List, Map (LinkedHashMap). In lenient mode (used only to read the answer-key files) floats become
 *  JFloat and big integers stay BigInteger. */
final class Json {
    static final class Refusal extends RuntimeException {
        final String code;
        Refusal(String code, String why) { super(code + ": " + why, null, false, false); this.code = code; }
    }
    /** a JSON number with a fraction or exponent (only produced in lenient mode) */
    record JFloat(double value) {}

    static final BigInteger SAFE = BigInteger.valueOf(9007199254740991L);
    static final int MAX_READ_DEPTH = 20000; // beyond this: malformed (spec allows any code past 100 levels)

    private final String s;
    private final boolean lenient;
    private int i = 0;
    private int depth = 0;

    private Json(String s, boolean lenient) { this.s = s; this.lenient = lenient; }

    static Object read(String text, boolean lenient) {
        Json j = new Json(text, lenient);
        j.ws();
        Object v = j.value();
        j.ws();
        if (j.i != j.s.length()) throw new Refusal("malformed", "trailing characters");
        if (!(v instanceof Map) && !lenient) throw new Refusal("malformed", "not an object");
        return v;
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++; else break;
        }
    }

    private Refusal bad(String why) { return new Refusal("malformed", why + " at " + i); }

    private Object value() {
        if (i >= s.length()) throw bad("unexpected end");
        char c = s.charAt(i);
        switch (c) {
            case '{': return object();
            case '[': return array();
            case '"': return string();
            case 't': lit("true"); return Boolean.TRUE;
            case 'f': lit("false"); return Boolean.FALSE;
            case 'n': lit("null"); return null;
            default:
                if (c == '-' || (c >= '0' && c <= '9')) return number();
                throw bad("unexpected character");
        }
    }

    private void lit(String w) {
        if (!s.startsWith(w, i)) throw bad("bad literal");
        i += w.length();
    }

    private Map<String, Object> object() {
        if (++depth > MAX_READ_DEPTH) throw bad("nested too deep");
        i++; // {
        Map<String, Object> m = new LinkedHashMap<>();
        ws();
        if (i < s.length() && s.charAt(i) == '}') { i++; depth--; return m; }
        while (true) {
            ws();
            if (i >= s.length() || s.charAt(i) != '"') throw bad("expected key");
            String k = string();
            ws();
            if (i >= s.length() || s.charAt(i) != ':') throw bad("expected colon");
            i++;
            ws();
            Object v = value();
            if (m.containsKey(k)) throw bad("duplicate key");
            m.put(k, v);
            ws();
            if (i >= s.length()) throw bad("unterminated object");
            char c = s.charAt(i++);
            if (c == ',') continue;
            if (c == '}') break;
            throw bad("expected , or }");
        }
        depth--;
        return m;
    }

    private List<Object> array() {
        if (++depth > MAX_READ_DEPTH) throw bad("nested too deep");
        i++; // [
        List<Object> l = new ArrayList<>();
        ws();
        if (i < s.length() && s.charAt(i) == ']') { i++; depth--; return l; }
        while (true) {
            ws();
            l.add(value());
            ws();
            if (i >= s.length()) throw bad("unterminated array");
            char c = s.charAt(i++);
            if (c == ',') continue;
            if (c == ']') break;
            throw bad("expected , or ]");
        }
        depth--;
        return l;
    }

    private String string() {
        i++; // opening quote
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (i >= s.length()) throw bad("unterminated string");
            char c = s.charAt(i++);
            if (c == '"') return sb.toString();
            if (c < 0x20) throw bad("raw control character in string");
            if (c != '\\') { sb.append(c); continue; }
            if (i >= s.length()) throw bad("bad escape");
            char e = s.charAt(i++);
            switch (e) {
                case '"': sb.append('"'); break;
                case '\\': sb.append('\\'); break;
                case '/': sb.append('/'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'u': {
                    if (i + 4 > s.length()) throw bad("bad \\u escape");
                    int cp = 0;
                    for (int k = 0; k < 4; k++) {
                        int d = Character.digit(s.charAt(i + k), 16);
                        if (d < 0 || s.charAt(i + k) > 'f') throw bad("bad \\u escape");
                        cp = cp * 16 + d;
                    }
                    i += 4;
                    sb.append((char) cp); // a lone surrogate is kept; the profile check refuses it
                    break;
                }
                default: throw bad("bad escape");
            }
        }
    }

    private Object number() {
        int st = i;
        if (s.charAt(i) == '-') i++;
        if (i >= s.length()) throw bad("bad number");
        char c = s.charAt(i);
        if (c == '0') i++;
        else if (c >= '1' && c <= '9') { while (i < s.length() && isDigit(s.charAt(i))) i++; }
        else throw bad("bad number");
        boolean flt = false;
        if (i < s.length() && s.charAt(i) == '.') {
            flt = true; i++;
            int d0 = i;
            while (i < s.length() && isDigit(s.charAt(i))) i++;
            if (i == d0) throw bad("bad fraction");
        }
        if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
            flt = true; i++;
            if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
            int d0 = i;
            while (i < s.length() && isDigit(s.charAt(i))) i++;
            if (i == d0) throw bad("bad exponent");
        }
        String tok = s.substring(st, i);
        if (flt) {
            if (!lenient) throw new Refusal("profile", "float or exponent");
            return new JFloat(Double.parseDouble(tok));
        }
        BigInteger b = new BigInteger(tok);
        if (!lenient && b.abs().compareTo(SAFE) > 0) throw new Refusal("profile", "integer beyond 2^53-1");
        return b;
    }

    private static boolean isDigit(char c) { return c >= '0' && c <= '9'; }
}
