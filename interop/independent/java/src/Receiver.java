import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/** A UAI-1 receiver for the envelope layer: strict read, ordered envelope check, trust, replay ledger. */
final class Receiver {
    static final int MAX_BYTES = 1 << 20;
    static final int MAX_LEVELS = 32;
    static final long SKEW_MS = 120_000L;
    static final long DAY_MS = 24L * 3600 * 1000;
    static final List<String> KINDS = List.of("manifest", "endorsement", "request", "offer", "accept", "refuse", "decision", "revocation");
    static final Set<String> SESSION_KINDS = Set.of("request", "offer", "accept", "refuse", "decision");
    static final Set<String> FIELDS = Set.of("v", "kind", "id", "from", "to", "conversation", "in_reply_to", "issued_at", "expires_at", "body", "sig");
    static final Pattern IDENTITY = Pattern.compile("uai:ed25519:[0-9a-f]{64}");
    static final Pattern HEX32 = Pattern.compile("[0-9a-f]{32}");
    static final Pattern HEX64 = Pattern.compile("[0-9a-f]{64}");
    static final Pattern HEX128 = Pattern.compile("[0-9a-f]{128}");

    private final Set<String> ledger = new HashSet<>();

    void reset() { ledger.clear(); }

    /** @return the envelope digest (all fields, with sig) on accept; throws Json.Refusal otherwise */
    @SuppressWarnings("unchecked")
    String receive(String wire, long now, Collection<String> trust, String audience, Collection<String> kinds, boolean useLedger) {
        // 1. strict reading
        if (wire.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) throw new Json.Refusal("malformed", "over 1 MiB");
        Object top = Json.read(wire, false);
        Map<String, Object> env = (Map<String, Object>) top;

        // 2. fields and forms (malformed)
        if (!env.keySet().equals(FIELDS)) throw new Json.Refusal("malformed", "fields");
        Object v = env.get("v"), kind = env.get("kind");
        if (!(v instanceof String)) throw new Json.Refusal("malformed", "v not text");
        if (!(kind instanceof String k) || !KINDS.contains(k)) throw new Json.Refusal("malformed", "kind");
        String id = text(env, "id", HEX32), from = text(env, "from", IDENTITY), conv = text(env, "conversation", HEX32);
        String sig = text(env, "sig", HEX128);
        Object to = env.get("to");
        if (!(to instanceof String ts) || !(ts.isEmpty() || IDENTITY.matcher(ts).matches())) throw new Json.Refusal("malformed", "to");
        Object irt = env.get("in_reply_to");
        if (!(irt instanceof String is) || !(is.isEmpty() || HEX64.matcher(is).matches())) throw new Json.Refusal("malformed", "in_reply_to");
        long issued = ms(env.get("issued_at"));
        Object ea = env.get("expires_at");
        Long expires = null;
        if (ea != null) {
            expires = ms(ea);
            if (expires <= issued) throw new Json.Refusal("malformed", "expires_at not after issued_at");
        }
        if (!(env.get("body") instanceof Map)) throw new Json.Refusal("malformed", "body not a mapping");
        // a session message must expire and may claim at most 24 hours (section 2); no code is named, malformed chosen
        if (SESSION_KINDS.contains(k) && (expires == null || expires - issued > DAY_MS))
            throw new Json.Refusal("malformed", "session message lifetime");

        // 3. version, 4. kind accepted, 5. body profile
        if (!"uai/1".equals(v)) throw new Json.Refusal("version", "v");
        if (kinds != null && !kinds.contains(k)) throw new Json.Refusal("kind", "not accepted here");
        checkProfile(env.get("body"), 1);

        // 6. signature
        Map<String, Object> unsigned = new LinkedHashMap<>(env);
        unsigned.remove("sig");
        String signingDigest = Digest.digest(unsigned);
        byte[] pub = Ed25519Strict.unhex(from.substring("uai:ed25519:".length()));
        if (!Ed25519Strict.verify(pub, Ed25519Strict.signingMessage(signingDigest), Ed25519Strict.unhex(sig)))
            throw new Json.Refusal("signature", "does not verify");

        // 7. time
        if (issued > now + SKEW_MS) throw new Json.Refusal("not_yet_valid", "issued_at");
        if (expires != null && now >= expires) throw new Json.Refusal("expired", "expires_at");

        // 8. audience
        if (audience != null && !audience.equals(ts)) throw new Json.Refusal("audience", "to");

        // 9. trust (after audience, before replay)
        if (trust != null && !trust.contains(from)) throw new Json.Refusal("untrusted", "sender not admitted");

        // 10. replay ledger, spent on accept
        if (useLedger && !ledger.add(from + "|" + id)) throw new Json.Refusal("replayed", "(from, id) seen");

        return Digest.digest(env);
    }

    private static String text(Map<String, Object> m, String key, Pattern p) {
        Object o = m.get(key);
        if (!(o instanceof String s) || !p.matcher(s).matches()) throw new Json.Refusal("malformed", key);
        return s;
    }

    private static long ms(Object o) {
        if (!(o instanceof BigInteger b) || b.signum() < 0 || b.compareTo(Json.SAFE) > 0) throw new Json.Refusal("malformed", "ms field");
        return b.longValueExact();
    }

    /** value profile: text (valid Unicode), booleans, null, safe integers, lists, mappings; at most 32 levels, body = level 1 */
    @SuppressWarnings("unchecked")
    static void checkProfile(Object v, int level) {
        if (v == null || v instanceof Boolean) return;
        if (v instanceof String s) { if (Digest.hasLoneSurrogate(s)) throw new Json.Refusal("profile", "lone surrogate"); return; }
        if (v instanceof BigInteger b) { if (b.abs().compareTo(Json.SAFE) > 0) throw new Json.Refusal("profile", "integer"); return; }
        if (level > MAX_LEVELS) throw new Json.Refusal("profile", "nested past 32 levels");
        if (v instanceof List<?> l) { for (Object o : l) checkProfile(o, level + 1); return; }
        if (v instanceof Map<?, ?> m) {
            for (Map.Entry<?, ?> e : m.entrySet()) {
                checkProfile((String) e.getKey(), level + 1);
                checkProfile(e.getValue(), level + 1);
            }
            return;
        }
        throw new Json.Refusal("profile", "value type");
    }
}
