import java.math.BigInteger;
import java.nio.file.*;
import java.util.*;

/** Checks the digest answer key and the signed vectors. usage: java SelfTest <kit root> */
public final class SelfTest {
    @SuppressWarnings("unchecked")
    public static void main(String[] a) throws Exception {
        Path root = Path.of(a[0]);
        Map<String, Object> dv = (Map<String, Object>) Json.read(Files.readString(root.resolve("contracts/digest-vectors.json")), true);
        int ok = 0, total = 0;
        for (Object o : (List<Object>) dv.get("vectors")) {
            Map<String, Object> v = (Map<String, Object>) o;
            total++;
            String rendering = Digest.render(v.get("content"));
            String d = Digest.digest(v.get("content"));
            boolean good = rendering.equals(v.get("rendering")) && d.equals(v.get("digest"));
            if (good) ok++; else System.out.println("DIGEST FAIL " + v.get("name") + "\n  got  " + rendering + "\n  want " + v.get("rendering"));
        }
        System.out.println("digest vectors matched: " + ok + "/" + total);
        int rok = 0, rtotal = 0;
        for (Object o : (List<Object>) dv.get("refusals")) {
            Map<String, Object> v = (Map<String, Object>) o;
            String lj = (String) v.get("lenient_json");
            rtotal++;
            if (lj == null) { System.out.println("refusal " + v.get("name") + ": no JSON form to test (" + v.get("what") + ")"); continue; }
            try {
                Object x = Json.read(lj, true);
                Digest.render(x);
                System.out.println("REFUSAL NOT REFUSED " + v.get("name"));
            } catch (Digest.Unrenderable | Json.Refusal e) { rok++; }
        }
        System.out.println("digest refusals refused: " + rok + "/" + (rtotal) + " (those with a JSON form)");

        Map<String, Object> uv = (Map<String, Object>) Json.read(Files.readString(root.resolve("contracts/uai-vectors.json")), true);
        for (Object o : (List<Object>) uv.get("envelopes")) {
            Map<String, Object> e = (Map<String, Object>) o;
            Map<String, Object> wire = new LinkedHashMap<>((Map<String, Object>) e.get("wire"));
            String full = Digest.digest(wire);
            String sig = (String) wire.remove("sig");
            String sd = Digest.digest(wire);
            String from = (String) wire.get("from");
            boolean sv = Ed25519Strict.verify(Ed25519Strict.unhex(from.substring(12)), Ed25519Strict.signingMessage(sd), Ed25519Strict.unhex(sig));
            System.out.println(e.get("name") + ": digest " + full.equals(e.get("digest")) + " signing_digest " + sd.equals(e.get("signing_digest")) + " sigverify " + sv);
        }
        for (Object o : (List<Object>) uv.get("wire_text")) {
            Map<String, Object> w = (Map<String, Object>) o;
            String got;
            try { Json.read((String) w.get("text"), false); got = "accepted"; } catch (Json.Refusal e) { got = e.code; }
            System.out.println("reader " + w.get("name") + ": " + got + " want " + w.get("code") + (got.equals(w.get("code")) ? "" : "  MISMATCH"));
        }
    }
}
