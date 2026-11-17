import java.math.BigInteger;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

/** Does the JDK's own Ed25519 verifier accept what the spec refuses? (run with the java/out classes on the classpath) */
public final class JdkLeniency {
    @SuppressWarnings("unchecked")
    public static void main(String[] a) throws Exception {
        Map<String, Object> suite = (Map<String, Object>) Json.read(Files.readString(Path.of(a[0], "contracts/uai1/conformance-suite.json")), true);
        for (Object o : (List<Object>) suite.get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            String n = (String) c.get("name");
            if (!(n.equals("reject-small-order-key") || n.equals("reject-non-canonical-key") || n.equals("sig-s-plus-group-order") || n.startsWith("valid-request"))) continue;
            Map<String, Object> st = (Map<String, Object>) ((List<Object>) c.get("steps")).get(0);
            String wire = (String) ((Map<String, Object>) st.get("receive")).get("wire_text");
            Map<String, Object> env = (Map<String, Object>) Json.read(wire, false);
            String sig = (String) env.remove("sig");
            String msgDigest = Digest.digest(env);
            byte[] pub = Ed25519Strict.unhex(((String) env.get("from")).substring(12));
            byte[] enc = pub.clone();
            for (int i = 0; i < 16; i++) { byte t = enc[i]; enc[i] = enc[31 - i]; enc[31 - i] = t; }
            boolean xOdd = (enc[0] & 0x80) != 0; enc[0] &= 0x7f;
            BigInteger y = new BigInteger(1, enc);
            String jdk;
            try {
                PublicKey pk = KeyFactory.getInstance("Ed25519").generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y)));
                Signature s = Signature.getInstance("Ed25519");
                s.initVerify(pk); s.update(Ed25519Strict.signingMessage(msgDigest));
                jdk = String.valueOf(s.verify(Ed25519Strict.unhex(sig)));
            } catch (Exception e) { jdk = "exception " + e.getClass().getSimpleName(); }
            boolean mine = Ed25519Strict.verify(pub, Ed25519Strict.signingMessage(msgDigest), Ed25519Strict.unhex(sig));
            System.out.println(n + ": JDK verify=" + jdk + "  strict=" + mine);
        }
        // sanity: random JDK-made signatures verify under the strict verifier
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519"); int ok = 0;
        for (int i = 0; i < 200; i++) {
            KeyPair kp = g.generateKeyPair(); byte[] m = ("m" + i).getBytes();
            Signature s = Signature.getInstance("Ed25519"); s.initSign(kp.getPrivate()); s.update(m);
            byte[] sg = s.sign();
            byte[] raw = kp.getPublic().getEncoded(); byte[] pub = Arrays.copyOfRange(raw, raw.length - 32, raw.length);
            if (Ed25519Strict.verify(pub, m, sg)) ok++;
        }
        System.out.println("JDK-signed signatures accepted by strict verifier: " + ok + "/200");
    }
}
