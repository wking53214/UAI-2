import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Conformance adapter: one JSON request per line on stdin, one JSON answer per line on stdout. */
public final class Adapter {
    public static void main(String[] args) throws Exception {
        Thread t = new Thread(null, () -> {
            try { run(); } catch (IOException e) { throw new UncheckedIOException(e); }
        }, "adapter", 1L << 29);
        t.start();
        t.join();
    }

    @SuppressWarnings("unchecked")
    static void run() throws IOException {
        Receiver r = new Receiver();
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        PrintStream out = new PrintStream(new FileOutputStream(FileDescriptor.out), false, StandardCharsets.UTF_8);
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) continue;
            String answer;
            try {
                Map<String, Object> req = (Map<String, Object>) Json.read(line, true);
                String op = (String) req.get("op");
                if ("reset".equals(op)) { r.reset(); answer = "{\"ok\":true}"; }
                else if ("receive".equals(op)) {
                    try {
                        String d = r.receive((String) req.get("wire_text"), ((java.math.BigInteger) req.get("now")).longValueExact(),
                                (List<String>) req.get("trust"), (String) req.get("audience"), (List<String>) req.get("kinds"),
                                Boolean.TRUE.equals(req.get("ledger")));
                        answer = "{\"accept\":{\"digest\":\"" + d + "\"}}";
                    } catch (Json.Refusal e) {
                        answer = "{\"refuse\":\"" + e.code + "\"}";
                    } catch (StackOverflowError | OutOfMemoryError e) {
                        answer = "{\"refuse\":\"malformed\"}"; // fail closed
                    }
                } else answer = "{\"refuse\":\"malformed\"}";
            } catch (RuntimeException e) {
                answer = "{\"refuse\":\"malformed\"}";
            }
            out.print(answer + "\n");
            out.flush();
        }
    }
}
