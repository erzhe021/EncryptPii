import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class JavaInterop {
    public static void main(String[] args) throws Exception {
        Scanner input = new Scanner(System.in, StandardCharsets.UTF_8);
        Base64.Decoder decoder = Base64.getDecoder();
        var privateKey = KeyFactory.getInstance("RSA").generatePrivate(
            new PKCS8EncodedKeySpec(decoder.decode(input.nextLine()))
        );
        // Match SessionKeyService's default JCA OAEP parameters, not Forge.
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        var sessionKey = new SecretKeySpec(rsa.doFinal(decoder.decode(input.nextLine())), "AES");
        byte[] requestIv = decoder.decode(input.nextLine());
        byte[] requestData = decoder.decode(input.nextLine());
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(128, requestIv));
        byte[] plain = aes.doFinal(requestData);
        byte[] responseIv = new byte[12];
        new SecureRandom().nextBytes(responseIv);
        aes.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(128, responseIv));
        System.out.println(Base64.getEncoder().encodeToString(responseIv));
        System.out.println(Base64.getEncoder().encodeToString(aes.doFinal(plain)));
    }
}
