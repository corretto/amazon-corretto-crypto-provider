import java.security.Provider;
import java.security.Security;
import javax.crypto.Cipher;

public class TestCfb {
    public static void main(String[] args) throws Exception {
        // Load the provider
        Provider provider = (Provider) Class.forName("com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider")
                .getField("INSTANCE").get(null);
        Security.insertProviderAt(provider, 1);
        
        // Print all providers
        System.out.println("Providers:");
        for (Provider p : Security.getProviders()) {
            System.out.println("  " + p.getName() + " - " + p.getInfo());
        }
        
        // Print all cipher algorithms in the provider
        System.out.println("\nCipher algorithms in AmazonCorrettoCryptoProvider:");
        for (Provider.Service service : provider.getServices()) {
            if (service.getType().equals("Cipher")) {
                System.out.println("  " + service.getAlgorithm());
            }
        }
        
        // Try to get the AES/CFB/NoPadding cipher
        try {
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", provider);
            System.out.println("\nSuccessfully got AES/CFB/NoPadding cipher from provider");
        } catch (Exception e) {
            System.out.println("\nFailed to get AES/CFB/NoPadding cipher: " + e);
        }
        
        // Try with SunJCE provider
        try {
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
            System.out.println("Successfully got AES/CFB/NoPadding cipher from SunJCE");
        } catch (Exception e) {
            System.out.println("Failed to get AES/CFB/NoPadding cipher from SunJCE: " + e);
        }
    }
}