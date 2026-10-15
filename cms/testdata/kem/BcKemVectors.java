import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

// Writes DER EnvelopedData, without the ContentInfo wrapper as CMP carries it,
// with a Bouncy Castle KEMRecipientInfo for each key derivation variant the cms
// package decrypts.
public class BcKemVectors {
    static final byte[] PLAINTEXT = "go-pki-cmp KEM recipient vector".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    // main reads an ML-KEM SubjectPublicKeyInfo from standard input and writes the vectors into the directory args[0].
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Path out = Path.of(args[0]);
        byte[] spki = System.in.readAllBytes();
        PublicKey pub = KeyFactory.getInstance("ML-KEM", "BC").generatePublic(new X509EncodedKeySpec(spki));
        write(out, "default", pub, null, null, CMSAlgorithm.AES256_WRAP);
        write(out, "kdf3-sha256", pub, kdf(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha256, false), null, CMSAlgorithm.AES256_WRAP);
        write(out, "kdf3-sha256-null-ukm", pub, kdf(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha256, true), "user keying material".getBytes(java.nio.charset.StandardCharsets.US_ASCII), CMSAlgorithm.AES256_WRAP);
        write(out, "kdf3-sha512-aes128", pub, kdf(X9ObjectIdentifiers.id_kdf_kdf3, NISTObjectIdentifiers.id_sha512, false), null, CMSAlgorithm.AES128_WRAP);
        write(out, "kdf2-sha256", pub, kdf(X9ObjectIdentifiers.id_kdf_kdf2, NISTObjectIdentifiers.id_sha256, false), null, CMSAlgorithm.AES256_WRAP);
        write(out, "hkdf-sha256", pub, CMSAlgorithm.SHA256_HKDF, null, CMSAlgorithm.AES256_WRAP);
    }

    // kdf returns an X9.44 KDF AlgorithmIdentifier whose parameters name the hash, with NULL hash parameters when nullParams is set.
    static AlgorithmIdentifier kdf(ASN1ObjectIdentifier kdf, ASN1ObjectIdentifier hash, boolean nullParams) {
        AlgorithmIdentifier h = nullParams ? new AlgorithmIdentifier(hash, DERNull.INSTANCE) : new AlgorithmIdentifier(hash);
        return new AlgorithmIdentifier(kdf, h);
    }

    // write encrypts PLAINTEXT for pub with the KDF, UKM and wrap algorithm and saves it as <name>.der. A null kdf keeps the Bouncy Castle default.
    static void write(Path out, String name, PublicKey pub, AlgorithmIdentifier kdf, byte[] ukm, ASN1ObjectIdentifier wrap) throws Exception {
        JceKEMRecipientInfoGenerator recipient = new JceKEMRecipientInfoGenerator(new byte[] {1, 2, 3, 4}, pub, wrap).setProvider("BC");
        if (kdf != null) {
            recipient.setKDF(kdf);
        }
        if (ukm != null) {
            recipient.setUserKeyingMaterial(ukm);
        }
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(recipient);
        byte[] der = gen.generate(new CMSProcessableByteArray(PLAINTEXT), new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider("BC").build())
            .toASN1Structure().getContent().toASN1Primitive().getEncoded(ASN1Encoding.DER);
        Files.write(out.resolve(name + ".der"), der);
    }
}
