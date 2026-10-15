import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.EncryptedValueBuilder;
import org.bouncycastle.cert.crmf.jcajce.JceCRMFEncryptorBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AsymmetricKeyWrapper;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;

// Writes DER EncryptedValue (RFC 4211 §2.1) vectors that encrypt one certificate
// for an RSA key, with each content cipher and key transport the cms package decrypts.
public class BcEncryptedValueVectors {
    // main reads an RSA SubjectPublicKeyInfo from standard input and writes cert.der and the vectors into the directory args[0].
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Path out = Path.of(args[0]);
        PublicKey rsa = KeyFactory.getInstance("RSA", "BC").generatePublic(new X509EncodedKeySpec(System.in.readAllBytes()));
        X509CertificateHolder cert = certificate(rsa);
        Files.write(out.resolve("cert.der"), cert.getEncoded());

        JceAsymmetricKeyWrapper pkcs1 = new JceAsymmetricKeyWrapper(rsa).setProvider("BC");
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        JceAsymmetricKeyWrapper oaep = new JceAsymmetricKeyWrapper(oaepSpec, rsa).setProvider("BC");
        write(out, "des-ede3-pkcs1", cert, pkcs1, CMSAlgorithm.DES_EDE3_CBC);
        write(out, "aes128-pkcs1", cert, pkcs1, CMSAlgorithm.AES128_CBC);
        write(out, "aes256-pkcs1", cert, pkcs1, CMSAlgorithm.AES256_CBC);
        write(out, "aes256-oaep-sha256", cert, oaep, CMSAlgorithm.AES256_CBC);
    }

    // certificate returns a certificate for rsa signed by a throwaway P-256 key.
    static X509CertificateHolder certificate(PublicKey rsa) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-256"));
        KeyPair issuer = gen.generateKeyPair();
        X500Name name = new X500Name("CN=go-pki-cmp EncryptedValue vector");
        Date now = new Date();
        return new JcaX509v3CertificateBuilder(name, BigInteger.ONE, now, new Date(now.getTime() + 86_400_000L), name, rsa)
            .build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(issuer.getPrivate()));
    }

    // write encrypts cert with the key wrapper and content cipher and saves the EncryptedValue as <name>.der.
    static void write(Path out, String name, X509CertificateHolder cert, AsymmetricKeyWrapper wrapper, ASN1ObjectIdentifier cipher) throws Exception {
        EncryptedValueBuilder builder = new EncryptedValueBuilder(wrapper, new JceCRMFEncryptorBuilder(cipher).setProvider("BC").build());
        Files.write(out.resolve(name + ".der"), builder.build(cert).getEncoded(ASN1Encoding.DER));
    }
}
