package certificates;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CertificateGenerator {

	//registracija providera
	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	public X509Certificate generateCertificate(IssuerData issuerData, SubjectData subjectData) {
		try {

			//posto klasa za generisanje sertifiakta ne moze da primi direktno privatni kljuc
			//pravi se builder za objekat koji ce sadrzati privatni kljuc i koji 
			//ce se koristiti za potpisivanje sertifikata
			//parametar je koji algoritam se koristi za potpisivanje sertifiakta
			JcaContentSignerBuilder builder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
			//koji provider se koristi
			builder = builder.setProvider("BC");

			//objekat koji ce sadrzati privatni kljuc i koji ce se koristiti za potpisivanje sertifikata
			ContentSigner contentSigner = builder.build(issuerData.getPrivateKey());

			//postavljaju se podaci za generisanje sertifiakta
			X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(issuerData.getX500name(),
					new BigInteger(subjectData.getSerialNumber()),
					subjectData.getStartDate(),
					subjectData.getEndDate(),
					subjectData.getX500name(),
					subjectData.getPublicKey());
			//generise se sertifikat
			X509CertificateHolder certHolder = certGen.build(contentSigner);

			//certGen generise sertifikat kao objekat klase X509CertificateHolder
			//sad je potrebno certHolder konvertovati u sertifikat
			//za to se koristi certConverter
			JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();
			certConverter = certConverter.setProvider("BC");

			//konvertuje objekat u sertifikat i vraca ga
			return certConverter.getCertificate(certHolder);

		} catch (CertificateEncodingException e) {
			e.printStackTrace();
			return null;
		} catch (IllegalArgumentException e) {
			e.printStackTrace();
			return null;
		} catch (IllegalStateException e) {
			e.printStackTrace();
			return null;
		} catch (OperatorCreationException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		}
	}

	public KeyPair generateKeyPair() {
		try {
			//generator para kljuceva
			KeyPairGenerator   keyGen = KeyPairGenerator.getInstance("RSA");
			//inicijalizacija generatora, 1024 bitni kljuc
			keyGen.initialize(1024);

			//generise par kljuceva
			KeyPair pair = keyGen.generateKeyPair();

			return pair;

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

}
