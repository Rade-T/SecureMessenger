package client;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import certificates.CertificateGenerator;
import certificates.IssuerData;
import certificates.KeyStoreReader;
import certificates.KeyStoreWriter;
import certificates.SubjectData;

public class CertGen {

	public static void main(String[] args) throws ParseException {
		KeyStoreReader ksr = new KeyStoreReader();
		generateCA();
		generateSigned("A", "A", "A", "ftn", "uns", "srbija", "a@email.com", ksr);
		generateSigned("B", "B", "B", "ftn", "uns", "srbija", "b@email.com", ksr);
		generateSigned("C", "C", "C", "ftn", "uns", "srbija", "c@email.com", ksr);
		importCertificate("A", "B");
		importCertificate("B", "A");
		//certificateImportTest();
	}
	
	private static void certificateImportTest() {
		KeyStoreReader ksr = new KeyStoreReader();
		try {
			generateSigned("C", "C", "C", "ftn", "uns", "srbija", "c@email.com", ksr);
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new BufferedInputStream(new FileInputStream("./data/C.jks")), "C10".toCharArray());
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream("./data/B.cer"));
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Certificate cert = cf.generateCertificate(bis);
			ks.setCertificateEntry("b", cert);
			ks.store(new FileOutputStream("./data/C.jks"), "C10".toCharArray());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static boolean importCertificate(String senderId, String receiverId) {
		boolean success = false;
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			ks.load(new BufferedInputStream(new FileInputStream("./data/" + senderId + ".jks")), (senderId + "10").toCharArray());
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream("./data/" + receiverId + ".cer"));
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			Certificate cert = cf.generateCertificate(bis);
			ks.setCertificateEntry(receiverId, cert);
			ks.store(new FileOutputStream("./data/" + senderId + ".jks"), (senderId + "10").toCharArray());
			success = true;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return success;
	}
	
	public static void generateCA() throws ParseException {
		CertificateGenerator gen = new CertificateGenerator();
		KeyPair keyPair = gen.generateKeyPair();
		
		SimpleDateFormat iso8601Formater = new SimpleDateFormat("yyyy-MM-dd");
		Date startDate = iso8601Formater.parse("2007-12-31");
		Date endDate = iso8601Formater.parse("2017-12-31");
		
		//podaci o vlasniku i izdavacu posto je self signed 
		//klasa X500NameBuilder pravi X500Name objekat koji nam treba
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
	    builder.addRDN(BCStyle.CN, "Rade Tontic");
	    builder.addRDN(BCStyle.SURNAME, "Tontic");
	    builder.addRDN(BCStyle.GIVENNAME, "Rade");
	    builder.addRDN(BCStyle.O, "UNS-FTN");
	    builder.addRDN(BCStyle.OU, "Katedra za informatiku");
	    builder.addRDN(BCStyle.C, "RS");
	    builder.addRDN(BCStyle.E, "rtontic@gmail.com");
	    //UID (USER ID) je ID korisnika
	    builder.addRDN(BCStyle.UID, "123445");
		
	    //Serijski broj sertifikata
		String sn="1";
		//kreiraju se podaci za issuer-a
		IssuerData issuerData = new IssuerData(keyPair.getPrivate(), builder.build());
		//kreiraju se podaci za vlasnika
		SubjectData subjectData = new SubjectData(keyPair.getPublic(), builder.build(), sn, startDate, endDate);
		
		//generise se sertifikat
		X509Certificate cert = gen.generateCertificate(issuerData, subjectData);
		
		KeyStoreWriter keyStoreWriter = new KeyStoreWriter();
		keyStoreWriter.loadKeyStore(null, "ca_password".toCharArray());
		keyStoreWriter.write("certauthority", keyPair.getPrivate(), "ca_password".toCharArray(), cert);
		keyStoreWriter.saveKeyStore("./data/ca.jks", "ca_password".toCharArray());
		
	}
	
	public static void generateSigned(String commonName, String surname,
			String givenName, String orgName, String orgUnit, String country,
			String email, KeyStoreReader keyStoreReader) throws ParseException {
		
		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		builder.addRDN(BCStyle.CN, commonName);
		builder.addRDN(BCStyle.SURNAME, surname);
		builder.addRDN(BCStyle.GIVENNAME, givenName);
		builder.addRDN(BCStyle.O, orgName);
		builder.addRDN(BCStyle.OU, orgUnit);
		builder.addRDN(BCStyle.C, country);
		builder.addRDN(BCStyle.E, email);
		// UID (USER ID) je ID korisnika
		builder.addRDN(BCStyle.UID, "123445");

		CertificateGenerator cg = new CertificateGenerator();

		KeyPair keyPair = cg.generateKeyPair();

		Date startDate = null;
		Date endDate = null;
		final java.util.Calendar cal = GregorianCalendar.getInstance();
		startDate = cal.getTime();
		cal.setTime(startDate);
		cal.add(GregorianCalendar.YEAR, 2); // sertifikat traje 2 godine od
		// datuma kreiranja
		endDate = cal.getTime();
		String sn = "2";

		IssuerData issuerData = null;
		try {
			issuerData = keyStoreReader.readKeyStore("./data/ca.jks", "certauthority", "ca_password".toCharArray(), "ca_password".toCharArray());
		} catch (ParseException e) {
			e.printStackTrace();
		}
		// kreiraju se podaci za vlasnika
		SubjectData subjectData = new SubjectData(keyPair.getPublic(),
				builder.build(), sn, startDate, endDate);

		// generise se sertifikat
		X509Certificate cert = cg.generateCertificate(issuerData, subjectData);
		
		try {
			File file = new File("./data/" + commonName + ".cer");
		    byte[] buf = cert.getEncoded();
	
		    FileOutputStream os = new FileOutputStream(file);
		    os.write(buf);
		    os.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		// kreira se keystore, ucitava ks fajl, dodaje kljuc i sertifikat i
		// sacuvaju se izmene
		KeyStoreWriter keyStoreWriter = new KeyStoreWriter();
		keyStoreWriter.loadKeyStore(null, (commonName + "1").toCharArray());
		keyStoreWriter.write(commonName, keyPair.getPrivate(), (commonName + "1").toCharArray(), cert);
		keyStoreWriter.saveKeyStore("./data/" + commonName + ".jks", (commonName + "10").toCharArray());

		// ispis na konzolu
		System.out.println("ISSUER: " + cert.getIssuerX500Principal().getName());
		System.out.println("SUBJECT: " + cert.getSubjectX500Principal().getName());
		System.out.println("Sertifikat:");
		System.out.println("-------------------------------------------------------");
		System.out.println(cert);
		System.out.println("-------------------------------------------------------");
		try {
			cert.verify(keyStoreReader.readPublicKey());
			System.out.println("Validacija uspešna.");
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			System.out.println("Validacija neuspešna");
			e.printStackTrace();
		}
	}

}
