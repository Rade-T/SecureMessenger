package encryption;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.keys.KeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import client.CertGen;

//Generise tajni kljuc
//Kriptije sadrzaj elementa student tajnim kljucem
//Kriptuje tajni kljuc javnim kljucem
//Kriptovani tajni kljuc se stavlja kao KeyInfo kriptovanog elementa
public class EncryptKEK {
	
    static {
    	//staticka inicijalizacija
        Security.addProvider(new BouncyCastleProvider());
        org.apache.xml.security.Init.init();
    }
    
    public Document encryptXML(Document doc, String senderId, String recipientId) {
		SecretKey secretKey = generateDataEncryptionKey();
		Certificate cert = readCertificate(senderId, recipientId);
		doc = encrypt(doc, secretKey, cert);
		return doc;
	}
	
	/**
	 * Ucitava sertifikat is KS fajla
	 * alias primer
	 */
	private Certificate readCertificate(String senderId, String recipientId) {
		try {
			//kreiramo instancu KeyStore
			KeyStore ks = KeyStore.getInstance("JKS", "SUN");
			//ucitavamo podatke
			BufferedInputStream in = new BufferedInputStream(new FileInputStream("./data/" + senderId + ".jks"));
			ks.load(in, (senderId + "10").toCharArray());
			
			if(ks.isCertificateEntry(recipientId)) {
				Certificate cert = ks.getCertificate(recipientId);
				return cert;
			}
			else if (CertGen.importCertificate(senderId, recipientId)) {
				return readCertificate(senderId, recipientId);
			}
			else
				return null;
			
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return null;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			return null;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		} catch (CertificateException e) {
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} 
	}
	
	/**
	 * Generise tajni kljuc
	 */
	private SecretKey generateDataEncryptionKey() {

        try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede"); //Triple DES
			return keyGenerator.generateKey();
		
        } catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
    }
	
	/**
	 * Kriptuje sadrzaj prvog elementa odsek
	 */
	private Document encrypt(Document doc, SecretKey key, Certificate certificate) {
		
		try {
			
		    //cipher za kriptovanje XML-a
		    XMLCipher xmlCipher = XMLCipher.getInstance(XMLCipher.TRIPLEDES);
		    //inicijalizacija za kriptovanje
		    xmlCipher.init(XMLCipher.ENCRYPT_MODE, key);
		    
		    
		    //cipher za kriptovanje tajnog kljuca,
			//Koristi se Javni RSA kljuc za kriptovanje
			XMLCipher keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);
		    //inicijalizacija za kriptovanje tajnog kljuca javnim RSA kljucem
		    keyCipher.init(XMLCipher.WRAP_MODE, certificate.getPublicKey());
		    EncryptedKey encryptedKey = keyCipher.encryptKey(doc, key);
		    
		    //u EncryptedData elementa koji se kriptuje kao KeyInfo stavljamo kriptovan tajni kljuc
		    EncryptedData encryptedData = xmlCipher.getEncryptedData();
	        //kreira se KeyInfo
		    KeyInfo keyInfo = new KeyInfo(doc);
		    keyInfo.addKeyName("Kriptovani tajni kljuc");
	        //postavljamo kriptovani kljuc
		    keyInfo.add(encryptedKey);
		    //postavljamo KeyInfo za element koji se kriptuje
	        encryptedData.setKeyInfo(keyInfo);
			
			//trazi se element ciji sadrzaj se kriptuje
			NodeList poruke = doc.getElementsByTagName("messageText");
			Element poruka = (Element) poruke.item(0);
			
			xmlCipher.doFinal(doc, poruka, true); //kriptuje sa sadrzaj
			
			return doc;
			
		} catch (XMLEncryptionException e) {
			e.printStackTrace();
			return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
