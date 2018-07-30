package client;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.util.Scanner;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;

import encryption.DecryptKEK;
import signature.VerifySignatureEnveloped;

public class Receiver {

	public static void main(String[] args) {
		Document doc = null;
		Document decrypted = null;
		DecryptKEK decrypt = new DecryptKEK();
		VerifySignatureEnveloped verify = new VerifySignatureEnveloped();
		boolean potpisana = false;
		
		Scanner sc = new Scanner(System.in);
		String recipientId = "";
		System.out.println("Unesite vas ID:");
		recipientId = sc.nextLine();
		File test = new File("./data/" + recipientId + ".jks");
		if (!test.exists()) {
			System.out.println("Taj ID ne postoji.");
			sc.close();
			return;
		}
		
		System.out.println("1. Prikazi samo tekst poruka\n2. Prikazi ceo XML");
		int izbor = sc.nextInt();
		System.out.println();
		
		Integer i = 1;
		while ((doc = get(recipientId, i.toString())) != null) {
			decrypted = decrypt.decryptXML(doc, recipientId);
			switch(izbor) {
			case 1:
				NodeList poruke = decrypted.getElementsByTagName("messageText");
				NodeList senders = decrypted.getElementsByTagName("senderId");
				Element poruka = (Element) poruke.item(0);
				Element sender = (Element) senders.item(0);
				System.out.println("Poslao: " + sender.getTextContent());
				System.out.println(poruka.getTextContent());
				break;
			case 2:
				try {
					System.out.println(doc2string(decrypted));
				} catch (TransformerException e) {
					e.printStackTrace();
				}
			}
			potpisana = verify.verifyXML(doc);
			if (potpisana) {
				System.out.println("Poruka je potpisana!");
			} else {
				System.out.println("Poruka nije potpisana!");
			}
			System.out.println();
			i++;
		}
		sc.close();
	}

	private static URI getBaseURI() {
		return UriBuilder.fromUri("http://localhost:8080/SecurIM").build();
	}

	public static Document get(String userId, String messageid) {
		ClientConfig config = new DefaultClientConfig();
		Client client = Client.create(config);
		String message = null;
		WebResource service = client.resource(getBaseURI());
		try {
			message = service.path("messages").path(userId).path(messageid)
					.accept(MediaType.TEXT_PLAIN).get(String.class);
		} catch (Exception ex) {
			return null;
		}
		if (message != null) {
			return string2Doc(message);

		}
		return null;

	}

	private static String doc2string(Document doc) throws TransformerException {
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer transformer = tf.newTransformer();
		StringWriter writer = new StringWriter();
		transformer.transform(new DOMSource(doc), new StreamResult(writer));
		String output = writer.getBuffer().toString();
		return output;
	}
	
	private static Document string2Doc(String string) {

		Document document = null;
		try {
			
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			document = db.parse(new ByteArrayInputStream(string.getBytes()));
		} catch (SAXException | IOException | ParserConfigurationException e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
		}
		return document;
	}
}
