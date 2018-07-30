package client;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.security.KeyStore;
import java.util.Scanner;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientHandlerException;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;

import encryption.EncryptKEK;
import signature.SignEnveloped;

public class Sender {

	public static void main(String[] args) {
		
		String senderId = "";
		String recipientId = "";
		String messageText = "";
		File test = null;
		Scanner sc = new Scanner(System.in);
		
		System.out.println("Unesite vas ID:");
		senderId = sc.nextLine();
		test = new File("./data/" + senderId + ".jks");
		if (!test.exists()) {
			System.out.println("Taj ID ne postoji.");
			sc.close();
			return;
		}
		
		if (!checkSenderID(senderId)) {
			System.out.println("Vas ID se ne poklapa sa vasim sertifikatom.");
			sc.close();
			return;
		}
		
		System.out.println("Unesite ID primaoca:");
		recipientId = sc.nextLine();
		test = new File("./data/" + recipientId + ".jks");
		if (!test.exists()) {
			System.out.println("Taj ID ne postoji.");
			sc.close();
			return;
		}
		
		System.out.println("Unesite tekst poruke:");
		messageText = sc.nextLine();
		
		String rawMessage =
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				+ "<message>\n"
				+ "<recipientId>" + recipientId + "</recipientId>\n"
				+ "<senderId>" + senderId + "</senderId>\n"
				+ "<messageText>" + messageText + "</messageText>\n"
				+ "</message>";
		
		Document xmlMessage = string2Doc(rawMessage);
		SignEnveloped sign = new SignEnveloped();
		Document signed = sign.signXML(xmlMessage, senderId);
		EncryptKEK encrypt = new EncryptKEK();
		Document encrypted = encrypt.encryptXML(signed, senderId, recipientId);
		
		try {
			post(encrypted);
			System.out.println("Poruka uspesno poslata!");
		} catch (UniformInterfaceException e) {
			e.printStackTrace();
		} catch (ClientHandlerException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}
		sc.close();
	}
	
	private static boolean checkSenderID(String senderId) {
		try {
			KeyStore ks = KeyStore.getInstance("JKS", "SUN");
			BufferedInputStream in = new BufferedInputStream(new FileInputStream("./data/" + senderId + ".jks"));
			ks.load(in, (senderId + "10").toCharArray());
			if (ks.isKeyEntry(senderId)) {
				return true;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	private static URI getBaseURI() {
		return UriBuilder.fromUri("http://localhost:8080/SecurIM").build();
	}

	public static void post(Document doc) throws UniformInterfaceException,
			ClientHandlerException, TransformerException {
		ClientConfig config = new DefaultClientConfig();
		Client client = Client.create(config);
		WebResource service = client.resource(getBaseURI());

		service.path("messages").accept(MediaType.TEXT_PLAIN)
				.post(doc2string(doc));
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
			document = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder()
					.parse(new ByteArrayInputStream(string.getBytes()));
		} catch (SAXException | IOException | ParserConfigurationException e) {
			e.printStackTrace();
			System.out.println(e.getMessage());
		}
		return document;
	}
}
