package client;

import java.io.File;
import java.text.ParseException;
import java.util.Scanner;

import certificates.KeyStoreReader;

public class UserGen {

	public static void main(String[] args) {
		String commonName = "";
		String surname = "";
		String givenName = "";
		String email = "";
		File test = null;
		Scanner sc = new Scanner(System.in);
		do {
			System.out.println("Zeljeni ID:");
			commonName = sc.nextLine();
			test = new File("./data/" + commonName + ".jks");
		} while (test.exists());
		System.out.println("Ime:");
		givenName = sc.nextLine();
		System.out.println("Prezime:");
		surname = sc.nextLine();
		System.out.println("Email:");
		email = sc.nextLine();
		
		KeyStoreReader ksr = new KeyStoreReader();
		try {
			CertGen.generateSigned(commonName, surname, givenName, "ftn", "uns", "srbija", givenName, ksr);
			System.out.println("Generacija uspesna!");
		} catch (ParseException e) {
			e.printStackTrace();
		}
	}

}
