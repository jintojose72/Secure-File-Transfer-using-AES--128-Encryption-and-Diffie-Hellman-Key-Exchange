//Incorporate the AES-128 encryption/decryption into your program.
// Server Side
package connection;
import java.net.*;
import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.*;

import connection.LSLAESCrypto.*;

import java.security.*;
import java.security.cert.CertificateException;
public class ServerSide { 
  final static String myIV = "89ABCDEF0123456789ABCDEF01234567";
  public void readFromFileWriteToClient(String argv[]) {
	    FileInputStream fis = null;
		BufferedInputStream bis = null;
		OutputStream os = null;
		SSLSocket server=null;
	try {
		int serverPort;//server is listening for connection request on port via TCP.
		//ServerSocket s = new ServerSocket(serverPort);
		
			if (argv.length > 1) {
	          
	            throw new Exception("Wrong number of command options");
	        } else if (argv.length == 1) {
	        	serverPort=Integer.parseInt(argv[0]);
	        }else{
	        	serverPort=7777;
	        }
		
		
		System.setProperty("javax.net.ssl.keyStore", "keystoreFile.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "password");
		KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("keystoreFile.jks"), "password".toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, "password".toCharArray());

		TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); 
		tmf.init(ks);

		SSLContext sc = SSLContext.getInstance("TLS"); 
		TrustManager[] trustManagers = tmf.getTrustManagers(); 
		sc.init(kmf.getKeyManagers(), trustManagers, null); 

		SSLServerSocketFactory ssf = sc.getServerSocketFactory(); 
		SSLServerSocket s = (SSLServerSocket) ssf.createServerSocket(serverPort);
		s.setSoTimeout(50000);//set Time out
		System.out.println("Server : Server Started on Port Number "+serverPort+"\n"); 
		System.out.println("Server : Waiting for client\n"); 
		System.out.println("--------------------------Waiting for client-----------------------------------------\n"); 
		server = (SSLSocket) s.accept();
		//key exchange
		System.out.println("Server : Connection Recieved from Client\n"); 
		
		
		//KeyExchangeServer.ServerKey(server);
		String myKey = null;
		
		try {
			myKey=DHKeyAgreement2Server.run(server);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//System.out.println("Server Sharerd Key : "+ myKey);
		
		try{
			//ta.textToASCII();
			//e.encryption();
			//myKey = "97D3E76701AC5DA71D31B0BB8077AA36";
			
			String myMsg = "";
	        
			final LSLAESCrypto aes = new LSLAESCrypto(
				LSLAESCryptoMode.CFB,
				LSLAESCryptoPad.NONE,
				128, myKey,
				myIV);
			System.out.println("Server : Diffie-Hellman KeyExchange is Complete.\n"); 
			System.out.println("----------------------Encryption---------------------------------------------\n"); 
			
			System.out.println("Server : Starting Encryption of File to send using AES-128\n"); 
			
			System.out.println("Server : Reading from Input File 'inputMessage.txt'\n"); 
			
			BufferedReader file = new BufferedReader(new FileReader("inputMessage.txt"));
			String line="";
			while ((line=file.readLine())!=null){
				
				myMsg=myMsg+line;
				myMsg=myMsg+"\n";
			}
			System.out.println("----------------------File to be sent---------------------------------------------"); 
			System.out.println("File : inputMessage.txt");
			System.out.println("----------------------inputMessage.txt---------------------------------------------");
			System.out.println(myMsg); 
			System.out.println("----------------------------------------------------------------------------------\n");
			System.out.println("Server : Encryption Completed.'encrypt.txt' is generated");
			System.out.println("----------------------Encrypted File---------------------------------------------"); 
			System.out.println("File : encrypt.txt");
			System.out.println("----------------------encrypt.txt---------------------------------------------");
			System.out.println(aes.encrypt(myMsg)+"\n");
			System.out.println("------------------------------------------------------------------------------------\n"); 
	        PrintWriter pw = new PrintWriter(new FileWriter("encrypt.txt"));
	        pw.printf(aes.encrypt(myMsg));
	        pw.close();
	        file.close();
	        
		}
		catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		 
		
		System.out.println("----------------------Sending encrypted file---------------------------------------------\n"); 
		//server = s.accept();//to listen for incoming connection requests from clients.
		File myFile = new File ("encrypt.txt");
        byte [] byteArray  = new byte [(int)myFile.length()];
        bis = new BufferedInputStream(new FileInputStream(myFile));
        bis.read(byteArray,0,byteArray.length);
        os = server.getOutputStream();
        System.out.println("Server : Sending encrypted file to the Client \n");
        os.write(byteArray,0,byteArray.length);
        os.flush();
        System.out.println("Done! Secure file Transfer is Complete\n");	
        System.out.println("Used:");
        System.out.println("------------------------Used-------------------------------------------\n");
        System.out.println("1.Connection between Server and Client using SSL\n");
        System.out.println("2.File Encryption/Decryption using AES-128\n");
        System.out.println("2.File Encryption/Decryption using Cipher Feedback Mode (CFB)\n");
        System.out.println("3.128 bit Key Exchange using Diffie-Hellman KeyExchange\n");
	}
	catch(UnknownHostException ex) {
		System.out.println("Host not found");
		ex.printStackTrace();
	}
	catch(IOException e){
		e.printStackTrace();//The Socket constructor throws an IOException if it cannot make a connection.
	} catch (KeyStoreException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (CertificateException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (UnrecoverableKeyException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (KeyManagementException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (Exception e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	finally {
		try{
          if (bis != null) bis.close();
          if (os != null) os.close();
          if (server!=null) server.close();
		}
		catch(IOException e){
		e.printStackTrace();//The Socket constructor throws an IOException if it cannot make a connection.
	}
        }
  }
  public static void main(String[] args) {
		//TextToASCII ta=new TextToASCII();
		ServerSide s = new ServerSide();
		//Encryption e=new Encryption();
		
		s.readFromFileWriteToClient(args);
  }
}