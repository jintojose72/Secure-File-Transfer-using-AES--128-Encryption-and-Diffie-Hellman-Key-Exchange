//Incorporate the AES-128 encryption/decryption into your program.
// Client Side
package connection;
import java.io.*;
import java.net.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.CertificateException;

import connection.LSLAESCrypto.*;

public class ClientSide {
  static String myIV=null;
  public void run(String argv[]) {
	FileOutputStream fos = null;
	BufferedOutputStream bos = null;
	SSLSocket socket = null;
	int read;
    int c = 0;
	try {
		int serverPort = 7777;
		String hostname="localhost";
		if (argv.length > 2) {
          
            throw new Exception("Wrong number of command options");
        } else if (argv.length == 2) {
        	hostname=argv[0];
        	serverPort=Integer.parseInt(argv[1]);
        }else if (argv.length == 1){
        	hostname=argv[0];
        	serverPort=7777;
        }else if(argv.length == 0){
        	hostname="localhost";
        	serverPort=7777;
        }
		
		
		InetAddress host = InetAddress.getByName(hostname); //
		System.out.println("Client : Connecting to server on port " + serverPort+"\n"); 
		//socket = new Socket(host,serverPort); //Connected with Server with host and port like 127.0.0.1:7777
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

		SSLSocketFactory ssf = sc.getSocketFactory();  
		socket = (SSLSocket) ssf.createSocket(host, serverPort);
        socket.startHandshake();
	
		System.out.println("Client : Connected to " + socket.getRemoteSocketAddress()+"\n");
		//key exchange
		
		
		//KeyExchangeClient.ClientKey(socket);
		String myKey=null;
		try {
			myKey=DHKeyAgreement2Client.run(socket);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		System.out.println("Client : Diffie-Hellman KeyExchange is Complete.\n"); 
		System.out.println("----------------------Receiving File from Server---------------------------------------------\n"); 
		
		
		byte [] mybytearray  = new byte [5555555];
        InputStream is = socket.getInputStream();
        fos = new FileOutputStream("receive.txt");
        bos = new BufferedOutputStream(fos);
        read = is.read(mybytearray,0,mybytearray.length);
        c = read;
	   
		do {
         read =
            is.read(mybytearray, c, (mybytearray.length-c));
         if(read >= 0) c += read;
      } while(read > -1);
	
      bos.write(mybytearray, 0 , c);
      bos.flush();
      System.out.println("Client : File received from Server saved in 'receive.txt'\n"); 
      BufferedReader file1 = new BufferedReader(new FileReader("receive.txt"));
      String myMsg1 = "";
		String line1="";
		while ((line1=file1.readLine())!=null){
			
			myMsg1=myMsg1+line1;
			myMsg1=myMsg1+"\n";
		}
		file1.close();
	  System.out.println("----------------------Encrypted File Received from Server---------------------------------------------");
	  
	  System.out.println("File : receive.txt\n"); 
	  System.out.println("----------------------receive.txt---------------------------------------------");
	  System.out.println(myMsg1); 
	  System.out.println("------------------------------------------------------------------------------------------");
      System.out.println("----------------------Decryption-------------------------------------------------------------------------\n");
	  
	  
	   // myKey = "97D3E76701AC5DA71D31B0BB8077AA36";
		//final String myIV = "89ABCDEF0123456789ABCDEF01234567";
		String myMsg="";
		//System.out.println("Client Sharerd Key : "+ myKey);

		try {
			LSLAESCrypto aes = new LSLAESCrypto(
				LSLAESCryptoMode.CFB,
				LSLAESCryptoPad.NONE,
				128, myKey,
				myIV);
			
			BufferedReader file = new BufferedReader(new FileReader("receive.txt"));
			String line="";
			while ((line=file.readLine())!=null){
				
				myMsg=myMsg+line;
			}
	        PrintWriter pw = new PrintWriter(new FileWriter("outputMessage.txt"));
	        pw.printf(aes.decrypt(myMsg));
	        System.out.println("Client : File decryption is complete and  saved in 'outputMessage.txt'\n"); 
	        System.out.println("----------------------File received from Server---------------------------------------------");
	        System.out.println("File : outputMessage.txt\n");
	        System.out.println("----------------------outputMessage.txt---------------------------------------------");
	        System.out.println(aes.decrypt(myMsg));
	        System.out.println("------------------------------------------------------------------------------------------");
	        System.out.println("Closing Connection with Server----------------------------------------------------------------------------\n");
	        pw.close();
	        file.close();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch blocks
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
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
      if (fos != null) fos.close();
      if (bos != null) bos.close();
      if (socket != null) socket.close();
	  }
		catch(IOException e){
		e.printStackTrace();//The Socket constructor throws an IOException if it cannot make a connection.
	}
    }
	}
	public static void main(String[] args) {
		ClientSide c = new ClientSide();
		c.run(args);
		
  }
}