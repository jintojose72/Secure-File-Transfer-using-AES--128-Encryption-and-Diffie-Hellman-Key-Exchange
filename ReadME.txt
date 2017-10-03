The Objective of the project is as follows:

1. Establish SSL Socket Connection between Server and Client using SSL certificates.

2. Establish Shared Key between Client and Server using Diffie-Hellman Key Exchange Protocol

3. Encrypt the File to be sent from the Server with AES-128 Encryption using the Shared key established with the Diffie-Hellman Key Exchange.

4. The Encrypted file is sent from the server to Client across the SSL connection

5. Once the Encrypted File received at the Client side, the Client decrypts the encrypted file using AES-128 Decryption using the Shared key established with the Diffie-Hellman Key Exchange.

Steps to Run the Project

There are two ways to run the program.
----------------------------------------------------------------------------------------------------------------
Run the Program using Client/Server jar
----------------------------------------------------------------------------------------------------------------
1.Executable_Jar
	1.SSLClient_Jar
		1.SSLClient.jar
		2.keystoreFile.jks
	2.SSLServer_Jar
		1.SSLServer.jar
		2.keystoreFile.jks
		3.inputMessage.txt
Description: This is readily Executable Jars
Steps to Execute
------------------
Running the Server:
-------------------
1.open Terminal and move to the folder 'SSLServer_Jar' using the command 'cd'
2.Make sure all the three files namely SSLServer.jar,keystoreFile.jks,inputMessage.txt are present.
3.run the command 'java -jar SSLServer.jar'
This will run the Server at default port:7777
To Run the SSLServer on a different port run :'java -jar SSLServer.jar portnumber'
Where 'portnumber' is the port to the server example : 'java -jar SSLServer.jar 7000'
Now the Server is running on the respective port.
------------------
Running the Client:
-------------------
4.Open another Terminal and move to the folder 'SSLClient_Jar' using the command 'cd'
5.Make sure all the three files namely SSLClient.jar,keystoreFile.jks are present.
6.Know the hostname of the server and the port number on which server is listening.
7.run the command 'java -jar SSLClient.jar hostname portnumber '
hostname-hostname of the server.If running the Server and Client on same machine then hostname is 'localhost'
portnumber-port number the server is listening.
example: 'java -jar SSLClient.jar localhost 7777'
------------------
Results:
-------------------
Connection are establish and files are transferred.
1.encrypt.txt is created at the serverside using the 'inputmessage.txt' and sent to client.
2.client receives the encrypted message and stores in the file-'receive.txt'
3.client then decrypts the file-'receive.txt' to 'outputMessage.txt'


----------------------------------------------------------------------------------------------------------------
Run the program with Code in Eclipse
----------------------------------------------------------------------------------------------------------------
2.Eclipse_Project_Code:
This folder contains SSLServer.zip and SSLClient.zip files.
These are Eclipse archive project files.
To Setup the Project Code in Eclipse follow steps.
1.open Eclipse.
2.Go to File-->open projects from file system
3.Click on Archive and navigate and select the 'SSLServer.zip' in the file Browser.
4.Once file selected click on finsih.The SSLServer project is setup.
5.Similarly do the same steps from 1-3 and this time select 'SSLClient.zip'
6.SSLClient project is setup.
7.All the java code is present in the src folder for both server and client projects.
8.go to SSLServer->src->connection->Serverside.java and run Serverside.java
9.Similarly go to SSLClient->src->connection->Clientside.java and run Clientside.java
------------------
Results:
-------------------
Connection are establish and files are transferred.
1.encrypt.txt is created at the serverside using the 'inputmessage.txt' and sent to client.
2.client receives the encrypted message and stores in the file-'receive.txt'
3.client then decrypts the file-'receive.txt' to 'outputMessage.txt'




















