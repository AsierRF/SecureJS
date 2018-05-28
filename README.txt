README.txt

Directories:
	- ChromeExtension: contains the extension to be installed in Chrome. It requires some configuration in the .json files.
	- clientSideApp: main application, client side app.
	- encryptionChecker: Tool to decrytp encrypted values with default or new keys.
	- encryptionGenerator: Tool to generate the data (JavaScript code) to be passed to the main client side app in Encryption Mode. It generates a hex encrypted value of the given text. There is a directory with created examples.
	- serverRemoteAttestation: Server code that is able to perform the EPID process for SecureJS.
	- signatureChecker: Tool to verify signature values with default or new keys.
	- signatureGenerator: Tool to generate the data (JavaScript code) to be passed to the main client side app in Signature Mode and also needed in Encryption Mode. It generates a hex signature value of the given text.
	- www: web page example to use SecureJS. Note that the Chrome extension id may change for your installation (Setup testPage.php according to your id). Setup the getData.php to store the data received in the right path.

Extra: All "Enclave" directories require a pem private key in order to sign he code during the building process. This is required by SGX. If you are familiar with SGX you will understand what this key is.

The flow is the following:
	Setup: Build every tool and client and server side app (Makefiles should do the work). Install the Chrome Extension.
	1- Use signatureGenerator and/or encryptionGenerator to create a signature and/or encryption.
	2- Set the values in testPage.php
	3- Surf to to testPage.php
	4- If everything went fine, you should have a data file where you configured getData.php.
	5- Use the signatureChecker and/or encryptionChecker to verify and decrypt the data received.

I will try to put the demo video and a graph of SecureJS architecture.

Sorry for the code not being the prettiest one, the goal was to create a proof of concept that worked :P