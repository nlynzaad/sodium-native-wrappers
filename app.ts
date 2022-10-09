import {
	generateRandomValue,
	IHashInput,
	bulk_Decrypt_SharedBox,
	bulk_Encrypt_SharedBox,
	createHash,
	decrypt_SealedBox,
	decrypt_SecretBox,
	decrypt_SharedBox,
	encrypt_SealedBox,
	encrypt_SecretBox,
	encrypt_SharedBox,
	generateKeyPair,
	generateKeyPairFromPassword,
	generateSecretKey,
	generateSecretKeyFromPassword,
	generateSharedKey,
	hashPassword,
	stringifyHashResult,
	verifyHash,
	verifyPassword,
	cryptoStream,
	cryptoSecretStream,
	secretStreamEncryptedChunkBytes,
	secretStreamRawChunkBytes,
	streamNonceBytes,
} from './sodium-native-wrappers';
import * as path from 'path';
import * as fs from 'fs';

//shared boxes are communication boxes that can be used for sending and receiving messages between two parties.
//this uses a shared key calculated using the recipient's public key and the sender's private key to encrypt.
//both parties can at all times encrypt and decrypt all messages that is encrypted with this shared key
//this is to be used in scenarios where information is being shared between two parties and both needs access to this information.
const SharedBoxTest = async () => {
	//create the message we want to encrypt
	const message = `Message in a shared box.Message 123`;

	//generate a key pairs for the receiver and sender. this will be stored somewhere and the public keys would be exchanged
	const recKeyPair = await generateKeyPair();
	const senderKeyPair = await generateKeyPair();

	//encrypt the message using the receiver's public key and the sender's secret key
	const encMessage = await encrypt_SharedBox(message, recKeyPair.publicKey, senderKeyPair.secretKey);

	//decrypt the message using the sender's public key and the receiver's secret key
	const decMessage = await decrypt_SharedBox(encMessage, senderKeyPair.publicKey, recKeyPair.secretKey);

	//log out the results
	console.table({
		'receiver keypair': recKeyPair,
		'sender keypair': senderKeyPair,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

//sealed boxes are communication boxes that can only be opened by the recipient.
//this uses the recipient's public key to encrypt and ony the recipient can decrypt using his/hers secret key.
//this is to be used in scenarios where information is being sent one way and is not required to be decrypted by the sender in the future.
//can be compared to a waxed sealed letter only for the recipient to open.
const sealedBoxTest = async () => {
	//create the message we want to encrypt
	const message = 'Message in a sealed box';

	//generate random keypair for the receiver. this will have to be stored somewhere and the public key exhcanged with the sender somewhow.
	const recKeyPair = await generateKeyPair();

	//encrypt a sealed box using encrypt_SealedBox with the message and secret key provided
	const encMessage = await encrypt_SealedBox(message, recKeyPair.publicKey);

	//decrypt a sealed box using decrypt_SecretBox with the encrypted message and secret key provided
	const decMessage = await decrypt_SealedBox(encMessage, recKeyPair.publicKey, recKeyPair.secretKey);

	//log out the results
	console.table({
		...recKeyPair,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

//in the below case we use a normal sealed box as described above.
//the difference is the key pair is derived from the user's password.
//this shows how to generate a key pair from a user's password. the same generation can be used in the case of shared boxes
const sealedBoxWithCustomPrivKeyTest = async () => {
	//create the message we want to encrypt
	const message = 'Message in a sealed box with a custom secret key';
	//get the user password
	const password = 'P@ssword1';

	//generate random keypair for the receiver. this will have to be stored somewhere and the public key exhcanged with the sender somewhow.
	//when working with a user provided password this needs to be altered to fit the requried carachteristics of a secret key and it s corresponding public key;
	//we use generateKeyPairFromPassword to derive a keypair given the password.
	//generateKeyPairFromPassword will return the hashinputs used to derive the key.
	//if no hashinputs is specified to generateKeyPairFromPassword a random salt and with default inputs will be used.
	//when hashinputs are provided to generateKeyPairFromPassword, this will be used to derive the key.
	//you will have to store the hashinputs somewhere, in order to derive the same key again in future for decryption.
	//keyPair and decryptKeyPair below must be equal.
	const { keyPair, hashInputs } = await generateKeyPairFromPassword(password);
	const { keyPair: decryptKeyPair } = await generateKeyPairFromPassword(password, hashInputs);

	//encrypt a sealed box using encrypt_SealedBox with the message and secret key provided
	const encMessage = await encrypt_SealedBox(message, keyPair.publicKey);
	//decrypt a sealed box using decrypt_SecretBox with the encrypted message and secret key provided
	const decMessage = await decrypt_SealedBox(encMessage, decryptKeyPair.publicKey, decryptKeyPair.secretKey);

	//log out the results
	console.table({
		...keyPair,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

//secret boxes use a secret key to encrypt and decrypt.
//this is not meant for shared communications. but rather for user only data.
//can be compared to a safe where only you have the key.
const secretBoxTest = async () => {
	//create the message we want to encrypt
	const message = 'Message in a secret box';

	//generate secret key for the user. this will have to encrypted and stored somewhere for example a DB.
	//it is usually safer to have the user provide a password and use this to derive a key. see below exmaple.
	//alternatively this key can be encrypted using a key derived from the user's password
	const secretKey = await generateSecretKey();

	//Encrypt the message uwith encrypt_SecretBox sing the user's secret key
	const encMessage = await encrypt_SecretBox(message, secretKey);
	//Encrypt the message with decrypt_SecretBox using the user's secret key
	const decMessage = await decrypt_SecretBox(encMessage, secretKey);

	//log out the results
	console.table({
		'secret key': secretKey,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

//secret boxes use a secret key to encrypt and decrypt.
//this is not meant for shared communications. but rather for user only data.
//in a scenario where more than one would require access to the secret box the secret key used
//can be derived from a shared key between the two parties given their respective public and secret keys
//can be compared to a safe where both you and your partner know the password.
//the below example shows how to derive a shared key between two parties.
const secretBoxSharedKeyTest = async () => {
	//create the message we want to encrypt
	const message = 'Message in a secret box encrypted with a shared key';

	//generate a key pairs for the receiver and sender. this will be stored somewhere and the public keys would be exchanged
	const bobKeyPair = await generateKeyPair();
	const aliceKeyPair = await generateKeyPair();

	//given the keypairs generate a shared key using one party's public key and the other's secret key
	const sharedKey = await generateSharedKey(aliceKeyPair.publicKey, bobKeyPair.secretKey);

	//encrypt the message with encrypt_SecretBox using the calculated shared key
	const encMessage = await encrypt_SecretBox(message, sharedKey);
	//decrypt the message with decrypt_SecretBox using the calculated shared key
	const decMessage = await decrypt_SecretBox(encMessage, sharedKey);

	//log out the results
	console.table({
		'secret key': sharedKey,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

//secret boxes use a secret key to encrypt and decrypt.
//this is not meant for shared communications. but rather for user only data.
//can be compared to a safe where only you have the key
//when deriving a key from a user password it is imperative to allow for some form of lost password recovery.
const secretBoxWithCustomPrivKeyTest = async () => {
	//create the message we want to encrypt
	const message = 'Message in a secret box with a custom secret key';

	//get the user password
	const password = 'P@ssword1';

	//when working with a user provided password this needs to be altered to fit the requried carachteristics of a secret key;
	//we use generateSecretKeyFromPassword to derive a key given the password.
	//generateSecretKeyFromPassword will return the hashinputs used to derive the key.
	//if no hashinputs is specified to generateSecretKeyFromPassword a random salt and with default inputs will be used.
	//when hashinputs are provided to generateSecretKeyFromPassword, this will be used to derive the key .
	//you will have to store the hashinputs somewhere, in order to derive the same key again in future for decryption.
	//secretKey and decryptSecretKey below must be equal.
	const { secretKey, hashInputs } = await generateSecretKeyFromPassword(password);
	const { secretKey: decryptSecretKey } = await generateSecretKeyFromPassword(password, hashInputs);

	//encrypt a secret box using encrypt_SecretBox with the message and secret key provided
	const encMessage = await encrypt_SecretBox(message, secretKey);
	//decrypt a secret box using decrypt_SecretBox with the encrypted message and secret key provided
	const decMessage = await decrypt_SecretBox(encMessage, decryptSecretKey);

	//log out the results
	console.table({
		'secret key': secretKey,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

//example to show the hashing and verification of a password.
//this is the simplest form and concatenates the hash inputs with the hash.
const easyPasswordTest = async () => {
	//get password from user
	const password = 'P@ssword1';
	//generate hash from password
	const hashedPassword = await hashPassword(password);

	//lets test the password
	const invalidPassword = 'P@ssword1.';
	const validPassword = 'P@ssword1';

	//verify password returns true or false depending on the result.
	const invalidVerify = await verifyPassword(invalidPassword, hashedPassword);
	const validVerify = await verifyPassword(validPassword, hashedPassword);

	//log out the results
	console.table({
		password,
		hashedPassword,
		invalidPassword,
		invalidVerify,
		validPassword,
		validVerify,
	});
};

//example to show the hashing and verification of a string value.
//this makes use of the createHash function and expects you to store the various hashinputs in some form or the other.
const PasswordTest = async () => {
	//get password from user
	const password = 'P@ssword1';

	//generate hash. and get the various inputs that was used to generate the hash.
	const hashResult = await createHash(password);
	const hashedPassword = stringifyHashResult(hashResult); //helper function to take the various inputs and concatenate it on to the hash

	//lets test the password
	const invalidPassword = 'P@ssword1.';

	const validPassword = 'P@ssword1';

	//verifyHash returns true or false depending on if the password is valid or not
	const invalidVerify = await verifyHash(invalidPassword, hashedPassword);

	const validVerify = await verifyHash(validPassword, hashedPassword);

	//log out the results
	console.table({
		password,
		hash: hashedPassword,
		invalidPassword: invalidPassword,
		invalidVerify,
		validPassword: validPassword,
		validVerify,
	});
};

//example to show bulk encryption and decryption of an array of messages
const bulkEncryptSharedBox = async () => {
	//build a relative large string to encrypt
	let message: string | null = 'Message in a secret box with a custom secret key1';
	message += message;
	message += message;
	message += message;
	message += message;
	message += message;
	message += message;
	message += message;
	message += message;
	message += message;
	message += message;
	message += message;
	message += message;
	console.log('bytelength:', Buffer.byteLength(message));

	//for testing generate key pairs for the receiver and sender.
	//usually this be stored somwhere and/or the public keys would've been exhcanged somehow.
	const recKeyPair = await generateKeyPair();
	const senderKeyPair = await generateKeyPair();

	//add a bunch of iterations of the large string
	const rounds: Array<string> = [];

	for (let i = 0; i < 1000; i++) {
		rounds.push(message);
	}

	//bulk encrypt by passing the array of messages to encrypt with the receivers's public key and the sender's privatekey
	let encryptedMessages: string[] | null = await bulk_Encrypt_SharedBox(
		rounds,
		recKeyPair.publicKey,
		senderKeyPair.secretKey
	);

	//get the last message that was encrypted
	const encryptedMessage = encryptedMessages.at(-1);

	//bulk decrypt by passing the array of encrypted messages with the sender's public key and the receiver's privatekey
	let decryptedMessages: string[] | null = await bulk_Decrypt_SharedBox(
		encryptedMessages,
		senderKeyPair.publicKey,
		recKeyPair.secretKey
	);

	//get the last message that was decrypted
	const decryptedMessage = decryptedMessages.at(-1);

	//clear the large arrays that is taking up memory
	encryptedMessages = null;
	decryptedMessages = null;

	//log results
	console.log({
		message: message,
		encryptedMessage: encryptedMessage,
		decryptedMessage: decryptedMessage,
	});
};

//example of decrypting an encrypted stream (that does not include autentication).
const decryptFile = async () => {
	//open the streams
	const encFile = fs.createReadStream(path.join(__dirname, 'files', 'encrypted.txt'));
	const decFileWrite = fs.createWriteStream(path.join(__dirname, 'files', 'decrypted.txt'));

	//get your secret key. this will normally be provided by the user/stored somewhere in an encrypted format
	const password = 'Password1.';
	const hashInputs: IHashInput = JSON.parse(
		fs.readFileSync(path.join(__dirname, 'files', 'hashInputs.txt')).toString()
	);
	const { secretKey } = await generateSecretKeyFromPassword(password, hashInputs);

	//get your stored nonce.
	const nonce = fs.readFileSync(path.join(__dirname, 'files', 'nonce.txt')).toString();

	//generate an instance of the crypto stream
	const crypt = new cryptoStream(secretKey, nonce);

	return new Promise<void>((resolve) => {
		//pipe your encrypted stream through the crypto stream to your writable stream
		encFile.pipe(crypt).pipe(decFileWrite);

		decFileWrite.on('close', () => {
			resolve();
		});
	});
};

//example of encrypting an unencrypted stream (that does not include autentication).
const encryptFile = async () => {
	//open the streams
	const origFile = fs.createReadStream(path.join(__dirname, 'files', 'unencrypted.txt'));
	const encFileWrite = fs.createWriteStream(path.join(__dirname, 'files', 'encrypted.txt'));

	//get your secret key. this will normally be provided by the user/stored somewhere in an encrypted format
	const password = 'Password1.';
	const { secretKey, hashInputs } = await generateSecretKeyFromPassword(password);
	//store hashinputs used for key somewhere
	fs.writeFileSync(path.join(__dirname, 'files', 'hashInputs.txt'), JSON.stringify(hashInputs));

	//generate a none. the nonce needs to be stored for the decryption. normally this will padded on to the filename, or on a DB.
	const nonce = await generateRandomValue(streamNonceBytes);
	fs.writeFileSync(path.join(__dirname, 'files', 'nonce.txt'), nonce);

	//generate an instance of the crypto stream
	const crypto = new cryptoStream(secretKey, nonce);

	return new Promise<void>((resolve) => {
		//pipe your unencrypted stream through the crypto stream to your writable stream
		origFile.pipe(crypto).pipe(encFileWrite);

		encFileWrite.on('close', () => {
			resolve();
		});
	});
};

//example of decrypting an encrypted stream with autentication.
const secretDecryptFile = async () => {
	//open the streams
	const encFile = fs.createReadStream(path.join(__dirname, 'files', 'encrypted.txt'), {
		//when working with secret streams it is important to set the highwatermark as the bytes get padded with authentication data
		//hence the number of bytes that needs to be read for encryption and decryption is different
		highWaterMark: secretStreamEncryptedChunkBytes,
	});
	const decFileWrite = fs.createWriteStream(path.join(__dirname, 'files', 'decrypted.txt'));

	//get your secret key. this will normally be provided by the user/stored somewhere in an encrypted format
	const password = 'Password1.';
	const hashInputs: IHashInput = JSON.parse(
		fs.readFileSync(path.join(__dirname, 'files', 'hashInputs.txt')).toString()
	);
	const { secretKey } = await generateSecretKeyFromPassword(password, hashInputs);

	//get your stored header.  normally this will padded on to the filename, or on a DB.
	const header = fs.readFileSync(path.join(__dirname, 'files', 'header.txt')).toString();

	//generate an instance of the crypto secret stream. when decrypting you must provide the header that was used during encryption
	const crypt = new cryptoSecretStream('decrypt', secretKey, header);

	return new Promise<void>((resolve) => {
		//pipe your encrypted stream through the crypto stream to your writable stream
		encFile.pipe(crypt).pipe(decFileWrite);
		decFileWrite.on('close', () => {
			resolve();
		});
	});
};

//example of encrypting an encrypted stream with autentication.
const secretEncryptFile = async () => {
	//open the streams
	const origFile = fs.createReadStream(path.join(__dirname, 'files', 'unencrypted.txt'), {
		//when working with secret streams it is important to set the highwatermark as the bytes get padded with authentication data
		//hence the number of bytes that needs to be read for encryption and decryption is different
		highWaterMark: secretStreamRawChunkBytes,
	});
	const encFileWrite = fs.createWriteStream(path.join(__dirname, 'files', 'encrypted.txt'));

	//get your secret key. this will normally be provided by the user/stored somewhere in an encrypted format
	const password = 'Password1.';
	const hashInputs: IHashInput = JSON.parse(
		fs.readFileSync(path.join(__dirname, 'files', 'hashInputs.txt')).toString()
	);
	const { secretKey } = await generateSecretKeyFromPassword(password, hashInputs);

	//generate an instance of the crypto secret stream. when encrypting you must extract and store the header that will be used during encryption
	const crypt = new cryptoSecretStream('encrypt', secretKey);
	const header = crypt.header;
	fs.writeFileSync(path.join(__dirname, 'files', 'header.txt'), header); // store your header. normally this will padded on to the filename, or on a DB.

	return new Promise<void>((resolve) => {
		//pipe your uncrypted stream through the crypto stream to your writable stream
		origFile.pipe(crypt).pipe(encFileWrite);

		encFileWrite.on('close', () => {
			resolve();
		});
	});
};

// uncomment the example you whish to run
// SharedBoxTest();
// sealedBoxTest();
// sealedBoxWithCustomPrivKeyTest();
// secretBoxTest();
// secretBoxSharedKetTest();
// secretBoxWithCustomPrivKeyTest();
// easyPasswordTest();
// PasswordTest();
// (async () => await bulkEncryptSharedBox())().then(async () => {
// 	await new Promise((resolve) => {
// 		console.log('starting timer');
// 		setTimeout(() => resolve(true), 60 * 1000);
// 	});
// });

// test encryption and decription of stream with no authenction added
// (async () => {
// 	await encryptFile();

// 	await decryptFile();
// })();

// test encryption and decription of stream with authenction added
// (async () => {
// 	await secretEncryptFile();

// 	await secretDecryptFile();
// })();
