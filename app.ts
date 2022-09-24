import {
	generateKeyPair,
	encrypt_SealedBox,
	decrypt_SealedBox,
	generateSecretKey,
	encrypt_SecretBox,
	decrypt_SecretBox,
	generateSharedKey,
	encrypt_SharedBox,
	decrypt_SharedBox,
	generateKeyPairFromPassword,
	generateSecretKeyFromPassword,
	hashPassword,
	verifyPassword,
	createHash,
	stringifyHashResult,
	verifyHash,
	bulk_Encrypt_SharedBox,
	bulk_Decrypt_SharedBox,
} from './crypto.server';

import type { IKeyPair } from './crypto.server';

const sealedBoxTest = async () => {
	const message = 'Message in a sealed box';
	const recKeyPair = await generateKeyPair();
	const encMessage = await encrypt_SealedBox(message, recKeyPair.publicKey);
	const decMessage = await decrypt_SealedBox(encMessage, recKeyPair.publicKey, recKeyPair.secretKey);

	console.table({
		...recKeyPair,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

const secretBoxTest = async () => {
	const message = 'Message in a secret box';
	const secretKey = await generateSecretKey();
	const encMessage = await encrypt_SecretBox(message, secretKey);
	const decMessage = await decrypt_SecretBox(encMessage, secretKey);

	console.table({
		'secret key': secretKey,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

const secretBoxSharedKetTest = async () => {
	const message = 'Message in a secret box encrypted with a shared key';
	const recKeyPair = await generateKeyPair();
	const senderKeyPair = await generateKeyPair();
	const sharedKey = await generateSharedKey(recKeyPair.publicKey, senderKeyPair.secretKey);
	const encMessage = await encrypt_SecretBox(message, sharedKey);
	const decMessage = await decrypt_SecretBox(encMessage, sharedKey);

	console.table({
		'secret key': sharedKey,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

const SharedBoxTest = async () => {
	const message = `Message in a shared box.Message 123`;
	const recKeyPair = await generateKeyPair();
	const senderKeyPair = await generateKeyPair();
	const encMessage = await encrypt_SharedBox(message, recKeyPair.publicKey, senderKeyPair.secretKey);
	const decMessage = await decrypt_SharedBox(encMessage, senderKeyPair.publicKey, recKeyPair.secretKey);

	console.table({
		'receiver keypair': recKeyPair,
		'sender keypair': senderKeyPair,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

const sealedBoxWithCustomPrivKeyTest = async () => {
	const message = 'Message in a sealed box with a custom secret key';
	const password = 'P@ssword1';
	const { keyPair } = await generateKeyPairFromPassword(password);

	const recKeyPair: IKeyPair = {
		secretKey: keyPair.secretKey,
		publicKey: keyPair.publicKey,
	};

	const encMessage = await encrypt_SealedBox(message, recKeyPair.publicKey);
	const decMessage = await decrypt_SealedBox(encMessage, recKeyPair.publicKey, recKeyPair.secretKey);

	console.table({
		...recKeyPair,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

const secretBoxWithCustomPrivKeyTest = async () => {
	const message = 'Message in a secret box with a custom secret key';
	const password = 'P@ssword1';
	const { secretKey } = await generateSecretKeyFromPassword(password);
	const encMessage = await encrypt_SecretBox(message, secretKey);
	const decMessage = await decrypt_SecretBox(encMessage, secretKey);

	console.table({
		'secret key': secretKey,
		'Original Message': message,
		'Encrypted Message': encMessage,
		'Decrypted Message': decMessage,
	});
};

const easyPasswordTest = async () => {
	const password = 'P@ssword1';
	const hashedPassword = await hashPassword(password);

	const invalidPassword = 'P@ssword1.';
	const validPassword = 'P@ssword1';
	const invalidVerify = await verifyPassword(invalidPassword, hashedPassword);
	const validVerify = await verifyPassword(validPassword, hashedPassword);

	console.table({
		password,
		hashedPassword,
		invalidPassword,
		invalidVerify,
		validPassword,
		validVerify,
	});
};

const PasswordTest = async () => {
	const password = 'P@ssword1';
	const hashResult = await createHash(password);
	const hashedPassword = stringifyHashResult(hashResult);

	const invalidPassword = 'P@ssword1.';

	const validPassword = 'P@ssword1';

	const invalidVerify = await verifyHash(invalidPassword, hashedPassword);

	const validVerify = await verifyHash(validPassword, hashedPassword);

	console.table({
		password,
		hash: hashedPassword,
		invalidPassword: invalidPassword,
		invalidVerify,
		validPassword: validPassword,
		validVerify,
	});
};

const bulkEncryptSharedBox = async () => {
	console.log(Date.now());

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

	const recKeyPair = await generateKeyPair();
	const senderKeyPair = await generateKeyPair();

	const rounds: Array<string> = [];

	for (let i = 0; i < 1000; i++) {
		rounds.push(message);
	}

	let encryptedMessages: string[] | null = await bulk_Encrypt_SharedBox(
		rounds,
		recKeyPair.publicKey,

		senderKeyPair.secretKey
	);
	console.log(encryptedMessages.length);
	const encryptedMessage = encryptedMessages.at(-1);

	let decryptedMessages: string[] | null = await bulk_Decrypt_SharedBox(
		encryptedMessages,
		senderKeyPair.publicKey,
		recKeyPair.secretKey
	);
	const decryptedMessage = decryptedMessages.at(-1);

	encryptedMessages = null;
	decryptedMessages = null;
	console.log({
		message: message,
		encryptedMessage: encryptedMessage,
		decryptedMessage: decryptedMessage,
	});
	console.log(Date.now());
};

// sealedBoxTest();
// secretBoxTest();
// secretBoxSharedKetTest();
// SharedBoxTest();
// sealedBoxWithCustomPrivKeyTest();
// secretBoxWithCustomPrivKeyTest();
// easyPasswordTest();
// PasswordTest();
// (async () => await bulkEncryptSharedBox())().then(async () => {
// 	await new Promise((resolve) => {
// 		console.log('starting timer');
// 		setTimeout(() => resolve(true), 60 * 1000);
// 	});
// });
