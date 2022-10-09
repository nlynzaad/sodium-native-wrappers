// noinspection JSUnusedGlobalSymbols,TypeScriptCheckImport

import {
	crypto_box_easy,
	crypto_box_keypair,
	crypto_box_MACBYTES,
	crypto_box_NONCEBYTES,
	crypto_box_open_easy,
	crypto_box_PUBLICKEYBYTES,
	crypto_box_seal,
	crypto_box_seal_open,
	crypto_box_SEALBYTES,
	crypto_box_SECRETKEYBYTES,
	crypto_kdf_keygen,
	crypto_pwhash,
	crypto_pwhash_ALG_DEFAULT,
	crypto_pwhash_MEMLIMIT_MODERATE,
	crypto_pwhash_OPSLIMIT_MODERATE,
	crypto_pwhash_SALTBYTES,
	crypto_pwhash_str,
	crypto_pwhash_str_verify,
	crypto_pwhash_STRBYTES,
	crypto_scalarmult,
	crypto_scalarmult_base,
	crypto_secretbox_easy,
	crypto_secretbox_open_easy,
	crypto_secretstream_xchacha20poly1305_ABYTES,
	crypto_secretstream_xchacha20poly1305_HEADERBYTES,
	crypto_secretstream_xchacha20poly1305_KEYBYTES,
	// @ts-ignore typescript definitions are outdated
	crypto_secretstream_xchacha20poly1305_STATEBYTES,
	crypto_secretstream_xchacha20poly1305_TAGBYTES,
	randombytes_buf,
	sodium_malloc,
	sodium_memzero,
	crypto_stream_xor_STATEBYTES,
	crypto_stream_KEYBYTES,
	crypto_stream_NONCEBYTES,
	// @ts-ignore typescript definitions are outdated
	crypto_stream_xor_update,
	// @ts-ignore typescript definitions are outdated
	crypto_stream_xor_init,
	// @ts-ignore typescript definitions are outdated
	crypto_stream_xor_final,
	crypto_secretstream_xchacha20poly1305_init_push,
	crypto_secretstream_xchacha20poly1305_init_pull,
	crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
	crypto_secretstream_xchacha20poly1305_push,
	crypto_secretstream_xchacha20poly1305_pull,
} from 'sodium-native';
import { Transform, Readable, TransformCallback } from 'node:stream';

//declare interfaces and types

//cipher interface containing the cipher, the nonce used for the cipher and the encoding.
interface ICipher {
	encoding: BufferEncoding;
	nonce: Buffer | string | undefined;
	cipher: Buffer | string;
}

//keypair interface contains the public and private keys in a keypair.
interface IKeyPair {
	publicKey: string;
	secretKey: string;
}

//result of hash function containing the hash and the inputs used to derive the hash
interface IHashResult {
	hash: string;
	hashInputs: IHashInput;
}

//inputs required for hashing of values.
interface IHashInput {
	salt: string;
	opsLimit: number;
	memLimit: number;
	alg: number;
}

//actions allowed for secret stream encryption.
type ISecretStreamAction = 'encrypt' | 'decrypt';

//default hashinput values
const hashDefaults: Pick<IHashInput, 'opsLimit' | 'memLimit' | 'alg'> = {
	opsLimit: crypto_pwhash_OPSLIMIT_MODERATE,
	memLimit: crypto_pwhash_MEMLIMIT_MODERATE,
	alg: crypto_pwhash_ALG_DEFAULT,
};

//default encoding types
const keyEncoding: BufferEncoding = 'base64';
const cipherEncoding: BufferEncoding = 'base64';
const valueEncoding: BufferEncoding = 'utf8';

const textEncoding: { [key: string]: BufferEncoding } = {
	utf8: 'utf8',
	base64: 'base64',
	hex: 'hex',
};

//default constants used throughout
const secretKeyBytes = crypto_box_SECRETKEYBYTES;
const publicKeyBytes = crypto_box_PUBLICKEYBYTES;
const nonceBytes = crypto_box_NONCEBYTES;
const macBytes = crypto_box_MACBYTES;
const saltBytes = crypto_pwhash_SALTBYTES;
const pwHashBytes = 32;
const easyPwHashBytes = crypto_pwhash_STRBYTES;
const sealBytes = crypto_box_SEALBYTES;
const secretStreamABytes = crypto_secretstream_xchacha20poly1305_ABYTES;
const secretStreamTagBytes = crypto_secretstream_xchacha20poly1305_TAGBYTES;
const secretStreamMessageTag = crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
const secretStreamRawChunkBytes = new Readable().readableHighWaterMark - secretStreamABytes;
const secretStreamEncryptedChunkBytes = secretStreamRawChunkBytes + secretStreamABytes;
const secretStreamHeaderBytes = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
const secretStreamKeyBytes = crypto_secretstream_xchacha20poly1305_KEYBYTES;
const secretStreamStateBytes = crypto_secretstream_xchacha20poly1305_STATEBYTES;
const streamChunkBytes = new Readable().readableHighWaterMark;
const streamStateBytes = crypto_stream_xor_STATEBYTES;
const streamKeyBytes = crypto_stream_KEYBYTES;
const streamNonceBytes = crypto_stream_NONCEBYTES;

//helper function to concatenate the hash results into a single string
const stringifyHashResult = (hashResult: IHashResult): string => {
	const hash = hashResult.hash;
	return hash.concat('.', stringifyHashInputs(hashResult.hashInputs));
};

//helper function to concatenate the hash inputs into a single string
const stringifyHashInputs = (hashInput: IHashInput): string => {
	return Object.entries(hashInput)
		.sort((a, b) => a[0].localeCompare(b[0]))
		.map((entry) => entry[1])
		.join('.');
};

//helper function to extract the hash results from a hashed string
const getHashResultFromStr = (hashResultString: string): IHashResult => {
	const [hash, algStr, memLimitStr, opsLimitStr, salt] = hashResultString.split('.');

	const opsLimit = parseInt(opsLimitStr);
	const memLimit = parseInt(memLimitStr);
	const alg = parseInt(algStr);

	if (isNaN(opsLimit) || isNaN(memLimit) || isNaN(alg)) {
		throw new Error('Could not extract the hash input variables from the string');
	}

	return {
		hashInputs: {
			salt,
			opsLimit,
			memLimit,
			alg,
		},
		hash,
	};
};

//helper function to extract the hash inputs from a string
const getHashInputsFromStr = (hashInputStr: string): IHashInput => {
	const [algStr, memLimitStr, opsLimitStr, salt] = hashInputStr.split('.');

	const opsLimit = parseInt(opsLimitStr);
	const memLimit = parseInt(memLimitStr);
	const alg = parseInt(algStr);

	if (isNaN(opsLimit) || isNaN(memLimit) || isNaN(alg)) {
		throw new Error('Could not extract the hash input variables from the string');
	}

	return {
		salt,
		opsLimit,
		memLimit,
		alg,
	};
};

//helper function to concatenate the cipher values into a single string
const stringifyCipher = ({ encoding, nonce, cipher }: ICipher): string => {
	const nonceStr = nonce && typeof nonce !== 'string' ? nonce.toString(cipherEncoding) : undefined;
	const cipherStr = typeof cipher !== 'string' ? cipher.toString(cipherEncoding) : cipher;

	if (nonce) {
		return Object.entries({ cipherStr, encoding: encoding.toString(), nonceStr })
			.sort((a, b) => a[0].localeCompare(b[0]))
			.map((entry) => entry[1])
			.join('.');
	}

	return Object.entries({ cipherStr, encoding: encoding.toString() })
		.sort((a, b) => a[0].localeCompare(b[0]))
		.map((entry) => entry[1])
		.join('.');
};

//helper function to extract the cipher values from a string
const getCipherFromStr = (cipherStr: string): ICipher => {
	const splitStr = cipherStr.split('.');

	let nonce: string | undefined = undefined;

	if (splitStr.length < 2 || splitStr.length > 3) {
		throw new Error('Invalid cipher string');
	}
	const cipher = splitStr[0];
	const encoding = textEncoding[splitStr[1]];

	if (splitStr.length === 3) {
		nonce = splitStr[2];
	}

	return {
		encoding,
		nonce,
		cipher,
	};
};

//helper function to create buffers from an array of input values.
//these buffers can the be prepopulated using predefined string values/buffers or functions that accept the buffer as input
const createBuffers = (
	inputArray: { length: number; data?: string | Buffer | ((buffer: Buffer) => void); encoding?: BufferEncoding }[]
): Buffer[] => {
	return inputArray.map((input) => {
		//check that the input data and specified lengths match
		if (
			input.data &&
			((typeof input.data === 'string' && Buffer.byteLength(input.data, input.encoding) !== input.length) ||
				(typeof input.data !== 'function' && typeof input.data !== 'string' && input.data.length !== input.length))
		)
			throw new Error(`Input value is not of length ${input.length}`);

		//create new buffer allocation
		const buffer = sodium_malloc(input.length);

		//if data was provided populate buffer based on the type of data provided
		if (input.data) {
			switch (typeof input.data) {
				case 'string':
					buffer.write(input.data, input.encoding);
					break;
				case 'function':
					input.data(buffer);
					break;
				default:
					input.data.copy(buffer);
			}
		}

		//return buffer
		return buffer;
	});
};

//fill existing array of buffers with data.
//these buffers can the be populated using string values/buffers or functions that accept the buffer as input
const fillBuffers = (
	inputArray: { buffer: Buffer; data: string | Buffer | ((buffer: Buffer) => void); encoding?: BufferEncoding }[]
) => {
	inputArray.forEach((input) => {
		if (input.data) {
			switch (typeof input.data) {
				case 'string':
					input.buffer.write(input.data, input.encoding);
					break;
				case 'function':
					input.data(input.buffer);
					break;
				default:
					input.data.copy(input.buffer);
			}
		}
	});
};

//write zeros to an array of burrers
const zeroBuffers = (buffers: Buffer[]) => {
	return buffers.map((buffer) => sodium_memzero(buffer));
};

//helper function generate random value given the size required.
//usefull for nonce values
const generateRandomValue = (size: number): string => {
	const [valueBuffer] = createBuffers([{ length: size, data: randombytes_buf }]);
	const value = valueBuffer.toString(keyEncoding);
	zeroBuffers([valueBuffer]);
	return value;
};

//helper function to generate a keyPair
const generateKeyPair = async (): Promise<IKeyPair> => {
	const [secretKeyBuff, publicKeyBuff] = createBuffers([{ length: secretKeyBytes }, { length: publicKeyBytes }]);

	crypto_box_keypair(publicKeyBuff, secretKeyBuff);

	const keyPair: IKeyPair = {
		publicKey: publicKeyBuff.toString(keyEncoding),
		secretKey: secretKeyBuff.toString(keyEncoding),
	};

	zeroBuffers([secretKeyBuff, publicKeyBuff]);

	return keyPair;
};

//helper function to generate a keypair derived from  a user provided password
const generateKeyPairFromPassword = async (
	password: string,
	hashInput: IHashInput | undefined = undefined
): Promise<{ hashInputs: IHashInput; keyPair: IKeyPair }> => {
	const { hash: secretKey, hashInputs } = await createHash(password, hashInput, secretKeyBytes);
	const publicKey = await generatePublicKey(secretKey);

	return {
		hashInputs,
		keyPair: { publicKey, secretKey },
	};
};

//helper function to generate a public key derived from a user provided secret
const generatePublicKey = async (secretKey: string): Promise<string> => {
	const [secretKeyBuff, publicKeyBuff] = createBuffers([
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
		{ length: publicKeyBytes },
	]);

	crypto_scalarmult_base(publicKeyBuff, secretKeyBuff);

	const publicKey = publicKeyBuff.toString(keyEncoding);

	zeroBuffers([secretKeyBuff, publicKeyBuff]);

	return publicKey;
};

//helper function to generate a shared key derived from a sender's secret key and a receiver's public key
const generateSharedKey = async (publicKey: string, secretKey: string): Promise<string> => {
	const [secretKeyBuff, publicKeyBuff, sharedKeyBuff] = createBuffers([
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
		{ length: publicKeyBytes, data: publicKey, encoding: keyEncoding },
		{ length: secretKeyBytes },
	]);

	crypto_scalarmult(sharedKeyBuff, secretKeyBuff, publicKeyBuff);

	const sharedKey = sharedKeyBuff.toString(keyEncoding);

	zeroBuffers([secretKeyBuff, publicKeyBuff, sharedKeyBuff]);

	return sharedKey;
};

//helper function to generate a secret key derived from a user provided password
const generateSecretKeyFromPassword = async (
	password: string,
	hashInput: IHashInput | undefined = undefined
): Promise<{ secretKey: string; hashInputs: IHashInput }> => {
	const { hash: secretKey, hashInputs } = await createHash(password, hashInput, secretKeyBytes);

	return { secretKey, hashInputs };
};

//helper function to generate a random secret key
const generateSecretKey = async (): Promise<string> => {
	const [secretKeyBuffer] = createBuffers([{ length: secretKeyBytes, data: crypto_kdf_keygen }]);

	return secretKeyBuffer.toString(keyEncoding);
};

//helper function to generate a random salt
const generateSalt = (): string => {
	const [saltBuff] = createBuffers([{ length: saltBytes, data: randombytes_buf }]);

	const salt = saltBuff.toString(keyEncoding);
	zeroBuffers([saltBuff]);

	return salt;
};

//function to create a secret box encrypting a value using a user's secret key
const encrypt_SecretBox = async (value: string, secretKey: string): Promise<string> => {
	const valueLength = Buffer.byteLength(value, valueEncoding);
	const cipherLength = valueLength + macBytes;

	const [nonceBuff, cipherBuff, valueBuff, secretKeyBuff] = createBuffers([
		{ length: nonceBytes, data: randombytes_buf },
		{ length: cipherLength },
		{ length: valueLength, data: value, encoding: valueEncoding },
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
	]);

	crypto_secretbox_easy(cipherBuff, valueBuff, nonceBuff, secretKeyBuff);

	const cipherText = stringifyCipher({ encoding: valueEncoding, nonce: nonceBuff, cipher: cipherBuff });

	zeroBuffers([cipherBuff, valueBuff, nonceBuff, secretKeyBuff]);

	return cipherText;
};

//function to open a secret box using a user's secret key
const decrypt_SecretBox = async (cipherText: string, secretKey: string): Promise<string> => {
	const { nonce, cipher } = getCipherFromStr(cipherText);

	if (!cipher || typeof cipher !== 'string' || typeof nonce !== 'string') throw new Error('Cipher is invalid');

	const cipherLength = Buffer.byteLength(cipher, cipherEncoding);
	const valueLength = cipherLength - macBytes;

	const [nonceBuff, cipherBuff, valueBuff, secretKeyBuff] = createBuffers([
		{ length: nonceBytes, data: nonce, encoding: cipherEncoding },
		{ length: cipherLength, data: cipher, encoding: cipherEncoding },
		{ length: valueLength },
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
	]);

	crypto_secretbox_open_easy(valueBuff, cipherBuff, nonceBuff, secretKeyBuff);

	const value = valueBuff.toString(valueEncoding);

	zeroBuffers([cipherBuff, valueBuff, nonceBuff, secretKeyBuff]);

	return value;
};

//function to create a sealed box encrypting a value using a recipient's public key
const encrypt_SealedBox = async (value: string, publicKey: string): Promise<string> => {
	const valueLength = Buffer.byteLength(value, valueEncoding);
	const cipherLength = valueLength + sealBytes;

	const [cipherBuff, valueBuff, publicKeyBuff] = createBuffers([
		{ length: cipherLength },
		{ length: valueLength, data: value, encoding: valueEncoding },
		{ length: publicKeyBytes, data: publicKey, encoding: keyEncoding },
	]);

	crypto_box_seal(cipherBuff, valueBuff, publicKeyBuff);

	const cipherText = stringifyCipher({ encoding: valueEncoding, cipher: cipherBuff, nonce: undefined });

	zeroBuffers([cipherBuff, valueBuff, publicKeyBuff]);

	return cipherText;
};

//function to open a sealed box using the recipient's public and private key
const decrypt_SealedBox = async (cipherText: string, publicKey: string, secretKey: string): Promise<string> => {
	const { encoding, cipher } = getCipherFromStr(cipherText);

	if (!cipher || typeof cipher !== 'string') throw new Error('Invalid cipher');

	const cipherLength = Buffer.byteLength(cipher, cipherEncoding);
	const valueLength = cipherLength - sealBytes;

	const [cipherBuff, valueBuff, publicKeyBuff, secretKeyBuff] = createBuffers([
		{ length: cipherLength, data: cipher, encoding: cipherEncoding },
		{ length: valueLength },
		{ length: publicKeyBytes, data: publicKey, encoding: keyEncoding },
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
	]);

	crypto_box_seal_open(valueBuff, cipherBuff, publicKeyBuff, secretKeyBuff);

	const value = valueBuff.toString(encoding);

	zeroBuffers([cipherBuff, valueBuff, publicKeyBuff, secretKeyBuff]);

	return value;
};

//function to create a shared box using the recipient's public and the sender's private key
const encrypt_SharedBox = async (value: string, publicKey: string, secretKey: string): Promise<string> => {
	const valueLength = Buffer.byteLength(value, valueEncoding);
	const cipherLength = valueLength + macBytes;

	const [nonceBuffer, cipherBuffer, valueBuffer, publicKeyBuffer, secretKeyBuffer] = createBuffers([
		{ length: nonceBytes, data: randombytes_buf },
		{ length: cipherLength },
		{ length: valueLength, data: value, encoding: valueEncoding },
		{ length: publicKeyBytes, data: publicKey, encoding: keyEncoding },
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
	]);

	crypto_box_easy(cipherBuffer, valueBuffer, nonceBuffer, publicKeyBuffer, secretKeyBuffer);

	const cipherText = stringifyCipher({ encoding: valueEncoding, nonce: nonceBuffer, cipher: cipherBuffer });

	zeroBuffers([nonceBuffer, cipherBuffer, valueBuffer, publicKeyBuffer, secretKeyBuffer]);

	return cipherText;
};

//function to open a shared box using the recipient's private and the sender's public key
const decrypt_SharedBox = async (cipherText: string, publicKey: string, secretKey: string): Promise<string> => {
	const { encoding, nonce, cipher } = getCipherFromStr(cipherText);

	if (!cipher || typeof cipher !== 'string' || typeof nonce !== 'string') throw new Error('Invalid cipher');

	const cipherLength = Buffer.byteLength(cipher, cipherEncoding);
	const valueLength = cipherLength - macBytes;

	const [nonceBuffer, cipherBuffer, valueBuffer, publicKeyBuffer, secretKeyBuffer] = createBuffers([
		{ length: nonceBytes, data: nonce, encoding: cipherEncoding },
		{ length: cipherLength, data: cipher, encoding: cipherEncoding },
		{ length: valueLength },
		{ length: publicKeyBytes, data: publicKey, encoding: keyEncoding },
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
	]);

	crypto_box_open_easy(valueBuffer, cipherBuffer, nonceBuffer, publicKeyBuffer, secretKeyBuffer);

	const value = valueBuffer.toString(encoding);

	zeroBuffers([nonceBuffer, cipherBuffer, valueBuffer, publicKeyBuffer, secretKeyBuffer]);

	return value;
};

//helper function to assist bulk creation of shared boxes given an array of messages using the recipient's public and the sender's private key
const bulk_Encrypt_SharedBox = async (
	messages: string[],
	publicKey: string,
	secretKey: string
): Promise<Array<string>> => {
	const chunk = 50;
	const encrypted: Array<string> = [];

	const maxValueLength = Math.max.apply(
		Math,
		messages.map((message) => message.length)
	);

	const maxCipherLength = maxValueLength + macBytes;

	const [nonceBuffer, valueBuffer, publicKeyBuffer, secretKeyBuffer] = createBuffers([
		{ length: nonceBytes },
		{ length: maxValueLength },
		{ length: publicKeyBytes },
		{ length: secretKeyBytes },
	]);

	const cipherBuffer: Array<Buffer> = Array(chunk).fill(sodium_malloc(maxCipherLength));

	for (let i = 0; i < Math.ceil(messages.length / chunk); i++) {
		const start = i * chunk;
		const end = start + chunk > messages.length ? messages.length : start + chunk;

		encrypted.push(
			...(await Promise.all(
				messages.slice(start, end).map(async (message, index) => {
					const valueLength = Buffer.byteLength(message, valueEncoding);
					const cipherLength = valueLength + macBytes;

					fillBuffers([
						{ buffer: nonceBuffer, data: randombytes_buf },
						{ buffer: valueBuffer, data: message, encoding: valueEncoding },
						{ buffer: publicKeyBuffer, data: publicKey, encoding: keyEncoding },
						{ buffer: secretKeyBuffer, data: secretKey, encoding: keyEncoding },
					]);

					crypto_box_easy(
						cipherBuffer[index].subarray(0, cipherLength),
						valueBuffer.subarray(0, valueLength),
						nonceBuffer,
						publicKeyBuffer,
						secretKeyBuffer
					);

					const cipherText = stringifyCipher({
						encoding: valueEncoding,
						nonce: nonceBuffer,
						cipher: cipherBuffer[index],
					});

					zeroBuffers([cipherBuffer[index], valueBuffer, nonceBuffer, publicKeyBuffer, secretKeyBuffer]);

					return cipherText;
				})
			))
		);
	}

	return encrypted;
};

//helper function to assist bulk openiong of shared boxes given an array of shared boxes using the recipient's private and the sender's public key
const bulk_Decrypt_SharedBox = async (
	encMessages: Array<string>,
	publicKey: string,
	secretKey: string
): Promise<Array<string>> => {
	const chunk = 50;
	const encrypted: Array<string> = [];

	const maxCipherLength = Math.max.apply(
		Math,
		encMessages.map((message) => message.length)
	);

	const maxValueLength = maxCipherLength - macBytes - nonceBytes - 3;

	const [nonceBuffer, cipherBuffer, publicKeyBuffer, secretKeyBuffer] = createBuffers([
		{ length: nonceBytes },
		{ length: maxCipherLength },
		{ length: publicKeyBytes },
		{ length: secretKeyBytes },
	]);

	const valueBuffer: Array<Buffer> = Array(chunk).fill(sodium_malloc(maxValueLength));

	for (let i = 0; i < Math.ceil(encMessages.length / chunk); i++) {
		const start = i * chunk;
		const end = start + chunk > encMessages.length ? encMessages.length : start + chunk;

		encrypted.push(
			...(await Promise.all(
				encMessages.slice(start, end).map(async (encMessage, index) => {
					const { encoding, nonce, cipher } = getCipherFromStr(encMessage);

					if (!cipher || typeof cipher !== 'string' || typeof nonce !== 'string') throw new Error('Invalid cipher');

					const cipherLength = Buffer.byteLength(cipher, cipherEncoding);
					const valueLength = cipherLength - macBytes;

					fillBuffers([
						{ buffer: nonceBuffer, data: nonce, encoding: cipherEncoding },
						{ buffer: cipherBuffer, data: cipher, encoding: cipherEncoding },
						{ buffer: publicKeyBuffer, data: publicKey, encoding: keyEncoding },
						{ buffer: secretKeyBuffer, data: secretKey, encoding: keyEncoding },
					]);

					crypto_box_open_easy(
						valueBuffer[index].subarray(0, valueLength),
						cipherBuffer.subarray(0, cipherLength),
						nonceBuffer,
						publicKeyBuffer,
						secretKeyBuffer
					);

					const value = valueBuffer[index].subarray(0, valueLength).toString(encoding);

					zeroBuffers([nonceBuffer, cipherBuffer, publicKeyBuffer, secretKeyBuffer]);

					return value;
				})
			))
		);
	}

	return encrypted;
};

//function to create a hash of a value, with optional specification of hash inputs and hash length.
//this is the recommended way to derive a key from a given input.
const createHash = async (
	password: string,
	hashInput?: IHashInput,
	hashLength: number = pwHashBytes
): Promise<IHashResult> => {
	const { salt, opsLimit, memLimit, alg } = {
		salt: hashInput?.salt ?? generateSalt(),
		opsLimit: hashInput?.opsLimit ?? hashDefaults.opsLimit,
		memLimit: hashInput?.memLimit ?? hashDefaults.memLimit,
		alg: hashInput?.alg ?? hashDefaults.alg,
	};

	const [saltBuffer, valueBuffer, hashBuffer] = createBuffers([
		{ length: saltBytes, data: salt, encoding: keyEncoding },
		{ length: Buffer.byteLength(password), data: password, encoding: valueEncoding },
		{ length: hashLength },
	]);

	crypto_pwhash(hashBuffer, valueBuffer, saltBuffer, opsLimit, memLimit, alg);

	const hash = hashBuffer.toString(cipherEncoding);

	zeroBuffers([hashBuffer, valueBuffer, saltBuffer]);

	return {
		hash,
		hashInputs: {
			opsLimit,
			memLimit,
			salt,
			alg,
		},
	};
};

//verify the hash created by the create hash function and concatenated using the stringifyHashResult helper function
const verifyHash = async (value: string, hashedValue: string): Promise<boolean> => {
	const hashResult = getHashResultFromStr(hashedValue);

	return (
		(await createHash(value, hashResult.hashInputs, Buffer.byteLength(hashResult.hash, cipherEncoding))).hash ===
		hashResult.hash
	);
};

//function to create hash from as value.
//hash inputs is derived and stored with the hash and not available for custom handling/storing.
//ideal usage is for passwords that needs to be hashed and compared easily
const hashPassword = async (password: string): Promise<string> => {
	const [passwordBuffer, hashBuffer] = createBuffers([
		{ length: Buffer.byteLength(password), data: password, encoding: valueEncoding },
		{ length: easyPwHashBytes },
	]);

	crypto_pwhash_str(hashBuffer, passwordBuffer, hashDefaults.opsLimit, hashDefaults.memLimit);

	const hash = hashBuffer.toString(cipherEncoding);

	zeroBuffers([hashBuffer, passwordBuffer]);

	return hash;
};

//function to verify password against hash from hashPassword function.
const verifyPassword = async (password: string, hashedPassword: string): Promise<boolean> => {
	const [passwordBuffer, hashBuffer] = createBuffers([
		{ length: Buffer.byteLength(password), data: password, encoding: valueEncoding },
		{ length: easyPwHashBytes, data: hashedPassword, encoding: cipherEncoding },
	]);

	const result = crypto_pwhash_str_verify(hashBuffer, passwordBuffer);

	zeroBuffers([hashBuffer, passwordBuffer]);

	return result;
};

//class used to encrypt/decrypt streams without adding additional authentication information.
//this is a transform stream and hence to be used inside a stream pipeline.
class cryptoStream extends Transform {
	private _secretKeyBuffer: Buffer;
	private _nonceBuffer: Buffer;
	private _stateBuffer: Buffer;

	constructor(secretKey: string, nonce: string) {
		super();

		this._stateBuffer = sodium_malloc(streamStateBytes);
		this._nonceBuffer = sodium_malloc(streamNonceBytes);
		this._secretKeyBuffer = sodium_malloc(streamKeyBytes);

		this._nonceBuffer.fill(nonce, 0, streamNonceBytes, keyEncoding);
		this._secretKeyBuffer.fill(secretKey, 0, streamKeyBytes, keyEncoding);

		crypto_stream_xor_init(this._stateBuffer, this._nonceBuffer, this._secretKeyBuffer);
	}

	_transform(chunk: any, encoding: BufferEncoding, callback: TransformCallback): void {
		const buff = sodium_malloc(chunk.length);

		crypto_stream_xor_update(this._stateBuffer, buff, chunk);

		this.push(buff);

		callback();
	}

	_flush(callback: TransformCallback): void {
		crypto_stream_xor_final(this._stateBuffer);
		sodium_memzero(this._stateBuffer);
		sodium_memzero(this._nonceBuffer);
		sodium_memzero(this._secretKeyBuffer);

		callback();
	}
}

//class used to encrypt/decrypt streams with additional authentication information.
//this is a transform stream and hence to be used inside a stream pipeline.
class cryptoSecretStream extends Transform {
	private _secretKeyBuffer: Buffer;
	private _headerBuffer: Buffer;
	private _stateBuffer: Buffer;
	public header: string;

	constructor(private action: ISecretStreamAction, secretKey: string, header: string = undefined) {
		super();

		if (action === 'decrypt' && !header) {
			throw new Error('For decryption the header must be specified');
		}

		this._secretKeyBuffer = sodium_malloc(secretStreamKeyBytes);
		this._stateBuffer = sodium_malloc(secretStreamStateBytes);
		this._headerBuffer = sodium_malloc(secretStreamHeaderBytes);

		this._secretKeyBuffer.fill(secretKey, 0, secretStreamKeyBytes, keyEncoding);

		if (action === 'decrypt') {
			this._headerBuffer.fill(header, 0, secretStreamHeaderBytes, keyEncoding);
		}

		if (action === 'encrypt') {
			//@ts-ignore
			crypto_secretstream_xchacha20poly1305_init_push(this._stateBuffer, this._headerBuffer, this._secretKeyBuffer);
			this.header = this._headerBuffer.toString(keyEncoding);
		} else {
			//@ts-ignore
			crypto_secretstream_xchacha20poly1305_init_pull(this._stateBuffer, this._headerBuffer, this._secretKeyBuffer);
		}
	}

	_transform(chunk: any, encoding: BufferEncoding, callback: TransformCallback): void {
		const buff = sodium_malloc(
			this.action === 'encrypt' ? chunk.length + secretStreamABytes : chunk.length - secretStreamABytes
		);

		const tagBuff = sodium_malloc(secretStreamTagBytes);

		if (this.action === 'encrypt') {
			crypto_secretstream_xchacha20poly1305_push(
				//@ts-ignore
				this._stateBuffer,
				buff,
				chunk,
				null,
				secretStreamMessageTag
			);
		} else {
			crypto_secretstream_xchacha20poly1305_pull(
				//@ts-ignore
				this._stateBuffer,
				buff,
				tagBuff,
				chunk,
				null
			);
			sodium_memzero(tagBuff);
		}

		this.push(buff);

		callback();
	}

	_flush(callback: TransformCallback): void {
		sodium_memzero(this._stateBuffer);
		callback();
	}
}

//export various types
export type { IKeyPair, IHashInput, IHashResult, ICipher };

//export various functions
export {
	bulk_Decrypt_SharedBox,
	bulk_Encrypt_SharedBox,
	decrypt_SealedBox,
	decrypt_SecretBox,
	decrypt_SharedBox,
	encrypt_SealedBox,
	encrypt_SecretBox,
	encrypt_SharedBox,
	generateKeyPair,
	generateKeyPairFromPassword,
	generatePublicKey,
	generateSecretKey,
	generateSecretKeyFromPassword,
	generateSharedKey,
	createHash,
	verifyHash,
	hashPassword,
	verifyPassword,
	getHashInputsFromStr,
	getHashResultFromStr,
	stringifyHashInputs,
	stringifyHashResult,
	keyEncoding,
	cipherEncoding,
	hashDefaults,
	macBytes,
	saltBytes,
	publicKeyBytes,
	secretKeyBytes,
	nonceBytes,
	pwHashBytes,
	easyPwHashBytes,
	sealBytes,
	streamChunkBytes,
	generateRandomValue,
	streamNonceBytes,
	streamKeyBytes,
	cryptoStream,
	cryptoSecretStream,
	secretStreamRawChunkBytes,
	secretStreamEncryptedChunkBytes,
};
