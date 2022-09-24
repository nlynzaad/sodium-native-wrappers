import {
	crypto_pwhash_OPSLIMIT_MODERATE,
	crypto_pwhash_MEMLIMIT_MODERATE,
	crypto_pwhash_ALG_DEFAULT,
	crypto_box_SECRETKEYBYTES,
	crypto_box_PUBLICKEYBYTES,
	crypto_box_NONCEBYTES,
	crypto_pwhash_SALTBYTES,
	crypto_pwhash_STRBYTES,
	crypto_box_SEALBYTES,
	crypto_box_MACBYTES,
	sodium_malloc,
	sodium_memzero,
	crypto_box_keypair,
	crypto_box_easy,
	crypto_box_open_easy,
	crypto_box_seal,
	crypto_box_seal_open,
	crypto_kdf_keygen,
	crypto_pwhash,
	crypto_pwhash_str,
	crypto_pwhash_str_verify,
	crypto_scalarmult,
	crypto_scalarmult_base,
	crypto_secretbox_easy,
	crypto_secretbox_open_easy,
	randombytes_buf,
} from 'sodium-native';

interface ICipher {
	encoding: BufferEncoding;
	nonce: Buffer | string | undefined;
	cipher: Buffer | string;
}

interface IKeyPair {
	publicKey: string;
	secretKey: string;
}

interface IHashResult {
	hash: string;
	hashInputs: IHashInput;
}

interface IHashInput {
	salt?: string | undefined;
	opsLimit?: number | undefined;
	memLimit?: number | undefined;
	alg?: number | undefined;
}

const hashDefaults: Pick<IHashInput, 'opsLimit' | 'memLimit' | 'alg'> = {
	opsLimit: crypto_pwhash_OPSLIMIT_MODERATE,
	memLimit: crypto_pwhash_MEMLIMIT_MODERATE,
	alg: crypto_pwhash_ALG_DEFAULT,
};

const keyEncoding: BufferEncoding = 'base64';
const cipherEncoding: BufferEncoding = 'base64';

const secretKeyBytes = crypto_box_SECRETKEYBYTES;
const publicKeyBytes = crypto_box_PUBLICKEYBYTES;
const nonceBytes = crypto_box_NONCEBYTES;
const macBytes = crypto_box_MACBYTES;
const saltBytes = crypto_pwhash_SALTBYTES;
const pwHashBytes = 32;
const easyPwHashBytes = crypto_pwhash_STRBYTES;
const sealBytes = crypto_box_SEALBYTES;

const textEncoding: { [key: string]: BufferEncoding } = {
	utf8: 'utf8',
	base64: 'base64',
	hex: 'hex',
};

const isBase64 = (data: string): boolean => {
	const base64 = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

	return base64.test(data);
};

const isHex = (data: string): boolean => {
	return /^[A-F0-9]+$/i.test(data);
};

const getEncoding = (data: string): BufferEncoding =>
	isBase64(data) ? textEncoding.base64 : isHex(data) ? textEncoding.hex : textEncoding.utf8;

const stringifyHashResult = (hashResult: IHashResult): string => {
	const hash = hashResult.hash;
	return hash.concat('.', stringifyHashInputs(hashResult.hashInputs));
};

const stringifyHashInputs = (hashInput: IHashInput): string => {
	return Object.entries(hashInput)
		.sort((a, b) => a[0].localeCompare(b[0]))
		.map((entry) => entry[1])
		.join('.');
};

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

const getHashInputsFromStr = (hashInpuStr: string): IHashInput => {
	const [salt, opsLimitStr, memLimitStr, algStr] = hashInpuStr.split('.');

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

const stringifyCipher = ({ encoding, nonce, cipher }: ICipher): string => {
	const nonceStr = nonce && typeof nonce !== 'string' ? nonce.toString(cipherEncoding) : undefined;
	const cipherStr = typeof nonce !== 'string' ? cipher.toString(cipherEncoding) : cipher;

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

const createBuffers = (
	inputArray: { length: number; data?: string | ((buffer: Buffer) => void); encoding?: BufferEncoding }[]
): Buffer[] => {
	return inputArray.map((input) => {
		if (input.data && typeof input.data == 'string' && Buffer.byteLength(input.data, input.encoding) !== input.length)
			throw new Error(`Input value is not of length ${input.length}`);

		const buffer = sodium_malloc(input.length);

		if (input.data) {
			if (typeof input.data == 'string') {
				buffer.write(input.data, input.encoding);
			} else {
				input.data(buffer);
			}
		}

		return buffer;
	});
};

const fillBuffers = (
	inputArray: { buffer: Buffer; data: string | ((buffer: Buffer) => void); encoding?: BufferEncoding }[]
) => {
	inputArray.forEach((input) => {
		if (input.data) {
			if (typeof input.data == 'string') {
				input.buffer.write(input.data, input.encoding);
			} else {
				input.data(input.buffer);
			}
		}
	});
};

const zeroBuffers = (buffers: Buffer[]) => {
	return buffers.map((buffer) => sodium_memzero(buffer));
};

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

const generatePublicKey = async (secretKey: string): Promise<string> => {
	const encoding = getEncoding(secretKey);

	const [secretKeyBuff, publicKeyBuff] = createBuffers([
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
		{ length: publicKeyBytes },
	]);

	crypto_scalarmult_base(publicKeyBuff, secretKeyBuff);

	const publicKey = publicKeyBuff.toString(encoding);

	zeroBuffers([secretKeyBuff, publicKeyBuff]);

	return publicKey;
};

const generateSharedKey = async (publicKey: string, secretKey: string = undefined): Promise<string> => {
	const encoding = getEncoding(secretKey);

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

const generateSecretKeyFromPassword = async (
	password: string,
	hashInput: IHashInput | undefined = undefined
): Promise<{ secretKey: string; hashInputs: IHashInput }> => {
	const { hash: secretKey, hashInputs } = await createHash(password, hashInput, secretKeyBytes);

	return { secretKey, hashInputs };
};

const generateSecretKey = async (): Promise<string> => {
	const [secretKeyBuffer] = createBuffers([{ length: secretKeyBytes, data: crypto_kdf_keygen }]);

	return secretKeyBuffer.toString(keyEncoding);
};

const generateSalt = (): string => {
	const [saltBuff] = createBuffers([{ length: saltBytes, data: randombytes_buf }]);

	const salt = saltBuff.toString(keyEncoding);
	zeroBuffers([saltBuff]);

	return salt;
};

const encrypt_SecretBox = async (value: string, secretKey: string): Promise<string> => {
	const encoding = getEncoding(value);

	const valueLength = Buffer.byteLength(value);
	const cipherLength = valueLength + macBytes;

	const [nonceBuff, cipherBuff, valueBuff, secretKeyBuff] = createBuffers([
		{ length: nonceBytes, data: randombytes_buf },
		{ length: cipherLength },
		{ length: valueLength, data: value, encoding },
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
	]);

	crypto_secretbox_easy(cipherBuff, valueBuff, nonceBuff, secretKeyBuff);

	const cipherText = stringifyCipher({ encoding, nonce: nonceBuff, cipher: cipherBuff });

	zeroBuffers([cipherBuff, valueBuff, nonceBuff, secretKeyBuff]);

	return cipherText;
};

const decrypt_SecretBox = async (cipherText: string, secretKey: string): Promise<string> => {
	const { encoding, nonce, cipher } = getCipherFromStr(cipherText);

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

	const value = valueBuff.toString(encoding);

	zeroBuffers([cipherBuff, valueBuff, nonceBuff, secretKeyBuff]);

	return value;
};

const encrypt_SealedBox = async (value: string, publicKey: string): Promise<string> => {
	const encoding = getEncoding(value);
	const valueLength = Buffer.byteLength(value);
	const cipherLength = valueLength + sealBytes;

	const [cipherBuff, valueBuff, publicKeyBuff] = createBuffers([
		{ length: cipherLength },
		{ length: valueLength, data: value, encoding },
		{ length: publicKeyBytes, data: publicKey, encoding: keyEncoding },
	]);

	crypto_box_seal(cipherBuff, valueBuff, publicKeyBuff);

	const cipherText = stringifyCipher({ encoding, cipher: cipherBuff, nonce: undefined });

	zeroBuffers([cipherBuff, valueBuff, publicKeyBuff]);

	return cipherText;
};

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

const encrypt_SharedBox = async (value: string, publicKey: string, secretKey: string): Promise<string> => {
	const encoding = getEncoding(value);

	const valueLength = Buffer.byteLength(value, encoding);
	const cipherLength = valueLength + macBytes;

	const [nonceBuffer, cipherBuffer, valueBuffer, publicKeyBuffer, secretKeyBuffer] = createBuffers([
		{ length: nonceBytes, data: randombytes_buf },
		{ length: cipherLength },
		{ length: valueLength, data: value, encoding },
		{ length: publicKeyBytes, data: publicKey, encoding: keyEncoding },
		{ length: secretKeyBytes, data: secretKey, encoding: keyEncoding },
	]);

	crypto_box_easy(cipherBuffer, valueBuffer, nonceBuffer, publicKeyBuffer, secretKeyBuffer);

	const cipherText = stringifyCipher({ encoding, nonce: nonceBuffer, cipher: cipherBuffer });

	zeroBuffers([nonceBuffer, cipherBuffer, valueBuffer, publicKeyBuffer, secretKeyBuffer]);

	return cipherText;
};

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
					const encoding = getEncoding(message);
					const valueLength = Buffer.byteLength(message, encoding);
					const cipherLength = valueLength + macBytes;

					fillBuffers([
						{ buffer: nonceBuffer, data: randombytes_buf },
						{ buffer: valueBuffer, data: message, encoding },
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

					const cipherText = stringifyCipher({ encoding, nonce: nonceBuffer, cipher: cipherBuffer[index] });

					zeroBuffers([cipherBuffer[index], valueBuffer, nonceBuffer, publicKeyBuffer, secretKeyBuffer]);

					return cipherText;
				})
			))
		);
	}

	return encrypted;
};

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

const createHash = async (
	password: string,
	hashInput: IHashInput = undefined,
	hashLength: number = pwHashBytes
): Promise<IHashResult> => {
	const encoding = getEncoding(password);

	const { salt, opsLimit, memLimit, alg } = {
		salt: hashInput?.salt ?? generateSalt(),
		opsLimit: hashInput?.opsLimit ?? hashDefaults.opsLimit,
		memLimit: hashInput?.memLimit ?? hashDefaults.memLimit,
		alg: hashInput?.alg ?? hashDefaults.alg,
	};

	const [saltBuffer, valueBuffer, hashBuffer] = createBuffers([
		{ length: saltBytes, data: salt, encoding: keyEncoding },
		{ length: Buffer.byteLength(password), data: password, encoding },
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

const verifyHash = async (value: string, hashedValue: string): Promise<boolean> => {
	const hashResult = getHashResultFromStr(hashedValue);

	return (
		(await createHash(value, hashResult.hashInputs, Buffer.byteLength(hashResult.hash, cipherEncoding))).hash ===
		hashResult.hash
	);
};

const hashPassword = async (password: string): Promise<string> => {
	const [passwordBuffer, hashBuffer] = createBuffers([
		{ length: Buffer.byteLength(password), data: password, encoding: getEncoding(password) },
		{ length: easyPwHashBytes },
	]);

	crypto_pwhash_str(hashBuffer, passwordBuffer, hashDefaults.opsLimit, hashDefaults.memLimit);

	const hash = hashBuffer.toString(cipherEncoding);

	zeroBuffers([hashBuffer, passwordBuffer]);

	return hash;
};

const verifyPassword = async (password: string, hashedPassword: string): Promise<boolean> => {
	const [passwordBuffer, hashBuffer] = createBuffers([
		{ length: Buffer.byteLength(password), data: password, encoding: getEncoding(password) },
		{ length: easyPwHashBytes, data: hashedPassword, encoding: cipherEncoding },
	]);

	const result = crypto_pwhash_str_verify(hashBuffer, passwordBuffer);

	zeroBuffers([hashBuffer, passwordBuffer]);

	return result;
};

export type { IKeyPair, IHashInput, IHashResult, ICipher };

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
};
