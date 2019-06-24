import { load } from 'js-yaml';
import { promisify } from 'util';
import {
  pbkdf2,
  createCipheriv,
  randomBytes,
  createHmac,
} from 'crypto';

const VAULT_HEADER = '$ANSIBLE_VAULT;1.1;AES256';
const ALGORITHM = 'aes-256-ctr';
const pbkdf2Async = promisify(pbkdf2);
const keyLen = 32;

export default class Encryptor {
	constructor(secret, content) {
		this.secret = secret;
		this.content = content;
		this.result = this.init();
	}

	init = async () => {
		this.createSalt();
		await this.getKey();
		this.getCipher();
		this.encryptContent();
		this.getSecret();
		return this.all;
	}

	createSalt = () => {
		this.salt = randomBytes(keyLen);
	}

	getKey = async () => {
		this.key = await pbkdf2Async(this.secret, this.salt, 10000, 80, 'sha256');
		this.cipherKey = this.key.slice(0, 32);
		this.hmacKey = this.key.slice(32, 64);
		this.iv = this.key.slice(64, 80);
	}

	getCipher = () => {
		this.cipher = createCipheriv(ALGORITHM, this.cipherKey, this.iv);
	}

	encryptContent = () => {
		this.encrypted = this.cipher.update(this.content, 'utf8', 'hex');
		this.encrypted = this.encrypted + this.cipher.final('hex');
	}

	getSecret = () => {
		let hexHmac = createHmac('sha256', this.hmacKey)
			.update(this.encrypted)
			.digest('hex');
		let hexSalt = Buffer.from(this.salt).toString('hex');

		this.all = `${hexSalt}\n${hexHmac}\n${this.encrypted}`;
		let all = '';
		let buffer = Buffer.from(this.all, 'utf8');
		buffer = buffer.toString('hex');

		let good = '';
		[...buffer].forEach((char, index) => {
			if(index > 0 && index%80 === 0) {
				good += '\n';
			}
			good += char;
		});

		this.all = `${VAULT_HEADER}\n${good}`;
	}
}