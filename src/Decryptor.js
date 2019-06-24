import { promisify } from 'util';
import {
  pbkdf2,
  createDecipheriv,
} from 'crypto';

const VAULT_HEADER = '$ANSIBLE_VAULT;1.1;AES256';
const ALGORITHM = 'aes-256-ctr';
const pbkdf2Async = promisify(pbkdf2);

export default class Decryptor {
  constructor(secret, content) {
    this.secret = secret;
    this.content = content;
    this.dechipher = null;
    this.decodedContent = null;
    this.salt = null;
    this.payload = null;
    this.decrypted = null;
    this.result = this.init();
  }

  init = async () => {
    this.getDecodedContent();
    this.getSalt();
    this.getPayload();
    await this.getCipherData()
    this.createDecipher();
    this.decryptContent();
    return this.decrypted;
  }

  getDecodedContent = content => {
    this.content = this.content.split('\n')
      .slice(1, this.content.length)
      .join('\n');

    this.content = Buffer.from(this.content.replace(/\n|\r|\f/g, ''), 'hex');
  }

  getSalt = () => {
    const lines = String.fromCharCode.apply(null, [...this.content]).split('\n');
    this.salt = Buffer.from(lines[0], 'hex');
  }

  getPayload = content => {
    const lines = String.fromCharCode.apply(null, [...this.content]).split('\n');
    this.payload = Buffer.from(lines[2], 'hex');
  }

  getCipherData = async () => {
    const key = await pbkdf2Async(this.secret, this.salt, 10000, 80, 'sha256');
    this.cipherKey = key.slice(0, 32);
    this.hmacKey = key.slice(32, 64);
    this.iv = key.slice(64, 80);
  }

  createDecipher = (cipherKey, cipherIv) => {
    this.dechipher = createDecipheriv(ALGORITHM, this.cipherKey, this.iv);
  }

  decryptContent = () => {
    this.decrypted = this.dechipher.update(this.payload);
    this.decrypted = this.decrypted + this.dechipher.final('utf-8');
  }
}
