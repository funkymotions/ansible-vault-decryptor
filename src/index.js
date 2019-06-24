import { promisify } from 'util';
import {
  exists,
  readFile,
} from 'fs';
import PasswordDecryptor from './Decryptor';
import Encryptor from './Encryptor';

const VAULT_HEADER = /\$ANSIBLE_VAULT;[0-9]\.[0-9];AES256/;
const isFileExists = promisify(exists);
const readFileAsync = promisify(readFile);

const decryptContent = async (content, secret) => {
  if (VAULT_HEADER.test(content)) {
    const decryptor = new PasswordDecryptor(secret, content);
    const res = await decryptor.result;
    return res;
  }
  throw new Error('Cannot validate vault file');
};

const decryptFile = async (filePath, secret) => {
  const isExists = await isFileExists(filePath);
  if (isExists) {
    const fileContent = await readFileAsync(filePath, 'utf-8');
    const content = await decryptContent(fileContent, secret);
    return content;
  }
  throw new Error('Cannot find vault file');
};

const encryptContent = async (content, secret) => {
  const encryptor = new Encryptor(secret, content);
  const res = await encryptor.result;
  return res;
};

export {
  decryptContent,
  decryptFile,
  encryptContent,
};
