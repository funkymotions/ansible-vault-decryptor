# anible-vault-decryptor

This package implements encryption and decryption of content
created by ansible-vault software package https://docs.ansible.com/ansible/latest/user_guide/vault.html


### Methods:
###### encryptContent(:string, :string)
    import { encryptContent } from 'ansible-vault-decryptor';
    
    const encrypted = await encryptContent(content, secret);
###### decryptContent(:string, :string)
    import { decryptContent } from 'ansible-vault-decryptor';
    
    const decrypted = await decryptContent(encryptedContent, secret);
###### decryptFile(:string, :string)
    import { decryptFile } from 'ansible-vault-decryptor';
    
    const decrypted = await decryptFile(filePath, secret);

## Licence
MIT