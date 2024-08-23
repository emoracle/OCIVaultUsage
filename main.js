const config = require('./config/config.json');

const kms = require("oci-keymanagement");
const common = require("oci-common");

const provider = new common.ConfigFileAuthenticationDetailsProvider();
const kmsVaultClient = new kms.KmsVaultClient({ authenticationDetailsProvider: provider });
const kmsManagementClient = new kms.KmsManagementClient({ authenticationDetailsProvider: provider });
const kmsCryptoClient = new kms.KmsCryptoClient({ authenticationDetailsProvider: provider });

(async () => {
  try {
    // Get the details of the given Vault to set the endpoints for the Management and Crypto clients.
    const vault = await getVault(kmsVaultClient, config.vaultId);

    // Set the endpoints for the Management and Crypto clients.
    kmsCryptoClient.endpoint = vault.cryptoEndpoint;
    kmsManagementClient.endpoint = vault.managementEndpoint;

    // Encrypt and decrypt a text with a symmetric key
    const ciphertext = await encryptWithAES(kmsCryptoClient, config.keyId, "Hello World	");
    await decryptFromAES(kmsCryptoClient, config.keyId, ciphertext);

    //const rsaKeyId = await createRSAKey(kmsManagementClient, config.compartmentId, "Test_RSA_Key_v1");
    //const aeskeyId = await createAESsleutel(kmsManagementClient, config.compartmentId, "Test_AES_Key_v3"); 

    //The public key is not available in the response of the createKey operation,  But it is available in the version of the key.
    const rsaKeyVersion = await getCurrentVersion(kmsManagementClient, config.rsaKeyId);
    const publicCert = await getRSAPublicPart(kmsManagementClient, config.rsaKeyId, rsaKeyVersion);

    // Encrypt and decrypt a text with a asymmetric key
    const encryptedData = await encryptWithRSA(kmsCryptoClient, config.rsaKeyId, rsaKeyVersion, "Hello RSA World");
    await decryptFromRSAWithPrivateKey(kmsCryptoClient, config.rsaKeyId, rsaKeyVersion, encryptedData);

    const publicEncrypted = await encryptWithPublicCert(publicCert, "Hello public World");
    await decryptFromRSAWithPrivateKey(kmsCryptoClient, config.rsaKeyId, rsaKeyVersion, publicEncrypted);

    // Print the public certificate (the pem format)
    console.log('\nPublic cert:\n', publicCert);

    
  } catch (error) {
    console.log(error);
  }
})();

/* 
  Definition of the functions used in the main script
*/

/**
 * Retrieves the specified vault from the client.
 *
 * @param {object} client - The client object used to interact with the vault.
 * @param {string} vault - The ID of the vault to retrieve.
 * @returns {Promise<object>} - A promise that resolves to the retrieved vault.
 */
async function getVault(client, vault) {
  const response = await client.getVault({ vaultId: vault });
  return response.vault;
}

/**
 * Creates an AES sleutel (key) using the specified client, compartment ID, and display name.
 * Protection mode is set to software (free) and not the default Hsm
 * @param {object} client - The client object used to create the key.
 * @param {string} compartmentId - The ID of the compartment where the key will be created.
 * @param {string} displayName - The display name of the key.
 * @returns {string} The ID of the created key.
 */
async function createAESsleutel(client, compartmentId, displayName) {
  const response = await client.createKey({
    createKeyDetails: {
      keyShape: {
        algorithm: kms.models.KeyShape.Algorithm.Aes,
        length: 32
      },
      compartmentId: compartmentId,
      displayName: displayName,
      protectionMode: kms.models.CreateKeyDetails.ProtectionMode.Software,
      freeformTags: getSampleFreeformTagData()
    }
  });
  return response.key.id;
}

/**
 * Retrieves an AES sleutel (key) from the client.
 * 
 * @param {object} client - The client object used to retrieve the key.
 * @param {string} keyId - The ID of the key to retrieve.
 * @returns {Promise<void>} - A promise that resolves when the key is retrieved.
 */
async function getAESSleutel(client, keyId) {
  const response = await client.getKey({ keyId: keyId });
  console.log(" Key Retrieved " + JSON.stringify(response.key.displayName));
}

/**
 * Encrypts the given plain text using the specified client and key ID.
 * @param {Client} client - The client used for encryption.
 * @param {string} keyId - The ID of the key used for encryption.
 * @param {string} plainText - The plain text to be encrypted.
 * @returns {string} The encrypted ciphertext.
 */
async function encryptWithAES(client, keyId, plainText) {
  const response = await client.encrypt({
    encryptDataDetails: {
      keyId: keyId,
      plaintext: Buffer.from(plainText).toString("base64"),
      loggingContext: getSampleLoggingContext()
    }
  });
  return response.encryptedData.ciphertext;
}

/**
 * Encrypts the given plain text using RSA encryption.
 * 
 * @param {object} client - The client object used for encryption.
 * @param {string} keyId - The ID of the key used for encryption.
 * @param {string} keyVersionId - The version ID of the key used for encryption.
 * @param {string} plainText - The plain text to be encrypted.
 * @returns {string} - The encrypted ciphertext.
 */
async function encryptWithRSA(client, keyId, keyVersionId, plainText) {
  const response = await client.encrypt({
    encryptDataDetails: {
      keyId: keyId,
      plaintext: Buffer.from(plainText).toString("base64"),
      loggingContext: getSampleLoggingContext(),
      keyVersionId: keyVersionId
    }
  });
  return response.encryptedData.ciphertext;
}

/**
 * Decrypts the given ciphertext using the specified keyId.
 * 
 * @param {object} client - The client object used for decryption.
 * @param {string} keyId - The ID of the key used for decryption.
 * @param {string} ciphertext - The ciphertext to be decrypted.
 * @returns {Promise<void>} - A promise that resolves when the decryption is complete.
 */
async function decryptFromAES(client, keyId, ciphertext) {
  const response = await client.decrypt({
    decryptDataDetails: {
      ciphertext: ciphertext,
      keyId: keyId
    }
  });
  const buffer = Buffer.from(response.decryptedData.plaintext, 'base64');
  const decodedText = buffer.toString('utf-8');
  console.log("Decoded Text:", decodedText);
}

/**
 * Returns a sample logging context object.
 * @returns {Object} The logging context object.
 */
function getSampleLoggingContext() {
  return {
    loggingContextKey1: "loggingContextValue1",
    loggingContextKey2: "loggingContextValue2"
  };
}

/**
 * Creates an RSA key.
 * protectionMode is set to software (free) and not the default Hsm
 * @param {object} client - The client object.
 * @param {string} compartmentId - The compartment ID.
 * @param {string} displayName - The display name.
 * @returns {string} - The ID of the created key.
 */
async function createRSAKey(client, compartmentId, displayName) {
  const response = await client.createKey({
    createKeyDetails: {
      keyShape: {
        algorithm: kms.models.KeyShape.Algorithm.Rsa,
        length: 512
      },
      compartmentId: compartmentId,
      displayName: displayName,
      protectionMode: kms.models.CreateKeyDetails.ProtectionMode.Software,
      freeformTags: getSampleFreeformTagData()
    }
  });
  return response.key.id;
}

/**
 * Retrieves sample freeform tag data.
 * @returns {Object} The sample freeform tag data.
 */
function getSampleFreeformTagData() {
  return {
    dummyfreeformkey1: "dummyfreeformvalue1",
    dummyfreeformkey2: "dummyfreeformvalue2"
  };
}

/**
 * Retrieves the current version of a key from the client.
 * 
 * @param {object} client - The client object used to interact with the key.
 * @param {string} rsaKeyId - The ID of the RSA key.
 * @returns {Promise<number>} - The current key version.
 */
async function getCurrentVersion(client, rsaKeyId) {
  const response = await client.getKey({
    keyId: rsaKeyId
  });
  return response.key.currentKeyVersion;
}

/**
 * Retrieves the RSA public part for a given RSA key.
 * 
 * @param {Client} client - The client object used to interact with the key service.
 * @param {string} rsaKeyId - The ID of the RSA key.
 * @param {string} rsaKeyVersion - The version of the RSA key.
 * @returns {string} The RSA public key.
 */
async function getRSAPublicPart(client, rsaKeyId, rsaKeyVersion) {
  const response = await client.getKeyVersion({
    keyId: rsaKeyId,
    keyVersionId: rsaKeyVersion
  });
  return response.keyVersion.publicKey;
}

/**
 * Encrypts the given plain text using RSA encryption algorithm.
 * 
 * @param {object} client - The client object used for encryption.
 * @param {string} keyId - The ID of the key used for encryption.
 * @param {string} rsaKeyVersion - The version of the RSA key used for encryption.
 * @param {string} plainText - The plain text to be encrypted.
 * @returns {string} - The encrypted ciphertext.
 */
async function encryptWithRSA(client, keyId, rsaKeyVersion, plainText) {
  const response = await client.encrypt({
    encryptDataDetails: {
      keyId: keyId,
      plaintext: Buffer.from(plainText).toString("base64"),
      loggingContext: getSampleLoggingContext(),
      keyVersionId: rsaKeyVersion,
      encryptionAlgorithm: kms.models.EncryptDataDetails.EncryptionAlgorithm.RsaOaepSha1
    }
  });
  return response.encryptedData.ciphertext;
}

/**
 * Decrypts the given ciphertext using RSA encryption algorithm.
 * 
 * @param {object} client - The client object used for decryption.
 * @param {string} keyId - The ID of the key used for decryption.
 * @param {string} rsaKeyVersion - The version of the RSA key used for decryption.
 * @param {string} ciphertext - The ciphertext to be decrypted.
 * @returns {Promise<void>} - A promise that resolves when the decryption is complete.
 */
async function decryptFromRSAWithPrivateKey(client, keyId, rsaKeyVersion, ciphertext) {
  const response = await client.decrypt({
    decryptDataDetails: {
      ciphertext: ciphertext,
      keyId: keyId,
      keyVersionId: rsaKeyVersion,
      encryptionAlgorithm: kms.models.EncryptDataDetails.EncryptionAlgorithm.RsaOaepSha1
    }
  });
  const buffer = Buffer.from(response.decryptedData.plaintext, 'base64');
  const decodedText = buffer.toString('utf-8');
  console.log("Decoded Text:", decodedText);
}

/**
 * Encrypts the given plain text using the provided public certificate.
 *
 * @param {string} publicCert - The public certificate used for encryption.
 * @param {string} plainText - The plain text to be encrypted.
 * @returns {string} - The encrypted text in base64 format.
 */
async function encryptWithPublicCert(publicCert, plainText) {
  const crypto = require('crypto');
  const encrypted = crypto.publicEncrypt(publicCert, Buffer.from(plainText));
  const encryptedBase64 = encrypted.toString('base64');

  return encryptedBase64;
}