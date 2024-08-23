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

    kmsCryptoClient.endpoint = vault.cryptoEndpoint;
    kmsManagementClient.endpoint = vault.managementEndpoint;

    const ciphertext = await versleutel(kmsCryptoClient, config.keyId, "Hello World	");
    await ontsleutel(kmsCryptoClient, config.keyId, ciphertext);

    //const rsaKeyId = await createRSAKey(kmsManagementClient, config.compartmentId, "Test_RSA_Key_v1");

    const rsaKeyVersion = await getCurrentVersion(kmsManagementClient, config.rsaKeyId);
    const publicCert = await getRSAPublicPart(kmsManagementClient, config.rsaKeyId, rsaKeyVersion);

    const encryptedData = await versleutelRSA(kmsCryptoClient, config.rsaKeyId, rsaKeyVersion, "Hello RSA World");
    await ontsleutelRSA(kmsCryptoClient, config.rsaKeyId, rsaKeyVersion, encryptedData);

    const publicEncrypted = await versleutelMetPublicCert(publicCert, "Hello public World");
    await ontsleutelRSA(kmsCryptoClient, config.rsaKeyId, rsaKeyVersion, publicEncrypted);

    console.log('\nPublic cert:\n', publicCert);
  } catch (error) {
    console.log(error);
  }
})();

/* 
  Definition of the functions used in the main script
*/
async function getVault(client, vault) {
  const response = await client.getVault({ vaultId: vault });
  return response.vault;
}

async function createAESsleutel(client, compartmentId, displayName) {
  const response = await client.createKey({
    createKeyDetails: {
      keyShape: {
        algorithm: kms.models.KeyShape.Algorithm.Aes,
        length: 32
      },
      compartmentId: compartmentId,
      displayName: displayName,
      freeformTags: getSampleFreeformTagData()
    }
  });
  return response.key.id;
}

async function getAESSleutel(client, keyId) {
  const response = await client.getKey({ keyId: keyId });
  console.log(" Key Retrieved " + JSON.stringify(response.key.displayName));
}

async function versleutel(client, keyId, plainText) {
  const response = await client.encrypt({
    encryptDataDetails: {
      keyId: keyId,
      plaintext: Buffer.from(plainText).toString("base64"),
      loggingContext: getSampleLoggingContext()
    }
  });
  return response.encryptedData.ciphertext;
}

async function versleutelRSA(client, keyId, keyVersionId, plainText) {
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

async function ontsleutel(client, keyId, ciphertext) {
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

function getSampleLoggingContext() {
  return {
    loggingContextKey1: "loggingContextValue1",
    loggingContextKey2: "loggingContextValue2"
  };
}

async function createRSAKey(client, compartmentId, displayName) {
  const response = await client.createKey({
    createKeyDetails: {
      keyShape: {
        algorithm: kms.models.KeyShape.Algorithm.Rsa,
        length: 512
      },
      compartmentId: compartmentId,
      displayName: displayName,
      freeformTags: getSampleFreeformTagData()
    }
  });
  return response.key.id;
}

function getSampleFreeformTagData() {
  return {
    dummyfreeformkey1: "dummyfreeformvalue1",
    dummyfreeformkey2: "dummyfreeformvalue2"
  };
}

async function getCurrentVersion(client, rsaKeyId) {
  const response = await client.getKey({
    keyId: rsaKeyId
  });
  return response.key.currentKeyVersion;
}

async function getRSAPublicPart(client, rsaKeyId, rsaKeyVersion) {
  const response = await client.getKeyVersion({
    keyId: rsaKeyId,
    keyVersionId: rsaKeyVersion
  });
  return response.keyVersion.publicKey;
}

async function versleutelRSA(client, keyId, rsaKeyVersion, plainText) {
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

async function ontsleutelRSA(client, keyId, rsaKeyVersion, ciphertext) {
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

async function versleutelMetPublicCert(publicCert, plainText) {
  const crypto = require('crypto');
  const encrypted = crypto.publicEncrypt(publicCert, Buffer.from(plainText));
  const encryptedBase64 = encrypted.toString('base64');

  return encryptedBase64;
}