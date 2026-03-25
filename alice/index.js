const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();
app.use(express.json());

const PORT = 3000;
const BOB_BASE_URL = `http://${process.env.BOB_IP}:${process.env.BOB_PORT}`;
const BOB_RECEIVE_URL = `${BOB_BASE_URL}/receive`;

function generateRsaKeyPair(ownerLabel) {
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        console.log(`[KEYGEN] RSA key pair generated for ${ownerLabel}`);
        return { publicKey, privateKey };
    } catch (error) {
        console.error(`[KEYGEN] Failed to generate key pair for ${ownerLabel}:`, error.message);
        throw error;
    }
}

const aliceKeys = generateRsaKeyPair('Alice');
let cachedBobPublicKey;

async function getBobPublicKey() {
    if (cachedBobPublicKey) {
        return cachedBobPublicKey;
    }
    try {
        const response = await axios.get(`${BOB_BASE_URL}/public-key`);
        cachedBobPublicKey = response.data.publicKey;
        console.log('[ALICE] Bob public key cached for future use');
        return cachedBobPublicKey;
    } catch (error) {
        console.error('[ALICE] Failed to fetch Bob public key:', error.message);
        throw new Error('Tidak dapat mengambil public key Bob');
    }
}

app.get('/public-key', (_req, res) => {
    res.json({ publicKey: aliceKeys.publicKey });
});

app.post('/send', async (req, res) => {
    console.log(`\n[ALICE] Memulai proses pengiriman pesan ke Bob...`);
    try {
        const { message } = req.body;
        if (!message || typeof message !== 'string') {
            return res.status(400).json({ error: 'Field "message" (string) wajib diisi' });
        }
        console.log(`\n[ALICE] 1. Alice membuat plaintext: "${message}"`);
        const bobPublicKey = await getBobPublicKey();

        // Generate AES-256 key dan IV 96-bit untuk AES-GCM
        const aesKey = crypto.randomBytes(32);
        const iv = crypto.randomBytes(12);
        console.log('[ALICE] 2. Alice membuat symmetric key (AES256)');

        // Enkripsi plaintext dengan AES-256-GCM
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        const ciphertext = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]);
        const authTag = cipher.getAuthTag();
        console.log('[ALICE] 3. Alice mengenkripsi pesan');

        // Enkripsi AES key dengan RSA-OAEP (public key Bob)
        const encryptedKey = crypto.publicEncrypt({
            key: bobPublicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, aesKey);
        console.log('[ALICE] 4. Alice mengenkripsi symmetric key dengan public key Bob');

        // Hash plaintext dengan SHA-256
        const hashBuffer = crypto.createHash('sha256').update(message, 'utf8').digest();
        const hashHex = hashBuffer.toString('hex');
        console.log('[ALICE] 5. Alice membuat hash (SHA256)');

        // Tanda tangani hash menggunakan private key Alice (RSASSA-PSS)
        const signature = crypto.sign('sha256', hashBuffer, {
            key: aliceKeys.privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        });
        console.log('[ALICE] 6. Alice membuat digital signature dengan private key Alice');

        const ciphertextB64 = ciphertext.toString('base64');
        const encryptedKeyB64 = encryptedKey.toString('base64');
        const signatureB64 = signature.toString('base64');
        const securePayload = {
            source_ip: '172.20.0.10',
            destination_ip: '172.20.0.20',
            ciphertext: ciphertextB64,
            iv: iv.toString('base64'),
            auth_tag: authTag.toString('base64'),
            encrypted_key: encryptedKeyB64,
            hash: hashHex,
            signature: signatureB64,
            hash_algorithm: 'SHA256',
            symmetric_algorithm: 'AES256-GCM',
            asymmetric_algorithm: 'RSA2048'
        };
        console.log('[ALICE] 7. Alice mengirim payload:');
        console.log(JSON.stringify(securePayload, null, 2));

        console.log(`[ALICE] Mengirim payload terenkripsi ke ${BOB_RECEIVE_URL}`);
        const response = await axios.post(BOB_RECEIVE_URL, securePayload);
        res.json({ status: response.data.status });
    } catch (error) {
        console.error('[ALICE] Gagal memproses pengiriman:', error.message);
        res.status(500).json({ error: 'Terjadi kesalahan saat mengirim pesan secara aman' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`[ALICE] Server berjalan di IP 172.20.0.10 Port ${PORT}`);
});
