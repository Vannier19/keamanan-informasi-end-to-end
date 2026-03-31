const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PORT = 3000;
const BOB_BASE_URL = `http://${process.env.BOB_IP}:${process.env.BOB_PORT}`;

function generateRsaKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
}

const aliceKeys = generateRsaKeyPair();
let cachedBobPublicKey = null;

async function getBobPublicKey() {
    if (cachedBobPublicKey) return cachedBobPublicKey;
    
    try {
        const res = await axios.get(`${BOB_BASE_URL}/public-key`);
        cachedBobPublicKey = res.data.publicKey;
        return cachedBobPublicKey;
    } catch (error) {
        throw new Error('Gagal mengambil public key Bob');
    }
}


app.get('/public-key', (req, res) => {
    res.json({ publicKey: aliceKeys.publicKey });
});

app.post('/send', async (req, res) => {
    try {
        const { message } = req.body;
        
        if (!message || typeof message !== 'string') {
            return res.status(400).json({ error: 'Field "message" harus diisi dengan string' });
        }

        const bobPublicKey = await getBobPublicKey();

        // Buat kunci AES-256 dan generate IV untuk GCM mode
        const aesKey = crypto.randomBytes(32);
        const iv = crypto.randomBytes(12);

        // Enkripsi pesan menggunakan AES-256-GCM
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        const ciphertext = Buffer.concat([
            cipher.update(message, 'utf8'),
            cipher.final()
        ]);
        const authTag = cipher.getAuthTag();

        // Bungkus symmetric key dengan public key Bob menggunakan RSA-OAEP
        const encryptedKey = crypto.publicEncrypt({
            key: bobPublicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, aesKey);

        // Buat hash SHA-256 dari plaintext
        const hashBuffer = crypto.createHash('sha256').update(message, 'utf8').digest();

        // Tanda tangani hash menggunakan private key Alice
        const signature = crypto.sign('sha256', hashBuffer, {
            key: aliceKeys.privateKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        });

        // Bangun payload dengan semua komponen terenkripsi
        const payload = {
            source_ip: '172.20.0.10',
            destination_ip: '172.20.0.20',
            ciphertext: ciphertext.toString('base64'),
            iv: iv.toString('base64'),
            auth_tag: authTag.toString('base64'),
            encrypted_key: encryptedKey.toString('base64'),
            hash: hashBuffer.toString('hex'),
            signature: signature.toString('base64'),
            hash_algorithm: 'SHA256',
            symmetric_algorithm: 'AES256-GCM',
            asymmetric_algorithm: 'RSA2048'
        };

        console.log(`[Alice] Mengirim pesan terenkripsi ke Bob (${message.length} bytes)`);
        const response = await axios.post(`${BOB_BASE_URL}/receive`, payload);
        
        res.json({ 
            status: 'berhasil',
            pesan: 'Pesan terenkripsi berhasil dikirim ke Bob',
            hasil: response.data
        });
    } catch (error) {
        console.error('[Alice] Gagal mengirim pesan:', error.message);
        res.status(500).json({ error: 'Gagal mengirim pesan terenkripsi' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Alice] Layanan enkripsi berjalan di port ${PORT}`);
});
