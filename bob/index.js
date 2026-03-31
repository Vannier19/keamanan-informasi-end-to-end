const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const PORT = 4000;
const ALICE_URL = `http://${process.env.ALICE_IP || '172.20.0.10'}:${process.env.ALICE_PORT || '3000'}`;

function generateRsaKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
}

const bobKeys = generateRsaKeyPair();
let cachedAlicePublicKey = null;

async function getAlicePublicKey() {
    if (cachedAlicePublicKey) return cachedAlicePublicKey;
    
    try {
        const res = await axios.get(`${ALICE_URL}/public-key`);
        cachedAlicePublicKey = res.data.publicKey;
        return cachedAlicePublicKey;
    } catch (error) {
        throw new Error('Gagal mengambil public key Alice');
    }
}

function formatOutput(value, limit = 60) {
    if (!value) return '-';
    return value.length <= limit ? value : `${value.substring(0, limit)}...`;
}


app.get('/public-key', (req, res) => {
    res.json({ publicKey: bobKeys.publicKey });
});

app.post('/receive', async (req, res) => {
    try {
        const { ciphertext, iv, auth_tag, encrypted_key, hash, signature } = req.body;
        
        if (!ciphertext || !iv || !auth_tag || !encrypted_key || !hash || !signature) {
            return res.status(400).json({ error: 'Payload tidak lengkap' });
        }

        const alicePublicKey = await getAlicePublicKey();
        console.log(`[Bob] Menerima pesan terenkripsi dari ${req.ip}`);

        // Dekripsi symmetric key menggunakan private key Bob
        const aesKey = crypto.privateDecrypt({
            key: bobKeys.privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, Buffer.from(encrypted_key, 'base64'));

        // Dekripsi pesan menggunakan AES-256-GCM
        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'base64'));
        decipher.setAuthTag(Buffer.from(auth_tag, 'base64'));
        
        const plaintext = Buffer.concat([
            decipher.update(Buffer.from(ciphertext, 'base64')),
            decipher.final()
        ]).toString('utf8');

        console.log(`[Bob] Pesan terdekripsi: "${plaintext}"`);

        // Verifikasi integritas hash
        const computedHash = crypto.createHash('sha256').update(plaintext, 'utf8').digest();
        const receivedHash = Buffer.from(hash, 'hex');
        
        const hashValid = computedHash.length === receivedHash.length &&
            crypto.timingSafeEqual(computedHash, receivedHash);

        if (!hashValid) {
            return res.status(400).json({ error: 'Verifikasi hash gagal' });
        }

        // Verifikasi digital signature
        const signatureValid = crypto.verify('sha256', computedHash, {
            key: alicePublicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        }, Buffer.from(signature, 'base64'));

        if (!signatureValid) {
            return res.status(400).json({ error: 'Verifikasi signature gagal - pesan ditolak' });
        }

        console.log(`[Bob] Verifikasi pesan: SUKSES`);
        console.log(`  - Hash valid: ${hashValid}`);
        console.log(`  - Signature valid: ${signatureValid}`);
        console.log('---');
        console.log(`Plaintext: ${plaintext}`);
        console.log(`Hash: ${hash}`);
        console.log(`Dari: ${req.body.source_ip || 'unknown'} -> Ke: ${req.body.destination_ip || 'unknown'}`);
        console.log('---');

        res.json({ 
            status: 'Pesan diterima dan terverifikasi',
            plaintext,
            verifikasi: {
                hash_valid: hashValid,
                signature_valid: signatureValid
            }
        });
    } catch (error) {
        console.error('[Bob] Gagal memproses pesan:', error.message);
        res.status(500).json({ error: 'Gagal memproses pesan terenkripsi' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Bob] Layanan dekripsi berjalan di port ${PORT}`);
});
