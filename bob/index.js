const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();
app.use(express.json());

const PORT = 4000;
const ALICE_BASE_URL = `http://${process.env.ALICE_IP || '172.20.0.10'}:${process.env.ALICE_PORT || '3000'}`;

const shortenValue = (value, limit = 60) => {
    if (!value) {
        return '-';
    }
    return value.length <= limit ? value : `${value.substring(0, limit)}...`;
};

const maskHexKey = (hexValue, visibleChars = 16) => {
    if (!hexValue) {
        return '-';
    }
    return hexValue.length <= visibleChars ? hexValue : `${hexValue.substring(0, visibleChars)}...`;
};

function printSummaryTable(rows) {
    const header = '| Field                         | Value |';
    const separator = '|------------------------------|-------|';
    console.log(header);
    console.log(separator);
    rows.forEach(([label, value]) => {
        const paddedLabel = label.padEnd(30, ' ');
        console.log(`| ${paddedLabel} | ${value} |`);
    });
}

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

const bobKeys = generateRsaKeyPair('Bob');
let cachedAlicePublicKey;

async function getAlicePublicKey() {
    if (cachedAlicePublicKey) {
        return cachedAlicePublicKey;
    }
    try {
        const response = await axios.get(`${ALICE_BASE_URL}/public-key`);
        cachedAlicePublicKey = response.data.publicKey;
        console.log('[BOB] Alice public key cached for future use');
        return cachedAlicePublicKey;
    } catch (error) {
        console.error('[BOB] Failed to fetch Alice public key:', error.message);
        throw new Error('Tidak dapat mengambil public key Alice');
    }
}

app.get('/public-key', (_req, res) => {
    res.json({ publicKey: bobKeys.publicKey });
});

app.post('/receive', async (req, res) => {
    console.log(`\n[BOB] 8. Bob menerima payload dari ${req.ip}`);
    try {
        const { ciphertext, iv, auth_tag, encrypted_key, hash, signature } = req.body;
        if (!ciphertext || !iv || !auth_tag || !encrypted_key || !hash || !signature) {
            return res.status(400).json({ error: 'Payload tidak lengkap untuk proses dekripsi' });
        }

        const alicePublicKey = await getAlicePublicKey();

        // Dekripsi AES key yang dibungkus dengan RSA-OAEP
        const aesKey = crypto.privateDecrypt({
            key: bobKeys.privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        }, Buffer.from(encrypted_key, 'base64'));
        console.log('[BOB] 9. Bob membuka symmetric key menggunakan private key Bob');

        // Dekripsi ciphertext menggunakan AES-256-GCM
        const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'base64'));
        decipher.setAuthTag(Buffer.from(auth_tag, 'base64'));
        const plaintextBuffer = Buffer.concat([
            decipher.update(Buffer.from(ciphertext, 'base64')),
            decipher.final()
        ]);
        const plaintext = plaintextBuffer.toString('utf8');
        console.log(`[BOB] 10. Bob membuka ciphertext menjadi plaintext: "${plaintext}"`);

        // Hitung ulang hash SHA-256 dan bandingkan
        const computedHash = crypto.createHash('sha256').update(plaintext, 'utf8').digest();
        const receivedHash = Buffer.from(hash, 'hex');
        console.log('[BOB] 11. Bob memverifikasi hash (Lokal vs Payload)');
        const hashesMatch = computedHash.length === receivedHash.length &&
            crypto.timingSafeEqual(computedHash, receivedHash);

        // Verifikasi tanda tangan digital dengan public key Alice
        const signatureValid = crypto.verify('sha256', computedHash, {
            key: alicePublicKey,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
        }, Buffer.from(signature, 'base64'));
        console.log('[BOB] 12. Bob memverifikasi signature menggunakan public key Alice');
        if (!hashesMatch) {
            return res.status(400).json({ error: 'Hash tidak cocok' });
        }

        if (!signatureValid) {
            return res.status(400).json({ error: 'Signature tidak valid, pesan ditolak' });
        }

        console.log('\n=========================================');
        console.log('[KESIMPULAN] Pesan berhasil didekripsi, integritas terjaga, dan diverifikasi dari Alice!');
        console.log('=========================================\n');
        printSummaryTable([
            ['Plaintext Awal', plaintext],
            ['Symmetric Key (hex)', maskHexKey(aesKey.toString('hex'))],
            ['Ciphertext (base64)', shortenValue(ciphertext)],
            ['Encrypted Sym Key', shortenValue(encrypted_key)],
            ['Hash (hex)', hash],
            ['Digital Signature', shortenValue(signature)],
            ['IP Pengirim -> Penerima', `${req.body.source_ip || '172.20.0.10'} -> ${req.body.destination_ip || '172.20.0.20'}`],
            ['Hasil Dekripsi Bob', plaintext],
            ['Verifikasi Hash', hashesMatch ? 'COCOK' : 'TIDAK COCOK'],
            ['Verifikasi Signature', signatureValid ? 'VALID' : 'INVALID']
        ]);
        res.json({ status: 'Payload diterima dan tervalidasi', plaintext });
    } catch (error) {
        console.error('[BOB] Gagal memproses payload:', error.message);
        res.status(500).json({ error: 'Terjadi kesalahan saat memproses payload terenkripsi' });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`[BOB] Server berjalan di IP 172.20.0.20 Port ${PORT}`);
});
