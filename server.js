const express = require('express');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const CREDENTIALS_FILE_PATH = path.join(__dirname, 'credentials.json');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

async function readCredentials() {
    try {
        await fs.access(CREDENTIALS_FILE_PATH);
        const data = await fs.readFile(CREDENTIALS_FILE_PATH, 'utf-8');
        return JSON.parse(data);
    } catch (error) {
        if (error.code === 'ENOENT') {
            return [];
        }
        console.error("Error reading credentials file, returning empty array:", error);
        return [];
    }
}

async function writeCredentials(credentials) {
    try {
        await fs.writeFile(CREDENTIALS_FILE_PATH, JSON.stringify(credentials, null, 2), 'utf-8');
    } catch (error) {
        console.error("Error writing credentials file:", error);
        throw error;
    }
}


app.get('/api/credentials', async (req, res) => {
    try {
        const credentials = await readCredentials();
        res.json(credentials);
    } catch (error) {
        res.status(500).json({ error: 'Failed to retrieve credentials', details: error.message });
    }
});

app.post('/api/credentials', async (req, res) => {
    const newCredentials = req.body;

    if (!Array.isArray(newCredentials)) {
        return res.status(400).json({ error: 'Invalid data format: Expected an array of credentials.' });
    }

    try {
        await writeCredentials(newCredentials);
        res.status(200).json({ message: 'Credentials saved successfully.' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save credentials', details: error.message });
    }
});


app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    console.log(`Credentials will be stored in: ${CREDENTIALS_FILE_PATH}`);
    readCredentials().then(creds => {
        if (creds.length === 0) {
             fs.access(CREDENTIALS_FILE_PATH)
                .catch(() => writeCredentials([]))
                .then(() => console.log('Initialized empty credentials.json as it did not exist.'))
                .catch(err => console.error('Error initializing credentials.json:', err));
        }
    });
});