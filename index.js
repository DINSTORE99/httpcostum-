const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const upload = multer({ storage: multer.memoryStorage() });
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Salin fungsi helper HC Decryptor & Generator di sini jika diperlukan

app.get('/api/operators', (req, res) => {
  try {
    const bugDir = path.join(__dirname, 'bug');
    if (!fs.existsSync(bugDir)) return res.json({ success: true, operators: [] });
    const files = fs.readdirSync(bugDir);
    const operators = files.map(file => path.basename(file, '.json'));
    res.json({ success: true, operators });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/generate', (req, res) => {
  try {
    const { operator, credential } = req.body;
    if (!operator || !credential) return res.status(400).json({ success: false, error: "Operator dan kredensial wajib diisi!" });

    const bugFilePath = path.join(__dirname, 'bug', `${operator.toLowerCase()}.json`);
    if (!fs.existsSync(bugFilePath)) {
      return res.status(404).json({ success: false, error: `File bug untuk operator ${operator} tidak ditemukan!` });
    }

    const bugData = JSON.parse(fs.readFileSync(bugFilePath, 'utf8'));
    const regex = /^([\w.-]+):(\d+)@([^:]+):(.+)$/;
    const match = credential.trim().match(regex);
    if (!match) return res.status(400).json({ success: false, error: "Format kredensial salah! Gunakan: host:port@username:password" });

    const [, host, port, username, password] = match;
    const configTemplate = new Array(32).fill("");
    
    configTemplate[0] = bugData.payload;
    configTemplate[1] = `${host}:${port}`;
    configTemplate[6] = `Config ${bugData.operator.toUpperCase()} by Web Tools`;
    configTemplate[7] = `${username}:${password}@${host}:${port}`;
    configTemplate[12] = bugData.bug;
    configTemplate[27] = "3.0";

    const rawConfigString = configTemplate.join("[splitConfig]");
    res.json({ success: true, rawConfig: rawConfigString });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

module.exports = app;

