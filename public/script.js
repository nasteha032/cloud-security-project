// API Configuration
const API_URL = 'http://localhost:5000';
let currentUser = null;

// ========== AUTHENTICATION ==========
async function handleLogin() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const messageDiv = document.getElementById('message');

    if (!email || !password) {
        showMessage('Lütfen e-posta ve şifre girin', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (data.token) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('userEmail', email);
            showMessage('Giriş başarılı! Yönlendiriliyorsunuz...', 'success');
            setTimeout(() => {
                window.location.href = '/dashboard.html';
            }, 1000);
        } else {
            showMessage(data.message || 'Giriş başarısız', 'error');
        }
    } catch (error) {
        showMessage('Sunucuya bağlanılamadı', 'error');
    }
}

async function handleRegister() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const messageDiv = document.getElementById('message');

    if (!email || !password) {
        showMessage('Lütfen e-posta ve şifre girin', 'error');
        return;
    }

    if (password.length < 3) {
        showMessage('Şifre en az 3 karakter olmalıdır', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.text();
        
        if (data.includes('successfully')) {
            showMessage('Kayıt başarılı! Şimdi giriş yapabilirsiniz', 'success');
            document.getElementById('email').value = '';
            document.getElementById('password').value = '';
        } else {
            showMessage(data, 'error');
        }
    } catch (error) {
        showMessage('Sunucuya bağlanılamadı', 'error');
    }
}

function showMessage(msg, type) {
    const messageDiv = document.getElementById('message');
    if (messageDiv) {
        messageDiv.textContent = msg;
        messageDiv.className = `message ${type}`;
        setTimeout(() => {
            messageDiv.textContent = '';
            messageDiv.className = 'message';
        }, 3000);
    }
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('userEmail');
    window.location.href = '/index.html';
}

// ========== DASHBOARD FUNCTIONS ==========
let uploadCounter = 0;
let anomalyAlerts = [];

async function loadFiles() {
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/files`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const files = await response.json();
        const fileList = document.getElementById('fileList');
        
        if (!files || files.length === 0) {
            fileList.innerHTML = '<tr class="empty-row"><td colspan="4">Henüz belge yüklenmedi</td></tr>';
            document.getElementById('fileCount').textContent = '0';
            return;
        }

        document.getElementById('fileCount').textContent = files.length;
        
        fileList.innerHTML = files.map(file => {
            const riskLevel = analyzeRisk(file.filename);
            return `
                <tr>
                    <td>${escapeHtml(file.filename)} <span class="encrypted-badge">🔒</span></td>
                    <td>${new Date(file.upload_date).toLocaleString('tr-TR')}</td>
                    <td><span class="risk-${riskLevel.toLowerCase()}">${riskLevel}</span></td>
                    <td><span style="color:#22c55e;">✓ Şifreli</span></td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading files:', error);
    }
}

function analyzeRisk(filename) {
    const lowerName = filename.toLowerCase();
    if (lowerName.includes('gizli') || lowerName.includes('confidential') || 
        lowerName.includes('password') || lowerName.includes('secret')) {
        return 'HIGH';
    } else if (lowerName.includes('rapor') || lowerName.includes('finans') || 
               lowerName.includes('veri')) {
        return 'MEDIUM';
    }
    return 'LOW';
}

async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    const token = localStorage.getItem('token');
    const statusDiv = document.getElementById('uploadStatus');

    if (!file) {
        showUploadStatus('Lütfen bir dosya seçin', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    showUploadStatus('Dosya şifreleniyor ve yükleniyor...', 'info');

    try {
        const response = await fetch(`${API_URL}/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData
        });

        const data = await response.text();
        
        uploadCounter++;
        
        // Anomaly Detection
        if (uploadCounter > 3) {
            addSecurityAlert('⚠️ Anomali: Çok fazla yükleme tespit edildi!');
        }

        // Risk-based alert
        const risk = analyzeRisk(file.name);
        if (risk === 'HIGH') {
            addSecurityAlert(`⚠️ Yüksek riskli dosya algılandı: ${file.name}`);
        }

        showUploadStatus('✅ Dosya başarıyla şifrelendi ve yüklendi!', 'success');
        fileInput.value = '';
        document.getElementById('fileName').textContent = 'Dosya seçilmedi';
        loadFiles();
        
        setTimeout(() => {
            statusDiv.innerHTML = '';
        }, 3000);
        
    } catch (error) {
        showUploadStatus('❌ Yükleme hatası: ' + error.message, 'error');
    }
}

function showUploadStatus(msg, type) {
    const statusDiv = document.getElementById('uploadStatus');
    statusDiv.textContent = msg;
    statusDiv.className = `upload-status ${type}`;
}

function addSecurityAlert(message) {
    const alert = {
        id: Date.now(),
        message: message,
        time: new Date().toLocaleTimeString('tr-TR')
    };
    anomalyAlerts.unshift(alert);
    if (anomalyAlerts.length > 10) anomalyAlerts.pop();
    renderAlerts();
    document.getElementById('alertCount').textContent = anomalyAlerts.length;
}

function renderAlerts() {
    const alertsContainer = document.getElementById('alertsList');
    
    if (anomalyAlerts.length === 0) {
        alertsContainer.innerHTML = '<div class="empty-alerts">✅ Sistem güvenli görünüyor</div>';
        return;
    }
    
    alertsContainer.innerHTML = anomalyAlerts.map(alert => `
        <div class="alert-item">
            <div class="alert-icon">⚠️</div>
            <div class="alert-content">
                <div class="alert-message">${escapeHtml(alert.message)}</div>
                <div class="alert-time">${alert.time}</div>
            </div>
        </div>
    `).join('');
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// File name display
document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            const fileName = document.getElementById('fileName');
            if (e.target.files[0]) {
                fileName.textContent = e.target.files[0].name;
            } else {
                fileName.textContent = 'Dosya seçilmedi';
            }
        });
    }
});

// ========== INITIALIZATION ==========
if (window.location.pathname.includes('dashboard.html')) {
    const token = localStorage.getItem('token');
    const userEmail = localStorage.getItem('userEmail');
    
    if (!token) {
        window.location.href = '/index.html';
    } else {
        document.getElementById('userEmail').textContent = userEmail || 'Kullanıcı';
        loadFiles();
        
        // Add demo alert for presentation
        setTimeout(() => {
            addSecurityAlert('🛡️ Güvenlik izleme sistemi aktif');
        }, 1000);
    }
}