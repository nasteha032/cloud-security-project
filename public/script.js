// API Configuration
const API_URL = window.location.origin;
let uploadCounter = 0;
let anomalyAlerts = [];
let securityScore = 95;
let storageChart = null;

// ========== AUTHENTICATION ==========
async function handleLogin() {
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPassword').value;
    if (!email || !password) {
        showMessage('Lütfen e-posta ve şifre girin', 'error');
        return;
    }

    // Email validation
    if (!isValidEmail(email)) {
        showMessage('Geçerli bir e-posta adresi girin (ornek@domain.com)', 'error');
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
            showMessage(data.message || 'Giriş başarısız. E-posta veya şifre hatalı.', 'error');
        }
    } catch (error) {
        showMessage('Sunucuya bağlanılamadı', 'error');
    }
}

async function handleRegister() {
   const email = document.getElementById('regEmail').value;
   const password = document.getElementById('regPassword').value;

    if (!email || !password) {
        showMessage('Lütfen e-posta ve şifre girin', 'error');
        return;
    }

    // Email validation
    if (!isValidEmail(email)) {
        showMessage('Geçerli bir e-posta adresi girin (ornek@domain.com)', 'error');
        return;
    }

    // Password strength check
    if (!isPasswordStrong(password)) {
        showMessage('Şifre çok zayıf! En az 8 karakter, büyük/küçük harf ve rakam içermeli', 'error');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        
        if (data.message && data.message.includes('successfully')) {
            showMessage('Kayıt başarılı! Şimdi giriş yapabilirsiniz', 'success');
            document.getElementById('email').value = '';
            document.getElementById('password').value = '';
        } else {
            showMessage(data.message || 'Kayıt başarısız', 'error');
        }
    } catch (error) {
        showMessage('Sunucuya bağlanılamadı', 'error');
    }
}

function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isPasswordStrong(password) {
    if (password.length < 8) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[A-Z]/.test(password)) return false;
    if (!/[0-9]/.test(password)) return false;
    return true;
}

function showMessage(msg, type) {
    const messageDiv = document.getElementById('message');
    if (messageDiv) {
        messageDiv.textContent = msg;
        messageDiv.className = `message ${type}`;
        setTimeout(() => {
            messageDiv.textContent = '';
            messageDiv.className = 'message';
        }, 4000);
    }
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('userEmail');
    window.location.href = '/index.html';
}

// ========== FILE OPERATIONS ==========
async function loadFiles() {
    const token = localStorage.getItem('token');
    if (!token) return;

    try {
        const response = await fetch(`${API_URL}/files`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        const files = await response.json();
        const fileList = document.getElementById('fileList');
        const totalFilesSpan = document.getElementById('totalFiles');
        const highRiskSpan = document.getElementById('highRiskFiles');
        const mediumRiskSpan = document.getElementById('mediumRiskFiles');
        const safeFilesSpan = document.getElementById('safeFiles');
        
        if (!files || files.length === 0) {
            if (fileList) fileList.innerHTML = '<tr class="empty-row"><td colspan="5">Henüz belge yüklenmedi</td></tr>';
            if (totalFilesSpan) totalFilesSpan.textContent = '0';
            if (highRiskSpan) highRiskSpan.textContent = '0';
            if (mediumRiskSpan) mediumRiskSpan.textContent = '0';
            if (safeFilesSpan) safeFilesSpan.textContent = '0';
            updateStorageUsage(files);
            return;
        }

        let high = 0, medium = 0, safe = 0;
        
        if (fileList) {
            fileList.innerHTML = files.map(file => {
                const riskLevel = file.risk_level || analyzeRisk(file.filename);
                const threatScore = file.risk_score || getThreatScore(riskLevel);
                const riskReason = file.risk_reason || '';
                
                if (riskLevel === 'HIGH') high++;
                else if (riskLevel === 'MEDIUM') medium++;
                else safe++;
                
                const uploadDate = file.created_at ? new Date(file.created_at).toLocaleString('tr-TR') : 'Belirtilmemiş';
                const riskClass = riskLevel === 'HIGH' ? 'risk-high' : (riskLevel === 'MEDIUM' ? 'risk-medium' : 'risk-low');
                const riskText = riskLevel === 'HIGH' ? 'YÜKSEK' : (riskLevel === 'MEDIUM' ? 'ORTA' : 'DÜŞÜK');
                
                return `
                    <tr>
                        <td>${escapeHtml(file.filename)} <span class="encrypted-badge">🔒</span></td>
                        <td>${uploadDate}</td>
                        <td><span class="${riskClass}">${riskText}</span></td>
                        <td><span style="color:#22c55e;">AES-256</span></td>
                        <td><span class="threat-score">${threatScore}</span></td>
                    </tr>
                `;
            }).join('');
        }
        
        if (totalFilesSpan) totalFilesSpan.textContent = files.length;
        if (highRiskSpan) highRiskSpan.textContent = high;
        if (mediumRiskSpan) mediumRiskSpan.textContent = medium;
        if (safeFilesSpan) safeFilesSpan.textContent = safe;
        
        updateStorageUsage(files);
        updateSecurityScoreRing();
        
        // Update alert count based on high risk files
        const alertCountSpan = document.getElementById('alertCount');
        if (alertCountSpan) alertCountSpan.textContent = high;
        
    } catch (error) {
        console.error('Error loading files:', error);
    }
}

function analyzeRisk(filename) {
    const lowerName = filename.toLowerCase();
    if (lowerName.includes('.exe') || lowerName.includes('.bat') || lowerName.includes('malware')) {
        return 'HIGH';
    } else if (lowerName.includes('.zip') || lowerName.includes('.rar')) {
        return 'MEDIUM';
    }
    return 'LOW';
}

function getThreatScore(riskLevel) {
    switch(riskLevel) {
        case 'HIGH': return Math.floor(Math.random() * 30) + 70;
        case 'MEDIUM': return Math.floor(Math.random() * 30) + 40;
        default: return Math.floor(Math.random() * 30) + 10;
    }
}

async function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    const token = localStorage.getItem('token');
    const statusDiv = document.getElementById('uploadStatus');
    const progressDiv = document.getElementById('uploadProgress');
    const riskResultDiv = document.getElementById('riskResult');

    if (!file) {
        showUploadStatus('Lütfen bir dosya seçin', 'error');
        return;
    }

    if (!token) {
        showUploadStatus('Oturum bulunamadı. Lütfen tekrar giriş yapın.', 'error');
        window.location.href = '/index.html';
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    showUploadStatus('🔐 Dosya şifreleniyor, AI analizi yapılıyor ve buluta yükleniyor...', 'info');

    if (progressDiv) progressDiv.style.display = 'block';

    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += 10;
        const progressBar = document.querySelector('.progress-bar');
        const progressText = document.querySelector('.progress-text');
        if (progressBar) progressBar.style.width = Math.min(progress, 90) + '%';
        if (progressText) progressText.textContent = `Analiz ediliyor... ${Math.min(progress, 90)}%`;
        if (progress >= 90) clearInterval(progressInterval);
    }, 200);

    try {
        const response = await fetch(`${API_URL}/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`
            },
            body: formData
        });

        const data = await response.json();

        clearInterval(progressInterval);

        if (progressDiv) {
            const progressBar = document.querySelector('.progress-bar');
            const progressText = document.querySelector('.progress-text');
            if (progressBar) progressBar.style.width = '100%';
            if (progressText) progressText.textContent = 'Tamamlandı 100%';
            setTimeout(() => {
                progressDiv.style.display = 'none';
            }, 800);
        }

        if (!response.ok || data.message?.includes('❌')) {
            showUploadStatus(data.message || 'Yükleme sırasında hata oluştu', 'error');
            return;
        }

        const risk = data.risk_level || 'LOW';
        const threatScore = data.risk_score || 20;
        const reason = data.risk_reason || 'Risk nedeni belirtilmedi';

        let riskText = 'DÜŞÜK';
        let riskClass = 'risk-safe';
        let riskIcon = '✅';

        if (risk === 'HIGH') {
            riskText = 'YÜKSEK';
            riskClass = 'risk-danger';
            riskIcon = '🚨';
        } else if (risk === 'MEDIUM') {
            riskText = 'ORTA';
            riskClass = 'risk-warning';
            riskIcon = '⚠️';
        }

        if (riskResultDiv) {
            riskResultDiv.innerHTML = `
                <div class="risk-scan-result ${riskClass}">
                    <strong>🤖 AI Güvenlik Analizi Tamamlandı</strong><br><br>
                    📄 Dosya: <strong>${escapeHtml(data.filename || file.name)}</strong><br>
                    ${riskIcon} Risk Seviyesi: <strong>${riskText}</strong><br>
                    📊 Tehdit Skoru: <strong>${threatScore}/100</strong><br>
                    🧠 Analiz Nedeni: ${escapeHtml(reason)}<br>
                    🔐 Şifreleme: AES-256<br>
                    ☁️ Durum: Supabase Cloud Storage içine kaydedildi ✅
                </div>
            `;
        }

        if (risk === 'HIGH') {
            addSecurityAlert(`🚨 YÜKSEK RİSK: ${file.name} - ${reason}`);
            updateSecurityScore(-5);
        } else if (risk === 'MEDIUM') {
            addSecurityAlert(`⚠️ ORTA RİSK: ${file.name} - ${reason}`);
            updateSecurityScore(-2);
        } else {
            addSecurityAlert(`✅ DÜŞÜK RİSK: ${file.name} güvenli görünüyor`);
            updateSecurityScore(1);
        }

        showUploadStatus('✅ Dosya AI tarafından analiz edildi, şifrelendi ve buluta kaydedildi!', 'success');

        fileInput.value = '';
        const fileNameSpan = document.getElementById('fileName');
        if (fileNameSpan) fileNameSpan.textContent = 'Dosya seçilmedi';

        loadFiles();

        setTimeout(() => {
            if (statusDiv) statusDiv.innerHTML = '';
            if (riskResultDiv) riskResultDiv.innerHTML = '';
        }, 5000);

    } catch (error) {
        clearInterval(progressInterval);
        if (progressDiv) progressDiv.style.display = 'none';
        showUploadStatus('❌ Yükleme hatası: ' + error.message, 'error');
    }
}

function showUploadStatus(msg, type) {
    const statusDiv = document.getElementById('uploadStatus');
    if (statusDiv) {
        statusDiv.textContent = msg;
        statusDiv.className = `upload-status ${type}`;
    }
}

// ========== SECURITY ALERTS ==========
let anomalyAlertsList = [];

function addSecurityAlert(message) {
    const alert = {
        id: Date.now(),
        message: message,
        time: new Date().toLocaleTimeString('tr-TR'),
        date: new Date().toLocaleDateString('tr-TR')
    };
    anomalyAlertsList.unshift(alert);
    if (anomalyAlertsList.length > 15) anomalyAlertsList.pop();
    renderAlerts();
    
    const alertCountSpan = document.getElementById('alertCount');
    if (alertCountSpan) alertCountSpan.textContent = anomalyAlertsList.length;
}

function renderAlerts() {
    const alertsContainer = document.getElementById('alertsList');
    if (!alertsContainer) return;
    
    if (anomalyAlertsList.length === 0) {
        alertsContainer.innerHTML = '<div class="empty-alerts">✅ Sistem güvenli - Tehdit tespit edilmedi</div>';
        return;
    }
    
    alertsContainer.innerHTML = anomalyAlertsList.map(alert => `
        <div class="alert-item">
            <div class="alert-icon">🚨</div>
            <div class="alert-content">
                <div class="alert-message">${escapeHtml(alert.message)}</div>
                <div class="alert-time">${alert.time} - ${alert.date}</div>
            </div>
        </div>
    `).join('');
}

// ========== SECURITY SCORE ==========
let currentScore = 95;

function updateSecurityScore(change = 0) {
    currentScore += change;
    currentScore = Math.min(100, Math.max(0, currentScore));
    updateSecurityScoreRing();
}

function updateSecurityScoreRing() {
    const scoreValue = document.getElementById('securityScore');
    const ringProgress = document.querySelector('.ring-progress');
    
    if (scoreValue) scoreValue.textContent = currentScore;
    
    if (ringProgress) {
        const circumference = 2 * Math.PI * 42;
        const offset = circumference - (currentScore / 100) * circumference;
        ringProgress.style.strokeDasharray = `${circumference}`;
        ringProgress.style.strokeDashoffset = offset;
    }
}

// ========== STORAGE MANAGEMENT ==========
function updateStorageUsage(files) {
    const totalSize = files ? files.length * 0.5 : 0;
    const maxStorage = 100;
    const percentage = (totalSize / maxStorage) * 100;
    
    const storageUsedSpan = document.getElementById('storageUsed');
    const storageUsedDetail = document.getElementById('storageUsedDetail');
    const storageAvailable = document.getElementById('storageAvailable');
    const storageProgressBar = document.getElementById('storageProgressBar');
    
    if (storageUsedSpan) storageUsedSpan.textContent = totalSize.toFixed(1) + ' MB';
    if (storageUsedDetail) storageUsedDetail.textContent = totalSize.toFixed(1) + ' MB';
    if (storageAvailable) storageAvailable.textContent = (maxStorage - totalSize).toFixed(1) + ' MB';
    if (storageProgressBar) storageProgressBar.style.width = percentage + '%';
    
    if (storageChart) {
        storageChart.data.datasets[0].data = [totalSize, maxStorage - totalSize];
        storageChart.update();
    }
}

function initStorageChart() {
    const ctx = document.getElementById('storageChart');
    if (!ctx) return;
    
    storageChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: ['#a855f7', 'rgba(168, 85, 247, 0.2)'],
                borderWidth: 0,
                cutout: '70%'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: { legend: { display: false } }
        }
    });
}

// ========== NAVIGATION ==========
function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const statsGrid = document.querySelector('.stats-grid');
    const uploadCard = document.querySelector('.upload-card');
    const filesCard = document.querySelector('.files-card');
    const alertsCard = document.querySelector('.alerts-card');
    const storageCard = document.querySelector('.storage-card');
    
    const oldSettings = document.getElementById('settingsPanel');
    if (oldSettings) oldSettings.remove();
    
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');
            
            const page = item.getAttribute('data-page');
            
            if (statsGrid) statsGrid.style.display = 'none';
            if (uploadCard) uploadCard.style.display = 'none';
            if (filesCard) filesCard.style.display = 'none';
            if (alertsCard) alertsCard.style.display = 'none';
            if (storageCard) storageCard.style.display = 'none';
            
            const existingSettings = document.getElementById('settingsPanel');
            if (existingSettings) existingSettings.style.display = 'none';
            
            switch(page) {
                case 'dashboard':
                    if (statsGrid) statsGrid.style.display = 'grid';
                    if (uploadCard) uploadCard.style.display = 'block';
                    if (filesCard) filesCard.style.display = 'block';
                    if (alertsCard) alertsCard.style.display = 'block';
                    if (storageCard) storageCard.style.display = 'block';
                    break;
                case 'files':
                    if (filesCard) filesCard.style.display = 'block';
                    filesCard?.scrollIntoView({ behavior: 'smooth' });
                    break;
                case 'risk':
                    if (filesCard) filesCard.style.display = 'block';
                    filesCard?.scrollIntoView({ behavior: 'smooth' });
                    break;
                case 'threats':
                    if (alertsCard) alertsCard.style.display = 'block';
                    alertsCard?.scrollIntoView({ behavior: 'smooth' });
                    break;
                case 'encryption':
                    if (uploadCard) uploadCard.style.display = 'block';
                    uploadCard?.scrollIntoView({ behavior: 'smooth' });
                    break;
                case 'settings':
                    showSettingsPanel();
                    break;
                default:
                    if (statsGrid) statsGrid.style.display = 'grid';
                    if (uploadCard) uploadCard.style.display = 'block';
                    if (filesCard) filesCard.style.display = 'block';
                    if (alertsCard) alertsCard.style.display = 'block';
                    if (storageCard) storageCard.style.display = 'block';
            }
        });
    });
}

function showSettingsPanel() {
    let settingsPanel = document.getElementById('settingsPanel');
    
    if (!settingsPanel) {
        settingsPanel = document.createElement('div');
        settingsPanel.id = 'settingsPanel';
        settingsPanel.className = 'glass-card';
        settingsPanel.innerHTML = `
            <div class="card-header">
                <h3>⚙️ Ayarlar</h3>
                <span class="badge-live">Admin</span>
            </div>
            <div style="padding: 24px;">
                <div style="margin-bottom: 24px;">
                    <h4 style="margin-bottom: 12px; color: #a855f7;">Hesap Güvenliği</h4>
                    <div style="background: rgba(255,255,255,0.05); padding: 16px; border-radius: 12px; margin-bottom: 12px;">
                        <p style="margin-bottom: 8px;">🔐 İki Faktörlü Kimlik Doğrulama (2FA)</p>
                        <button class="btn-upload" style="padding: 8px 16px; font-size: 12px;" onclick="alert('2FA feature coming soon')">Etkinleştir</button>
                    </div>
                    <div style="background: rgba(255,255,255,0.05); padding: 16px; border-radius: 12px;">
                        <p style="margin-bottom: 8px;">🔑 Şifre Değiştir</p>
                        <button class="btn-upload" style="padding: 8px 16px; font-size: 12px;" onclick="alert('Password change feature coming soon')">Güncelle</button>
                    </div>
                </div>
                <div>
                    <h4 style="margin-bottom: 12px; color: #a855f7;">Şifreleme Ayarları</h4>
                    <div style="background: rgba(255,255,255,0.05); padding: 16px; border-radius: 12px;">
                        <p style="margin-bottom: 8px;">🔒 Aktif Şifreleme: <strong>AES-256-CBC</strong></p>
                        <p style="font-size: 12px; color: #9ca3af;">Tüm dosyalar AES-256 standardı ile şifrelenmektedir.</p>
                    </div>
                </div>
                <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid rgba(255,255,255,0.1);">
                    <button onclick="logout()" class="logout-btn" style="width: auto; padding: 10px 24px;">Çıkış Yap</button>
                </div>
            </div>
        `;
        
        const alertsCard = document.querySelector('.alerts-card');
        if (alertsCard && alertsCard.parentNode) {
            alertsCard.parentNode.insertBefore(settingsPanel, alertsCard.nextSibling);
        }
    }
    
    settingsPanel.style.display = 'block';
    settingsPanel.scrollIntoView({ behavior: 'smooth' });
}

// ========== DRAG & DROP ==========
function setupDragAndDrop() {
    const uploadArea = document.getElementById('uploadArea');
    if (!uploadArea) return;
    
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('drag-over');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('drag-over');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) {
            const fileInput = document.getElementById('fileInput');
            if (fileInput) {
                const dataTransfer = new DataTransfer();
                dataTransfer.items.add(file);
                fileInput.files = dataTransfer.files;
                const fileNameSpan = document.getElementById('fileName');
                if (fileNameSpan) fileNameSpan.textContent = file.name;
            }
        }
    });
}

// ========== HELPER FUNCTIONS ==========
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ========== FILE NAME DISPLAY ==========
document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('fileInput');
    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            const fileNameSpan = document.getElementById('fileName');
            if (e.target.files[0]) {
                fileNameSpan.textContent = e.target.files[0].name;
            } else {
                fileNameSpan.textContent = 'Dosya seçilmedi';
            }
        });
    }
    
    // Real-time email validation on login page
    const emailInput = document.getElementById('email');
    if (emailInput) {
        emailInput.addEventListener('input', (e) => {
            const email = e.target.value;
            if (email && !isValidEmail(email)) {
                emailInput.style.borderColor = '#ef4444';
            } else {
                emailInput.style.borderColor = 'rgba(168, 85, 247, 0.3)';
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
        const userNameSpan = document.getElementById('userName');
        const userEmailSpan = document.getElementById('userEmail');
        const userAvatar = document.getElementById('userAvatar');
        
        if (userEmailSpan) userEmailSpan.textContent = userEmail || 'Kullanıcı';
        if (userNameSpan) {
            const name = userEmail ? userEmail.split('@')[0] : 'Admin';
            userNameSpan.textContent = name.charAt(0).toUpperCase() + name.slice(1);
        }
        if (userAvatar) userAvatar.textContent = userEmail ? userEmail.charAt(0).toUpperCase() : '👤';
        
        initStorageChart();
        loadFiles();
        setupDragAndDrop();
        setupNavigation();
        
        setTimeout(() => {
            addSecurityAlert('🛡️ CloudSecure DMS Aktif - Güvenlik izleme sistemi çalışıyor');
            updateSecurityScoreRing();
        }, 1000);
        
        setInterval(() => {
            loadFiles();
        }, 30000);
    }
}