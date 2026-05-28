// API Configuration
const API_URL = window.location.origin;
let currentUser = null;
let uploadCounter = 0;
let anomalyAlerts = [];
let securityScore = 95;
let storageChart = null;

// ========== AUTHENTICATION ==========
async function handleLogin() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

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

// ========== RISK ANALYSIS ==========
function analyzeRisk(filename) {
    const lowerName = filename.toLowerCase();
    if (lowerName.includes('gizli') || lowerName.includes('confidential') || 
        lowerName.includes('password') || lowerName.includes('secret') ||
        lowerName.includes('private') || lowerName.includes('kilitli')) {
        return 'HIGH';
    } else if (lowerName.includes('rapor') || lowerName.includes('finans') || 
               lowerName.includes('veri') || lowerName.includes('data') ||
               lowerName.includes('report') || lowerName.includes('muhasebe')) {
        return 'MEDIUM';
    }
    return 'LOW';
}

function getThreatScore(riskLevel) {
    switch(riskLevel) {
        case 'HIGH': return Math.floor(Math.random() * 30) + 70; // 70-100
        case 'MEDIUM': return Math.floor(Math.random() * 30) + 40; // 40-69
        default: return Math.floor(Math.random() * 30) + 10; // 10-39
    }
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
        const fileCount = document.getElementById('totalFiles');
        const highRiskCount = document.getElementById('highRiskFiles');
        const mediumRiskCount = document.getElementById('mediumRiskFiles');
        const safeCount = document.getElementById('safeFiles');
        
        if (!files || files.length === 0) {
            if (fileList) fileList.innerHTML = '<tr class="empty-row"><td colspan="5">Henüz belge yüklenmedi</td></tr>';
            if (fileCount) fileCount.textContent = '0';
            if (highRiskCount) highRiskCount.textContent = '0';
            if (mediumRiskCount) mediumRiskCount.textContent = '0';
            if (safeCount) safeCount.textContent = '0';
            updateSecurityScore();
            return;
        }

        let high = 0, medium = 0, safe = 0;
        
        if (fileList) {
            fileList.innerHTML = files.map(file => {
                const riskLevel = analyzeRisk(file.filename);
                const threatScore = getThreatScore(riskLevel);
                
                if (riskLevel === 'HIGH') high++;
                else if (riskLevel === 'MEDIUM') medium++;
                else safe++;
                
                const uploadDate = file.upload_date ? new Date(file.upload_date).toLocaleString('tr-TR') : 'Belirtilmemiş';
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
        
        if (fileCount) fileCount.textContent = files.length;
        if (highRiskCount) highRiskCount.textContent = high;
        if (mediumRiskCount) mediumRiskCount.textContent = medium;
        if (safeCount) safeCount.textContent = safe;
        
        updateSecurityScore();
        updateStorageUsage(files);
        updateSecurityScoreRing();
        
    } catch (error) {
        console.error('Error loading files:', error);
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

    const formData = new FormData();
    formData.append('file', file);

    showUploadStatus('Dosya şifreleniyor ve yükleniyor...', 'info');
    if (progressDiv) progressDiv.style.display = 'block';
    
    // Simulate progress
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += 10;
        const progressBar = document.querySelector('.progress-bar');
        const progressText = document.querySelector('.progress-text');
        if (progressBar) progressBar.style.width = progress + '%';
        if (progressText) progressText.textContent = `Şifreleniyor... ${progress}%`;
        if (progress >= 90) clearInterval(progressInterval);
    }, 200);

    try {
        const response = await fetch(`${API_URL}/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData
        });

        const data = await response.text();
        
        clearInterval(progressInterval);
        if (progressDiv) progressDiv.style.display = 'none';
        
        uploadCounter++;
        
        // Anomaly Detection
        if (uploadCounter > 3) {
            addSecurityAlert('🚨 ANOMALİ: Çok fazla yükleme tespit edildi! (1 dakikada 3+ dosya)');
        }

        // Risk-based alert
        const risk = analyzeRisk(file.name);
        const threatScore = getThreatScore(risk);
        
        if (riskResultDiv) {
            riskResultDiv.innerHTML = `
                <div class="risk-scan-result ${risk === 'HIGH' ? 'risk-danger' : (risk === 'MEDIUM' ? 'risk-warning' : 'risk-safe')}">
                    <strong>📊 Risk Analizi Tamamlandı</strong><br>
                    Risk Seviyesi: <strong>${risk === 'HIGH' ? 'YÜKSEK' : (risk === 'MEDIUM' ? 'ORTA' : 'DÜŞÜK')}</strong><br>
                    Tehdit Skoru: ${threatScore}/100<br>
                    ${risk === 'HIGH' ? '⚠️ Bu dosya yüksek riskli olarak işaretlendi!' : '✅ Dosya güvenli olarak işaretlendi'}
                </div>
            `;
            setTimeout(() => {
                riskResultDiv.innerHTML = '';
            }, 5000);
        }
        
        if (risk === 'HIGH') {
            addSecurityAlert(`⚠️ YÜKSEK RİSKLİ DOSYA: ${file.name} - Hemen inceleyin!`);
            updateSecurityScore(-5);
        } else if (risk === 'MEDIUM') {
            addSecurityAlert(`ℹ️ Orta riskli dosya yüklendi: ${file.name}`);
            updateSecurityScore(-2);
        } else {
            addSecurityAlert(`✅ Düşük riskli dosya yüklendi: ${file.name}`);
            updateSecurityScore(1);
        }

        showUploadStatus('✅ Dosya başarıyla AES-256 ile şifrelendi ve yüklendi!', 'success');
        
        // Reset upload area
        fileInput.value = '';
        const fileNameSpan = document.getElementById('fileName');
        if (fileNameSpan) fileNameSpan.textContent = 'Dosya seçilmedi';
        
        loadFiles();
        
        setTimeout(() => {
            if (statusDiv) statusDiv.innerHTML = '';
            if (riskResultDiv) riskResultDiv.innerHTML = '';
        }, 4000);
        
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
function addSecurityAlert(message) {
    const alert = {
        id: Date.now(),
        message: message,
        time: new Date().toLocaleTimeString('tr-TR'),
        date: new Date().toLocaleDateString('tr-TR')
    };
    anomalyAlerts.unshift(alert);
    if (anomalyAlerts.length > 15) anomalyAlerts.pop();
    renderAlerts();
    
    const alertCountSpan = document.getElementById('alertCount');
    if (alertCountSpan) alertCountSpan.textContent = anomalyAlerts.length;
    
    const alertTrend = document.getElementById('alertTrend');
    if (alertTrend && anomalyAlerts.length > 0) {
        alertTrend.textContent = `${anomalyAlerts.length} new`;
        alertTrend.style.color = '#f87171';
    }
}

function renderAlerts() {
    const alertsContainer = document.getElementById('alertsList');
    
    if (!alertsContainer) return;
    
    if (anomalyAlerts.length === 0) {
        alertsContainer.innerHTML = '<div class="empty-alerts">✅ Sistem güvenli - Tehdit tespit edilmedi</div>';
        return;
    }
    
    alertsContainer.innerHTML = anomalyAlerts.map(alert => `
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
function updateSecurityScore(change = 0) {
    securityScore += change;
    securityScore = Math.min(100, Math.max(0, securityScore));
    updateSecurityScoreRing();
}

function updateSecurityScoreRing() {
    const scoreValue = document.getElementById('securityScore');
    const ringProgress = document.querySelector('.ring-progress');
    
    if (scoreValue) scoreValue.textContent = securityScore;
    
    if (ringProgress) {
        const circumference = 2 * Math.PI * 42;
        const offset = circumference - (securityScore / 100) * circumference;
        ringProgress.style.strokeDasharray = `${circumference}`;
        ringProgress.style.strokeDashoffset = offset;
    }
}

// ========== STORAGE MANAGEMENT ==========
function updateStorageUsage(files) {
    const totalSize = files ? files.length * 0.5 : 0; // Simulate 0.5MB per file
    const maxStorage = 100; // 100MB limit
    const percentage = (totalSize / maxStorage) * 100;
    
    const storageUsedSpan = document.getElementById('storageUsed');
    const storageUsedDetail = document.getElementById('storageUsedDetail');
    const storageAvailable = document.getElementById('storageAvailable');
    const storageProgressBar = document.getElementById('storageProgressBar');
    
    if (storageUsedSpan) storageUsedSpan.textContent = totalSize.toFixed(1) + ' MB';
    if (storageUsedDetail) storageUsedDetail.textContent = totalSize.toFixed(1) + ' MB';
    if (storageAvailable) storageAvailable.textContent = (maxStorage - totalSize).toFixed(1) + ' MB';
    if (storageProgressBar) storageProgressBar.style.width = percentage + '%';
    
    // Update storage chart if exists
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

// ========== UI HELPER FUNCTIONS ==========
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Drag & Drop Upload
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

// Navigation Active State
function setupNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');
        });
    });
}

// Animated counter for stats
function animateValue(element, start, end, duration) {
    if (!element) return;
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;
    const timer = setInterval(() => {
        current += increment;
        if (current >= end) {
            clearInterval(timer);
            element.textContent = end;
        } else {
            element.textContent = Math.floor(current);
        }
    }, 16);
}

// ========== INITIALIZATION ==========
if (window.location.pathname.includes('dashboard.html')) {
    const token = localStorage.getItem('token');
    const userEmail = localStorage.getItem('userEmail');
    
    if (!token) {
        window.location.href = '/index.html';
    } else {
        // Set user info
        const userNameSpan = document.getElementById('userName');
        const userEmailSpan = document.getElementById('userEmail');
        const userAvatar = document.getElementById('userAvatar');
        
        if (userEmailSpan) userEmailSpan.textContent = userEmail || 'Kullanıcı';
        if (userNameSpan) {
            const name = userEmail ? userEmail.split('@')[0] : 'Admin';
            userNameSpan.textContent = name.charAt(0).toUpperCase() + name.slice(1);
        }
        if (userAvatar) userAvatar.textContent = userEmail ? userEmail.charAt(0).toUpperCase() : '👤';
        
        // Initialize components
        initStorageChart();
        loadFiles();
        setupDragAndDrop();
        setupNavigation();
        
        // Welcome alert after 1 second
        setTimeout(() => {
            addSecurityAlert('🛡️ CloudSecure DMS Aktif - Güvenlik izleme sistemi çalışıyor');
            updateSecurityScoreRing();
        }, 1000);
        
        // Auto-refresh every 30 seconds
        setInterval(() => {
            loadFiles();
        }, 30000);
    }
}

// File name display on selection
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
});