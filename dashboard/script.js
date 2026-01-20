// ==========================================
// SOC Dashboard - FINAL FIX (Permissions & Logic)
// ==========================================

const API_URL = '/api/stats'; 

const state = {
    currentView: 'monitoring',
    chartData: {
        normal: new Array(60).fill(0),
        attack: new Array(60).fill(0)
    },
    lastNetIO: 0,
    lastTimestamp: 0
};

document.addEventListener('DOMContentLoaded', () => {
    initializeNavigation();
    initializeTrafficChart();
    // Refresh nhanh (1s) để mượt mà
    setInterval(fetchRealTimeData, 1000);
});

function initializeNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const viewSections = document.querySelectorAll('.view-section');
    navButtons.forEach(button => {
        button.addEventListener('click', () => {
            const viewName = button.dataset.view;
            navButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');
            viewSections.forEach(section => section.classList.remove('active'));
            document.getElementById(`${viewName}-view`).classList.add('active');
        });
    });
}

// --- LOGIC KẾT NỐI API ---
async function fetchRealTimeData() {
    try {
        // Thêm timestamp để chống cache trình duyệt
        const response = await fetch(API_URL + '?t=' + Date.now());
        const data = await response.json();
        
        updateDashboardUI(data);
    } catch (e) {
        console.error("API Connection Error:", e);
    }
}

function updateDashboardUI(data) {
    // 1. Cập nhật Số liệu
    document.querySelector('.stat-value-danger').textContent = data.total_threats || 0;
    document.querySelector('.stat-value-warning').textContent = data.unique_ips || 0;
    
    // 2. Tính toán Tốc độ mạng (Bytes/s)
    let currentNet = data.net_recv;
    let now = Date.now();
    let speedBytes = 0;

    if (state.lastNetIO > 0 && state.lastTimestamp > 0) {
        let deltaBytes = currentNet - state.lastNetIO;
        let deltaTime = (now - state.lastTimestamp) / 1000;
        if (deltaTime > 0) speedBytes = deltaBytes / deltaTime;
    }
    if (speedBytes < 0) speedBytes = 0; // Fix lỗi reset counter

    state.lastNetIO = currentNet;
    state.lastTimestamp = now;

    // Hiển thị text tốc độ
    const speedElem = document.getElementById('current-speed');
    if(speedElem) {
        speedElem.textContent = formatSpeed(speedBytes);
        // Đổi màu text nếu đang bị tấn công
        if (data.is_under_attack) speedElem.classList.add('speed-high');
        else speedElem.classList.remove('speed-high');
    }

    // 3. Logic Biểu đồ (SỬA LỖI MÀU ĐỎ)
    let speedKB = speedBytes / 1024;
    state.chartData.normal.shift();
    state.chartData.normal.push(speedKB);

    state.chartData.attack.shift();
    // [FIX] Chỉ vẽ đường màu đỏ khi Server báo 'is_under_attack = true'
    // (tức là có log tấn công mới trong 30s qua)
    let attackVal = data.is_under_attack ? speedKB : 0;
    state.chartData.attack.push(attackVal);

    // 4. Cập nhật Alerts (SỬA LỖI KHÔNG CẬP NHẬT)
    updateAlertsPanel(data.alerts);
    
    // 5. Update Gauges
    updateGauge(0, data.cpu || 0);
    updateGauge(1, data.ram || 0);
}

function updateAlertsPanel(alerts) {
    const container = document.querySelector('.alerts-list');
    if (!container) return;

    // [FIX] Nếu danh sách rỗng, XÓA cảnh báo cũ và hiện thông báo an toàn
    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div style="text-align:center; padding:20px; color:#666">✅ Hệ thống an toàn. Không có cảnh báo.</div>';
        return;
    }

    let html = '';
    alerts.forEach(alert => {
        // [FIX] Đổi màu badge dựa trên loại cảnh báo (Attack = Đỏ, Suspicious = Vàng)
        let badgeClass = 'alert-high'; // Mặc định Vàng
        let priority = 'P2';
        
        if (alert.score === 'Attack') {
            badgeClass = 'alert-critical'; // Đỏ
            priority = 'P1';
        }

        html += `
        <div class="alert-card ${badgeClass}">
            <div class="alert-header">
                <span class="alert-priority">${priority}</span>
                <span class="alert-type">${alert.type}</span>
                <span class="alert-time">${alert.time}</span>
            </div>
            <div class="alert-title">Phát hiện từ ${alert.src_ip}</div>
            <div class="alert-details">
                <div class="detail-row"><span class="detail-label">Nguồn:</span> <span class="detail-value monospace">${alert.src_ip}</span></div>
                <div class="detail-row"><span class="detail-label">Đích:</span> <span class="detail-value monospace">${alert.dst_ip}</span></div>
                <div class="detail-row"><span class="detail-label">Mức độ:</span> <span class="detail-value">${alert.score}</span></div>
            </div>
            <div class="alert-actions">
                <button class="btn btn-danger btn-sm" onclick="blockIP('${alert.src_ip}')">Block IP</button>
            </div>
        </div>`;
    });
    container.innerHTML = html;
}

function formatSpeed(bytes) {
    if (bytes === 0) return '0 KB/s';
    const k = 1024;
    const sizes = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function blockIP(ip) {
    if(!confirm(`Xác nhận chặn IP: ${ip}?`)) return;
    fetch('/api/block_ip', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip: ip})
    }).then(r => r.json()).then(d => {
        if(d.status==='success') alert('Đã gửi lệnh chặn!');
        else alert('Lỗi: ' + d.message);
    });
}

// --- CHART RENDERING (Auto Scale) ---
function initializeTrafficChart() {
    const canvas = document.getElementById('trafficCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    function resize() {
        canvas.width = canvas.parentElement.offsetWidth;
        canvas.height = canvas.parentElement.offsetHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    function loop() {
        drawChart(ctx, canvas.width, canvas.height);
        requestAnimationFrame(loop);
    }
    loop();
}

function drawChart(ctx, w, h) {
    ctx.clearRect(0, 0, w, h);
    
    // Auto Scale: Tìm giá trị lớn nhất trong dữ liệu hiện tại
    let maxVal = Math.max(...state.chartData.normal, ...state.chartData.attack, 10);
    maxVal = maxVal * 1.2; // Thêm khoảng trống ở trên

    // Grid
    ctx.strokeStyle = '#2A2A3C'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(0, h-1); ctx.lineTo(w, h-1); ctx.stroke();

    // Vẽ
    drawLine(ctx, state.chartData.normal, '#52C41A', w, h, maxVal, true);
    drawLine(ctx, state.chartData.attack, '#FF4D4F', w, h, maxVal, true);
}

function drawLine(ctx, data, color, w, h, maxVal, fill) {
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
    const step = w / (data.length - 1);
    
    data.forEach((val, i) => {
        let x = step * i;
        let y = h - (val / maxVal * h);
        if (y < 0) y = 0; if (y > h) y = h;
        if (i===0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();
    
    if(fill) {
        ctx.lineTo(w, h); ctx.lineTo(0, h);
        ctx.fillStyle = color + "33"; 
        ctx.fill();
    }
}

// Giữ nguyên logic Gauge cũ
function updateGauge(index, value) {
    const gauges = document.querySelectorAll('.gauge-value');
    const fills = document.querySelectorAll('.gauge-fill');
    if (gauges[index] && fills[index]) {
        gauges[index].textContent = Math.round(value) + '%';
        const offset = 251.2 * (1 - value / 100);
        fills[index].setAttribute('stroke-dashoffset', offset);
        fills[index].setAttribute('stroke', value > 80 ? '#FF4D4F' : (value > 50 ? '#FAAD14' : '#52C41A'));
    }
}