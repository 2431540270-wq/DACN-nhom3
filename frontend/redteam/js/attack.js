let interval = null;

/**
 * Hiển thị log
 */
function addLog(text) {
    const box = document.getElementById("logBox");
    const time = new Date().toLocaleTimeString();

    const p = document.createElement("p");
    p.textContent = `[${time}] ${text}`;
    box.appendChild(p);

    // Giữ tối đa 50 dòng
    if (box.children.length > 50) {
        box.removeChild(box.firstChild);
    }

    box.scrollTop = box.scrollHeight;
}

/**
 * Attack 1 lần
 */
async function attackOnce(apiFunc, label) {
    try {
        await apiFunc();
        addLog(`Đã gửi ${label}`);
    } catch {
        addLog(`Đã bị block`);
    }
}

/**
 * Attack liên tục
 */
function attackLoop(apiFunc, label, delay) {
    if (interval) return;

    addLog(`🔥 Bắt đầu ${label}...`);

    interval = setInterval(async () => {
        try {
            await apiFunc();
            addLog(`⚡ Đã gửi ${label}`);
        } catch {
            clearInterval(interval);
            interval = null;
            addLog(`Đã bị block - dừng`);
        }
    }, delay);
}

/**
 * Dừng attack
 */
function stopAttack() {
    clearInterval(interval);
    interval = null;
    addLog("Đã dừng attack");
}

/**
 * Check block realtime
 */
async function checkNow() {
    const data = await checkBlock();
    if (data.blocked) {
        window.location.href = "403.html";
    }
}

// chạy ngay + lặp
checkNow();
setInterval(checkNow, 1000);