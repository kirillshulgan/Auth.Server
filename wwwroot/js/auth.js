// ── Переключение табов ──────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        tab.classList.add('active');
        document.getElementById('tab-' + tab.dataset.tab)?.classList.add('active');
    });
});

// ── Показать/скрыть пароль ──────────────────────────────────────────
function togglePassword() {
    const input = document.getElementById('password');
    input.type = input.type === 'password' ? 'text' : 'password';
}

// ── Таймер повторной отправки ───────────────────────────────────────
let timerInterval = null;

function startResendTimer(seconds = 60) {
    const btn = document.getElementById('btn-resend');
    const timerEl = document.getElementById('otp-timer');
    btn.disabled = true;

    let remaining = seconds;
    timerEl.textContent = `(${remaining}с)`;

    timerInterval = setInterval(() => {
        remaining--;
        timerEl.textContent = `(${remaining}с)`;
        if (remaining <= 0) {
            clearInterval(timerInterval);
            btn.disabled = false;
            timerEl.textContent = '';
        }
    }, 1000);
}

// ── Отправка OTP ────────────────────────────────────────────────────
async function sendOtp() {
    const email = document.getElementById('otp-email').value.trim();
    if (!email) {
        showOtpError('Введите email адрес');
        return;
    }

    const btn = document.getElementById('btn-send-otp');
    btn.textContent = 'Отправка...';
    btn.disabled = true;

    try {
        const res = await fetch('/auth/send-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });

        const data = await res.json();

        if (!res.ok) {
            showOtpError(data.error ?? 'Ошибка отправки');
            btn.textContent = 'Получить код';
            btn.disabled = false;
            return;
        }

        // Переходим к вводу кода
        document.getElementById('otp-email-display').textContent = email;
        document.getElementById('otp-email-hidden').value = email;
        document.getElementById('otp-step-email').style.display = 'none';
        document.getElementById('otp-step-code').style.display = 'block';
        document.getElementById('otp-code')?.focus();

        // В Development показываем код подсказкой
        if (data.code) {
            document.getElementById('otp-code').placeholder = data.code;
            console.log('[DEV] OTP код:', data.code);
        }

        startResendTimer(60);

    } catch {
        showOtpError('Сервер недоступен. Попробуйте позже.');
        btn.textContent = 'Получить код';
        btn.disabled = false;
    }
}

// ── Повторная отправка ──────────────────────────────────────────────
async function resendOtp() {
    const email = document.getElementById('otp-email-hidden').value;
    document.getElementById('otp-email').value = email;
    document.getElementById('btn-send-otp').textContent = 'Получить код';
    document.getElementById('btn-send-otp').disabled = false;
    document.getElementById('otp-step-email').style.display = 'block';
    document.getElementById('otp-step-code').style.display = 'none';
    clearInterval(timerInterval);
    await sendOtp();
}

// ── Сброс OTP формы ─────────────────────────────────────────────────
function resetOtp() {
    document.getElementById('otp-step-email').style.display = 'block';
    document.getElementById('otp-step-code').style.display = 'none';
    document.getElementById('btn-send-otp').textContent = 'Получить код';
    document.getElementById('btn-send-otp').disabled = false;
    clearInterval(timerInterval);
}

// ── Автоформат OTP поля ─────────────────────────────────────────────
document.getElementById('otp-code')?.addEventListener('input', function () {
    this.value = this.value.replace(/\D/g, '').slice(0, 6);
});

// ── Вспомогательная функция ─────────────────────────────────────────
function showOtpError(msg) {
    // Показываем ошибку под полем email
    let err = document.getElementById('otp-inline-error');
    if (!err) {
        err = document.createElement('p');
        err.id = 'otp-inline-error';
        err.style.cssText = 'color:#dc2626;font-size:13px;margin-top:6px';
        document.getElementById('otp-email')?.after(err);
    }
    err.textContent = msg;
}

// ── Telegram Login через официальный SDK ────────────────────────────
function openTelegramPopup(returnUrl, _attempt) {
    _attempt = _attempt || 0;

    if (typeof Telegram === 'undefined' || !Telegram.Login) {
        if (_attempt > 10) {
            showAuthError('Telegram SDK не загружен. Проверьте соединение.');
            return;
        }
        setTimeout(() => openTelegramPopup(returnUrl, _attempt + 1), 200);
        return;
    }

    Telegram.Login.auth(
        {
            client_id: parseInt(window.TELEGRAM_CLIENT_ID),
            lang: 'ru',
            request_access: ['write']
        },
        async (data) => {
            if (!data || data.error) {
                if (data?.error !== 'popup_closed') {
                    showAuthError(data?.error || 'Вход отменён.');
                }
                return;
            }

            try {
                const res = await fetch('/connect/social/telegram/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        idToken: data.id_token,
                        returnUrl: returnUrl || '/'
                    })
                });

                const result = await res.json();

                if (res.ok && result.redirectUrl) {
                    window.location.href = result.redirectUrl;
                } else {
                    showAuthError(result.error || 'Ошибка входа.');
                }
            } catch {
                showAuthError('Сервер недоступен. Попробуйте позже.');
            }
        }
    );
}


function showAuthError(msg) {
    let err = document.getElementById('auth-error-msg');
    if (!err) {
        err = document.createElement('div');
        err.id = 'auth-error-msg';
        err.className = 'auth-error';
        err.style.marginTop = '12px';
        document.querySelector('.auth-card')?.prepend(err);
    }
    err.innerHTML = `<span>⚠️</span> ${msg}`;
    err.style.display = 'flex';
}
