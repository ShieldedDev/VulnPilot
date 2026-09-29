// Auth page interactions

document.addEventListener('DOMContentLoaded', function () {

    // ─── Password Strength Meter ────────────────────────────────
    const passwordInput = document.getElementById('password');
    const strengthBar = document.getElementById('strengthBar');

    if (passwordInput && strengthBar) {
        passwordInput.addEventListener('input', function () {
            const val = this.value;
            let score = 0;

            if (val.length >= 8)  score++;
            if (val.length >= 12) score++;
            if (/[A-Z]/.test(val)) score++;
            if (/[a-z]/.test(val)) score++;
            if (/[0-9]/.test(val)) score++;
            if (/[^A-Za-z0-9]/.test(val)) score++;

            const colors = ['', '#f85149', '#ff7700', '#f0a500', '#3fb950', '#00d4ff'];
            const widths = [0, 20, 40, 60, 80, 100];
            strengthBar.style.width = widths[score] + '%';
            strengthBar.style.background = colors[score] || '#30363d';
        });
    }

    // ─── Password Confirm Match ─────────────────────────────────
    const confirmInput = document.getElementById('confirm_password');
    const matchHint = document.getElementById('matchHint');

    if (confirmInput && matchHint && passwordInput) {
        confirmInput.addEventListener('input', function () {
            if (this.value === '') {
                matchHint.textContent = '';
                return;
            }
            if (this.value === passwordInput.value) {
                matchHint.textContent = '✓ Passwords match';
                matchHint.style.color = '#3fb950';
            } else {
                matchHint.textContent = '✗ Passwords do not match';
                matchHint.style.color = '#f85149';
            }
        });
    }

    // ─── Form Validation ────────────────────────────────────────
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function (e) {
            const pwd = document.getElementById('password').value;
            const conf = document.getElementById('confirm_password').value;
            if (pwd !== conf) {
                e.preventDefault();
                showAlert('Passwords do not match.', 'error');
            }
        });
    }

    // ─── Auto-dismiss alerts ─────────────────────────────────────
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            alert.style.transition = 'opacity 0.5s';
            alert.style.opacity = '0';
            setTimeout(function () { alert.remove(); }, 500);
        }, 4000);
    });
});

function showAlert(message, type) {
    const existing = document.querySelector('.alert');
    if (existing) existing.remove();

    const alert = document.createElement('div');
    alert.className = 'alert alert-' + type;
    alert.textContent = message;

    const form = document.querySelector('.auth-form');
    form.parentNode.insertBefore(alert, form);
}
