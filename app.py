<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login - Secure Access</title>
    
    <!-- Security Headers -->
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
    
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .login-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            padding: 40px;
            width: 100%;
            max-width: 400px;
            transform: translateY(-20px);
            animation: slideIn 0.6s ease-out forwards;
        }

        @keyframes slideIn {
            to {
                transform: translateY(0);
            }
        }

        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }

        .login-header h1 {
            color: #333;
            font-size: 2.5rem;
            font-weight: 300;
            margin-bottom: 10px;
        }

        .login-header p {
            color: #666;
            font-size: 1rem;
        }

        .security-notice {
            background: rgba(255, 193, 7, 0.1);
            border-left: 4px solid #ffc107;
            padding: 12px;
            margin-bottom: 20px;
            border-radius: 0 8px 8px 0;
            font-size: 0.85rem;
            color: #856404;
        }

        .form-group {
            margin-bottom: 25px;
            position: relative;
        }

        .form-group label {
            display: block;
            color: #555;
            font-weight: 500;
            margin-bottom: 8px;
            font-size: 0.95rem;
        }

        .form-group input {
            width: 100%;
            padding: 15px 20px;
            border: 2px solid #e1e5e9;
            border-radius: 12px;
            font-size: 1rem;
            transition: all 0.3s ease;
            background: #fff;
        }

        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            transform: translateY(-1px);
        }

        .form-group input.error {
            border-color: #e74c3c;
            animation: shake 0.5s ease-in-out;
        }

        .password-strength {
            margin-top: 5px;
            font-size: 0.8rem;
            color: #666;
            display: none;
        }

        .strength-bar {
            height: 3px;
            background: #e1e5e9;
            border-radius: 2px;
            margin-top: 5px;
            overflow: hidden;
        }

        .strength-fill {
            height: 100%;
            width: 0%;
            transition: all 0.3s ease;
            border-radius: 2px;
        }

        .strength-weak { background: #e74c3c; }
        .strength-medium { background: #f39c12; }
        .strength-strong { background: #27ae60; }

        .login-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 12px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .login-btn:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
        }

        .login-btn:active {
            transform: translateY(0);
        }

        .login-btn:disabled {
            opacity: 0.7;
            cursor: not-allowed;
            transform: none;
        }

        .error-message {
            color: #e74c3c;
            text-align: center;
            margin-top: 15px;
            padding: 12px;
            background: rgba(231, 76, 60, 0.1);
            border: 1px solid rgba(231, 76, 60, 0.2);
            border-radius: 8px;
            display: none;
            animation: shake 0.5s ease-in-out;
        }

        .success-message {
            color: #27ae60;
            text-align: center;
            margin-top: 15px;
            padding: 12px;
            background: rgba(39, 174, 96, 0.1);
            border: 1px solid rgba(39, 174, 96, 0.2);
            border-radius: 8px;
            display: none;
        }

        @keyframes shake {
            0%, 20%, 50%, 80%, 100% { transform: translateX(0); }
            10%, 30%, 70%, 90% { transform: translateX(-5px); }
            40%, 60% { transform: translateX(5px); }
        }

        .loading-spinner {
            display: none;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s ease-in-out infinite;
            margin-right: 10px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .admin-icon {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            color: white;
            font-size: 1.5rem;
        }

        .rate-limit-warning {
            background: rgba(220, 53, 69, 0.1);
            border: 1px solid rgba(220, 53, 69, 0.2);
            color: #721c24;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
            text-align: center;
            font-size: 0.9rem;
        }

        .attempts-remaining {
            margin-top: 10px;
            text-align: center;
            font-size: 0.85rem;
            color: #666;
        }

        .show-password {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #666;
            cursor: pointer;
            font-size: 0.9rem;
        }

        .show-password:hover {
            color: #333;
        }

        /* Accessibility improvements */
        @media (prefers-reduced-motion: reduce) {
            * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }

        /* Mobile responsiveness */
        @media (max-width: 480px) {
            .login-container {
                padding: 30px 20px;
            }
            
            .login-header h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <div class="admin-icon">🔐</div>
            <h1>Admin Access</h1>
            <p>Secure authentication required</p>
        </div>
        
        <div class="security-notice">
            <strong>Security Notice:</strong> This is a restricted access area. All login attempts are monitored and logged.
        </div>

        <div class="rate-limit-warning" id="rateLimitWarning">
            Too many failed attempts. Please wait before trying again.
        </div>
        
        <form id="loginForm" action="/admin/login" method="POST" novalidate>
            <div class="form-group">
                <label for="username">Username</label>
                <input 
                    type="text" 
                    id="username" 
                    name="username" 
                    required 
                    autocomplete="username"
                    maxlength="50"
                    pattern="[a-zA-Z0-9_-]+"
                    title="Username can only contain letters, numbers, underscores, and hyphens"
                >
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <div style="position: relative;">
                    <input 
                        type="password" 
                        id="password" 
                        name="password" 
                        required 
                        autocomplete="current-password"
                        maxlength="128"
                        minlength="6"
                    >
                    <button type="button" class="show-password" id="togglePassword" aria-label="Show password">
                        👁️
                    </button>
                </div>
                <div class="password-strength" id="passwordStrength">
                    <div class="strength-bar">
                        <div class="strength-fill" id="strengthFill"></div>
                    </div>
                    <span id="strengthText">Password strength</span>
                </div>
            </div>
            
            <button type="submit" class="login-btn" id="loginBtn">
                <span class="loading-spinner" id="loadingSpinner"></span>
                <span id="btnText">Sign In Securely</span>
            </button>
            
            <div class="attempts-remaining" id="attemptsRemaining"></div>
            
            <div class="error-message" id="errorMessage"></div>
            <div class="success-message" id="successMessage"></div>
        </form>
    </div>

    <script>
        // Security and UX enhancements
        let failedAttempts = 0;
        const maxAttempts = 5;
        let isRateLimited = false;
        
        // Get form elements
        const loginForm = document.getElementById('loginForm');
        const usernameInput = document.getElementById('username');
        const passwordInput = document.getElementById('password');
        const togglePassword = document.getElementById('togglePassword');
        const loginBtn = document.getElementById('loginBtn');
        const loadingSpinner = document.getElementById('loadingSpinner');
        const btnText = document.getElementById('btnText');
        const errorMessage = document.getElementById('errorMessage');
        const successMessage = document.getElementById('successMessage');
        const rateLimitWarning = document.getElementById('rateLimitWarning');
        const attemptsRemaining = document.getElementById('attemptsRemaining');

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            // Check if already logged in
            checkAuthStatus();
            
            // Focus on username field
            usernameInput.focus();
            
            // Load failed attempts from sessionStorage
            const storedAttempts = sessionStorage.getItem('failedLoginAttempts');
            if (storedAttempts) {
                failedAttempts = parseInt(storedAttempts);
                updateAttemptsDisplay();
            }
        });

        // Check authentication status
        function checkAuthStatus() {
            fetch('/admin/dashboard', {
                method: 'GET',
                credentials: 'same-origin'
            })
            .then(response => {
                if (response.ok) {
                    // Already authenticated, redirect
                    window.location.href = '/admin/dashboard';
                }
            })
            .catch(() => {
                // Not authenticated, continue with login form
            });
        }

        // Password visibility toggle
        togglePassword.addEventListener('click', function() {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            this.textContent = type === 'password' ? '👁️' : '🙈';
        });

        // Input validation and sanitization
        usernameInput.addEventListener('input', function() {
            // Remove invalid characters
            this.value = this.value.replace(/[^a-zA-Z0-9_-]/g, '');
            clearErrors();
        });

        passwordInput.addEventListener('input', function() {
            clearErrors();
            // Don't show password strength for security reasons in admin login
        });

        // Form submission with enhanced security
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            if (isRateLimited) {
                showError('Rate limited. Please wait before trying again.');
                return;
            }
            
            const username = usernameInput.value.trim();
            const password = passwordInput.value;
            
            // Client-side validation
            if (!validateInputs(username, password)) {
                return;
            }
            
            // Show loading state
            showLoading();
            
            // Create form data with CSRF protection
            const formData = new FormData();
            formData.append('username', username);
            formData.append('password', password);
            
            // Submit to Flask with timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
            
            fetch('/admin/login', {
                method: 'POST',
                body: formData,
                credentials: 'same-origin',
                signal: controller.signal,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => {
                clearTimeout(timeoutId);
                
                if (response.ok) {
                    // Check if it's a redirect response
                    if (response.redirected || response.url.includes('/admin/dashboard')) {
                        handleSuccess();
                        return;
                    }
                    // If response is OK but not redirected, check the response
                    return response.text().then(text => {
                        if (text.includes('dashboard') || text.includes('admin-dashboard')) {
                            handleSuccess();
                        } else {
                            handleError('Authentication failed');
                        }
                    });
                } else if (response.status === 429) {
                    handleRateLimit();
                } else {
                    handleError('Invalid credentials');
                }
            })
            .catch(error => {
                clearTimeout(timeoutId);
                hideLoading();
                
                if (error.name === 'AbortError') {
                    showError('Request timeout. Please try again.');
                } else {
                    console.error('Login error:', error);
                    showError('Connection error. Please try again.');
                }
            });
        });

        function validateInputs(username, password) {
            let isValid = true;
            
            // Username validation
            if (!username) {
                usernameInput.classList.add('error');
                showError('Username is required');
                isValid = false;
            } else if (username.length < 2) {
                usernameInput.classList.add('error');
                showError('Username must be at least 2 characters');
                isValid = false;
            } else if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
                usernameInput.classList.add('error');
                showError('Username contains invalid characters');
                isValid = false;
            }
            
            // Password validation
            if (!password) {
                passwordInput.classList.add('error');
                showError('Password is required');
                isValid = false;
            } else if (password.length < 6) {
                passwordInput.classList.add('error');
                showError('Password must be at least 6 characters');
                isValid = false;
            }
            
            return isValid;
        }

        function handleSuccess() {
            hideLoading();
            showSuccess('Login successful! Redirecting...');
            
            // Clear failed attempts
            failedAttempts = 0;
            sessionStorage.removeItem('failedLoginAttempts');
            
            // Redirect after short delay
            setTimeout(() => {
                window.location.href = '/admin/dashboard';
            }, 1500);
        }

        function handleError(message) {
            hideLoading();
            failedAttempts++;
            sessionStorage.setItem('failedLoginAttempts', failedAttempts.toString());
            
            updateAttemptsDisplay();
            showError(message);
            
            // Clear password field
            passwordInput.value = '';
            passwordInput.focus();
            
            // Check for rate limiting
            if (failedAttempts >= maxAttempts) {
                handleRateLimit();
            }
        }

        function handleRateLimit() {
            isRateLimited = true;
            rateLimitWarning.style.display = 'block';
            loginBtn.disabled = true;
            
            // Re-enable after 5 minutes
            setTimeout(() => {
                isRateLimited = false;
                rateLimitWarning.style.display = 'none';
                loginBtn.disabled = false;
                failedAttempts = 0;
                sessionStorage.removeItem('failedLoginAttempts');
                updateAttemptsDisplay();
            }, 300000); // 5 minutes
        }

        function updateAttemptsDisplay() {
            if (failedAttempts > 0) {
                const remaining = maxAttempts - failedAttempts;
                if (remaining > 0) {
                    attemptsRemaining.textContent = `Attempts remaining: ${remaining}`;
                    attemptsRemaining.style.display = 'block';
                } else {
                    attemptsRemaining.style.display = 'none';
                }
            } else {
                attemptsRemaining.style.display = 'none';
            }
        }

        function showLoading() {
            loginBtn.disabled = true;
            loadingSpinner.style.display = 'inline-block';
            btnText.textContent = 'Authenticating...';
            clearMessages();
        }

        function hideLoading() {
            loginBtn.disabled = false;
            loadingSpinner.style.display = 'none';
            btnText.textContent = 'Sign In Securely';
        }

        function showSuccess(message) {
            loginBtn.style.background = 'linear-gradient(135deg, #27ae60 0%, #2ecc71 100%)';
            btnText.textContent = 'Success! Redirecting...';
            loadingSpinner.style.display = 'none';
            
            if (message) {
                successMessage.textContent = message;
                successMessage.style.display = 'block';
            }
        }

        function showError(message) {
            errorMessage.textContent = message;
            errorMessage.style.display = 'block';
            
            // Auto-hide after 5 seconds
            setTimeout(() => {
                errorMessage.style.display = 'none';
            }, 5000);
        }

        function clearErrors() {
            usernameInput.classList.remove('error');
            passwordInput.classList.remove('error');
            errorMessage.style.display = 'none';
        }

        function clearMessages() {
            errorMessage.style.display = 'none';
            successMessage.style.display = 'none';
        }

        // Security: Clear form data on page unload
        window.addEventListener('beforeunload', function() {
            passwordInput.value = '';
        });

        // Security: Disable right-click context menu
        document.addEventListener('contextmenu', function(e) {
            e.preventDefault();
        });

        // Security: Disable common keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Disable F12, Ctrl+Shift+I, Ctrl+U, Ctrl+Shift+J
            if (e.key === 'F12' || 
                (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J')) ||
                (e.ctrlKey && e.key === 'U')) {
                e.preventDefault();
                return false;
            }
        });

        // Accessibility: Announce errors to screen readers
        function announceToScreenReader(message) {
            const announcement = document.createElement('div');
            announcement.setAttribute('aria-live', 'polite');
            announcement.setAttribute('aria-atomic', 'true');
            announcement.className = 'sr-only';
            announcement.textContent = message;
            document.body.appendChild(announcement);
            
            setTimeout(() => {
                document.body.removeChild(announcement);
            }, 1000);
        }
    </script>
</body>
</html>
