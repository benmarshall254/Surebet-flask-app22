<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Admin Login - Secure Access</title>

  <!-- Security Headers -->
  <meta http-equiv="X-Content-Type-Options" content="nosniff" />
  <meta http-equiv="X-Frame-Options" content="DENY" />
  <meta http-equiv="X-XSS-Protection" content="1; mode=block" />
  <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin" />

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
    }

    .login-btn:hover:not(:disabled) {
      transform: translateY(-2px);
      box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
    }

    .login-btn:disabled {
      opacity: 0.7;
      cursor: not-allowed;
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

    @media (prefers-reduced-motion: reduce) {
      * {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
      }
    }

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
        />
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
          />
          <button type="button" class="show-password" id="togglePassword" aria-label="Show password">👁️</button>
        </div>
      </div>

      <button type="submit" class="login-btn">Login</button>
    </form>
  </div>

  <script>
    const togglePassword = document.getElementById("togglePassword");
    const passwordInput = document.getElementById("password");

    togglePassword.addEventListener("click", () => {
      const type = passwordInput.getAttribute("type") === "password" ? "text" : "password";
      passwordInput.setAttribute("type", type);
      togglePassword.textContent = type === "password" ? "👁️" : "🙈";
    });
  </script>
</body>
</html>
