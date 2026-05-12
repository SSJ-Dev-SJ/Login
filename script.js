(function () {
    // Shared DOM references used across authentication and dashboard views.
    const authContainer = document.getElementById('authContainer');
    const dashboardContainer = document.getElementById('dashboardContainer');
    const loginFormDiv = document.getElementById('loginForm');
    const registerFormDiv = document.getElementById('registerForm');
    const toast = document.getElementById('toast');

    // Login form fields, validation messages, and loading state.
    const loginIdentifier = document.getElementById('loginIdentifier');
    const loginPassword = document.getElementById('loginPassword');
    const loginIdError = document.getElementById('loginIdError');
    const loginPassError = document.getElementById('loginPassError');
    const rememberMe = document.getElementById('rememberMe');
    const loginBtn = document.getElementById('loginBtn');
    const loginSpinner = document.getElementById('loginSpinner');

    // Registration form fields, validation messages, and password strength UI.
    const regUsername = document.getElementById('regUsername');
    const regEmail = document.getElementById('regEmail');
    const regPassword = document.getElementById('regPassword');
    const regConfirmPassword = document.getElementById('regConfirmPassword');
    const regUserError = document.getElementById('regUserError');
    const regEmailError = document.getElementById('regEmailError');
    const regPassError = document.getElementById('regPassError');
    const regConfirmError = document.getElementById('regConfirmError');
    const registerBtn = document.getElementById('registerBtn');
    const regSpinner = document.getElementById('regSpinner');
    const strengthFill = document.getElementById('strengthFill');
    const strengthText = document.getElementById('strengthText');

    // Dashboard elements populated from the authenticated session.
    const dashAvatar = document.getElementById('dashAvatar');
    const dashUsername = document.getElementById('dashUsername');
    const dashGreeting = document.getElementById('dashGreeting');
    const sessionBadge = document.getElementById('sessionBadge');
    const statLogins = document.getElementById('statLogins');
    const statMemberSince = document.getElementById('statMemberSince');
    const statIterations = document.getElementById('statIterations');
    const profileUsername = document.getElementById('profileUsername');
    const profileEmail = document.getElementById('profileEmail');
    const profileId = document.getElementById('profileId');
    const profileCreated = document.getElementById('profileCreated');
    const profileSession = document.getElementById('profileSession');
    const logoutBtn = document.getElementById('logoutBtn');
    const toggleUsersBtn = document.getElementById('toggleUsersBtn');
    const allUsersPanel = document.getElementById('allUsersPanel');
    const loginTimeDisplay = document.getElementById('loginTimeDisplay');

    // Storage keys and security/session settings.
    const USERS_KEY = 'appUsers_v2';
    const REMEMBER_KEY = 'rememberToken_v2';
    const SESSION_KEY = 'currentSession';
    const PBKDF2_ITERATIONS = 100000;
    const REMEMBER_DAYS = 7;

    // HELPERS
    // Generates a random salt encoded as hexadecimal.
    function generateSalt(length = 16) {
        return Array.from(crypto.getRandomValues(new Uint8Array(length)))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Generates a random token encoded as hexadecimal.
    function generateToken(length = 32) {
        return Array.from(crypto.getRandomValues(new Uint8Array(length)))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }

     // Hashes a password with PBKDF2/SHA-256.
    async function pbkdf2Hash(password, saltHex, iterations) {
        const enc = new TextEncoder();
        const saltBytes = enc.encode(saltHex);
        const keyMaterial = await crypto.subtle.importKey(
            'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
        );
        const derived = await crypto.subtle.deriveBits({
            name: 'PBKDF2', salt: saltBytes, iterations: iterations, hash: 'SHA-256'
        }, keyMaterial, 256);
        return Array.from(new Uint8Array(derived))
            .map(b => b.toString(16).padStart(2, '0')).join('');
    }
    
    // Reads the full user list from localStorage.
    function getAllUsers() {
        try { return JSON.parse(localStorage.getItem(USERS_KEY)) || []; } catch { return []; }
    }

    // Persists the full user list to localStorage.
    function saveAllUsers(users) {
        localStorage.setItem(USERS_KEY, JSON.stringify(users));
    }
    
    // Finds a user by username or email address.
    function findUser(identifier) {
        const lower = identifier.toLowerCase().trim();
        return getAllUsers().find(u => u.username.toLowerCase() === lower || u.email.toLowerCase() === lower);
    }

    // Checks whether a username or email is already registered.
    function userExists(username, email) {
        const lowerUser = username.toLowerCase().trim();
        const lowerEmail = email.toLowerCase().trim();
        return getAllUsers().some(u => u.username.toLowerCase() === lowerUser || u.email.toLowerCase() === lowerEmail);
    }
    
    // Shows a temporary toast message
    function showToast(msg, type = 'success') {
        toast.innerHTML = (type === 'success' ? '<i class="fas fa-check-circle"></i> ' : '<i class="fas fa-exclamation-circle"></i> ') + msg;
        toast.className = `toast ${type} show`;
        clearTimeout(toast._t);
        toast._t = setTimeout(() => toast.classList.remove('show'), 3000);
    }

    // Removes visible validation messages and input error styling.
    function clearErrors() {
        [loginIdError, loginPassError, regUserError, regEmailError, regPassError, regConfirmError]
            .forEach(e => e.classList.remove('visible'));
        [loginIdentifier, loginPassword, regUsername, regEmail, regPassword, regConfirmPassword]
            .forEach(i => i && i.classList.remove('input-error'));
    }

    // Marks a single field as invalid and displays its message.
    function showFieldError(input, errorEl, msg) {
        input.classList.add('input-error');
        errorEl.textContent = msg;
        errorEl.classList.add('visible');
    }

    // SESSION
    // Creates a session for an authenticated user and updates login metadata.
    function createSession(user, persist) {
        const now = new Date().toISOString();
        const sessionData = {
            id: user.id,
            username: user.username,
            email: user.email,
            createdAt: user.createdAt,
            loginCount: (user.loginCount || 0) + 1,
            sessionStart: now,
            isPersistent: persist,
        };
        sessionStorage.setItem(SESSION_KEY, JSON.stringify(sessionData));
        if (persist) {
            const token = generateToken();
            const expiry = new Date();
            expiry.setDate(expiry.getDate() + REMEMBER_DAYS);

            // Store remember-me data in localStorage
            localStorage.setItem(REMEMBER_KEY, JSON.stringify({
                userId: user.id, token, expiry: expiry.toISOString()
            }));
        } else {
            // Remove any existing remember-me data
            localStorage.removeItem(REMEMBER_KEY);
        }
        const users = getAllUsers();
        const idx = users.findIndex(u => u.id === user.id);
        if (idx !== -1) {
            // Increment login count
            users[idx].loginCount = (users[idx].loginCount || 0) + 1;
            users[idx].lastLogin = now;
            saveAllUsers(users);
        }
        return sessionData;
    }

    // Gets the active session from sessionStorage or restores it from remember-me.
    function getCurrentSession() {
        const sess = sessionStorage.getItem(SESSION_KEY);
        if (sess) {
            try {
                const parsed = JSON.parse(sess);
                if (getAllUsers().some(u => u.id === parsed.id)) return { ...parsed, source: 'session' };
            } catch { sessionStorage.removeItem(SESSION_KEY); }
        }

        // Try to restore a remembered login session from localStorage
        const rem = localStorage.getItem(REMEMBER_KEY);
        if (rem) {
            try {
                const parsed = JSON.parse(rem);
                if (new Date() < new Date(parsed.expiry)) {
                    const user = getAllUsers().find(u => u.id === parsed.userId);
                    if (user) {
                        const restored = {
                            id: user.id, username: user.username, email: user.email,
                            createdAt: user.createdAt, loginCount: user.loginCount || 0,
                            sessionStart: new Date().toISOString(), isPersistent: true
                        };
                        sessionStorage.setItem(SESSION_KEY, JSON.stringify(restored));
                        return { ...restored, source: 'remember' };
                    }
                } else {
                    localStorage.removeItem(REMEMBER_KEY);
                }
            } catch { localStorage.removeItem(REMEMBER_KEY); }
        }
        return null;
    }

    // Clears both the browser session and any remember-me token.
    function clearSession() {
        sessionStorage.removeItem(SESSION_KEY);
        localStorage.removeItem(REMEMBER_KEY);
    }

    // UI
    // Displays the login form and hides the registration form.
    function showLogin() {
        clearErrors();
        loginFormDiv.style.display = 'block';
        registerFormDiv.style.display = 'none';
    }

    // Displays a fresh registration form and resets password strength output.
    function showRegister() {
        clearErrors();
        loginFormDiv.style.display = 'none';
        registerFormDiv.style.display = 'block';
        regUsername.value = '';
        regEmail.value = '';
        regPassword.value = '';
        regConfirmPassword.value = '';
        strengthFill.style.width = '0%';
        strengthText.textContent = '';
    }

    // Formats an ISO date string for the dashboard login time.
    function formatDateTime(isoString) {
        const d = new Date(isoString);
        return d.toLocaleString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    }

    // Switches from the auth card to the dashboard and renders session details.
    function showDashboard(session) {
        authContainer.style.display = 'none';
        dashboardContainer.classList.add('visible');
        dashboardContainer.style.display = 'block';
        updateDashboard(session);
        allUsersPanel.classList.remove('open');
    }

    //  Switches back to the auth card and clears the current session.
    function showAuth() {
        dashboardContainer.classList.remove('visible');
        dashboardContainer.style.display = 'none';
        authContainer.style.display = 'block';
        showLogin();
        clearSession();
    }


    // Fills dashboard fields from the current session object.
    function updateDashboard(s) {
        dashAvatar.innerHTML = '<i class="fas fa-user"></i>';
        dashUsername.textContent = dashGreeting.textContent = s.username;
        profileUsername.textContent = s.username;
        profileEmail.textContent = s.email;
        profileId.textContent = s.id;
        const createdDate = new Date(s.createdAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
        profileCreated.textContent = statMemberSince.textContent = createdDate;
        statLogins.textContent = s.loginCount || 1;
        statIterations.textContent = (PBKDF2_ITERATIONS / 1000) + 'k';
        profileSession.textContent = s.isPersistent ? 'Persistent (Remember Me)' : 'Browser Session';
        sessionBadge.textContent = s.isPersistent ? '🔗 Remembered' : '⏳ Session';
        sessionBadge.className = 'session-badge' + (s.isPersistent ? ' persistent' : '');
        // Display login time
        loginTimeDisplay.textContent = s.sessionStart ? formatDateTime(s.sessionStart) : 'Just now';
    }

    // Password strength
    // Calculates a simple password strength score based on length and character mix.
    function evaluateStrength(pw) {
        let score = 0;
        if (pw.length >= 8) score++;
        if (pw.length >= 12) score++;
        if (/[A-Z]/.test(pw)) score++;
        if (/[0-9]/.test(pw)) score++;
        if (/[^A-Za-z0-9]/.test(pw)) score++;
        return Math.min(score, 4);
    }

    // Updates the registration password strength meter.
    function updateStrengthUI(pw) {
        const level = evaluateStrength(pw);
        const percent = (level / 4) * 100;
        strengthFill.style.width = percent + '%';
        const colors = ['#ef4444', '#f97316', '#eab308', '#84cc16', '#10b981'];
        strengthFill.style.background = colors[level];
        const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
        strengthText.textContent = pw ? labels[level] : '';
        strengthText.style.color = colors[level];
    }

    // AUTH
    // Validates login input, verifies the password hash, and opens a session.
    async function handleLogin(e) {
        e.preventDefault();
        clearErrors();
        if (!loginIdentifier.value.trim()) { showFieldError(loginIdentifier, loginIdError, 'Required'); return; }
        if (!loginPassword.value) { showFieldError(loginPassword, loginPassError, 'Password required'); return; }
        loginBtn.disabled = true;
        loginSpinner.style.display = 'inline-block';
        const identifier = loginIdentifier.value.trim();
        const password = loginPassword.value;
        const persist = rememberMe.checked;
        await new Promise(r => setTimeout(r, 200));
        try {
            const user = findUser(identifier);
            if (!user) {
                showToast('No account found', 'error');
                showFieldError(loginIdentifier, loginIdError, 'Account not found');
                resetLoginBtn(); return;
            }
            const hash = await pbkdf2Hash(password, user.salt, user.iterations);
            if (hash !== user.passwordHash) {
                showToast('Incorrect password', 'error');
                showFieldError(loginPassword, loginPassError, 'Wrong password');
                resetLoginBtn(); return;
            }
            const session = createSession(user, persist);
            showToast('Welcome back, ' + user.username + '!', 'success');
            showDashboard(session);
        } catch (err) {
            console.error(err);
            showToast('Login error', 'error');
            resetLoginBtn();
        }
    }

    // Restores the login button after validation or authentication failure.
    function resetLoginBtn() {
        loginBtn.disabled = false;
        loginSpinner.style.display = 'none';
    }

    // Validates registration input, hashes the password, saves the user, and logs in.
    async function handleRegister(e) {
        e.preventDefault();
        clearErrors();
        let valid = true;
        const username = regUsername.value.trim();
        const email = regEmail.value.trim();
        const password = regPassword.value;
        const confirm = regConfirmPassword.value;

        // Minimum Character Input Validation 
        if (!username || username.length < 3) { showFieldError(regUsername, regUserError, 'Min 3 characters'); valid = false; }

        // Email Validation 
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { showFieldError(regEmail, regEmailError, 'Invalid email'); valid = false; }

        // Password Validation 
        if (!password || password.length < 6) { showFieldError(regPassword, regPassError, 'Min 6 characters'); valid = false; }

        //Check The Password Match Validation 
        if (password !== confirm) { showFieldError(regConfirmPassword, regConfirmError, 'Miss Match'); valid = false; }
        if (!valid) return;
        registerBtn.disabled = true;
        regSpinner.style.display = 'inline-block';
        await new Promise(r => setTimeout(r, 200));
        try {
            if (userExists(username, email)) {
                showToast('Username or email already taken', 'error');
                showFieldError(regUsername, regUserError, 'Already taken');
                resetRegBtn(); return;
            }
            const salt = generateSalt();
            const passwordHash = await pbkdf2Hash(password, salt, PBKDF2_ITERATIONS);
            const newUser = {
                id: 'user_' + generateToken(8),
                username, email,
                salt, iterations: PBKDF2_ITERATIONS,
                passwordHash,
                createdAt: new Date().toISOString(),
                lastLogin: new Date().toISOString(),
                loginCount: 0,
            };
            const users = getAllUsers();
            users.push(newUser);
            saveAllUsers(users);
            const session = createSession(newUser, false);
            showToast('Account created! Welcome, ' + username + '!', 'success');
            showDashboard(session);
        } catch (err) {
            console.error(err);
            showToast('Registration failed', 'error');
            resetRegBtn();
        }
    }

    // Restores the registration button after validation or registration failure.
    function resetRegBtn() {
        registerBtn.disabled = false;
        regSpinner.style.display = 'none';
    }

    // LOGOUT
    // Ends the current session and returns the user to the login form.
    function logout() {
        clearSession();
        showAuth();
        showToast('Logged out successfully', 'success');
    }

    // ALL USERS
    // Renders every locally stored user into the dashboard's users table.
    function renderAllUsers() {
        const users = getAllUsers();
        if (!users.length) {
            allUsersPanel.innerHTML = '<p style="color:var(--text-secondary);">No users yet.</p>';
            return;
        }
        const current = getCurrentSession();
        const currentId = current ? current.id : null;
        let html = '<table><thead><tr><th>Username</th><th>Email</th><th>Created</th><th>Logins</th></tr></thead><tbody>';
        users.forEach(u => {
            const isYou = u.id === currentId;
            html += `<tr class="${isYou ? 'you' : ''}">
                        <td>${u.username} ${isYou ? '(you)' : ''}</td>
                        <td>${u.email}</td>
                        <td>${new Date(u.createdAt).toLocaleDateString()}</td>
                        <td>${u.loginCount || 0}</td>
                    </tr>`;
        });
        html += '</tbody></table>';
        allUsersPanel.innerHTML = html;
    }

    // Opens or closes the locally stored users panel.
    toggleUsersBtn.addEventListener('click', () => {
        const isOpen = allUsersPanel.classList.contains('open');
        if (isOpen) {
            allUsersPanel.classList.remove('open');
            toggleUsersBtn.innerHTML = '<i class="fas fa-users"></i> Show All Registered Users (localStorage array)';
        } else {
            renderAllUsers();
            allUsersPanel.classList.add('open');
            toggleUsersBtn.innerHTML = '<i class="fas fa-users"></i> Hide User List';
        }
    });

    // EVENT LISTENERS
    // Wire form navigation, authentication actions, and logout behavior.
    document.getElementById('showRegister').addEventListener('click', showRegister);
    document.getElementById('showLogin').addEventListener('click', showLogin);
    loginFormDiv.querySelector('form').addEventListener('submit', handleLogin);
    registerFormDiv.querySelector('form').addEventListener('submit', handleRegister);
    logoutBtn.addEventListener('click', logout);

    // Toggle password inputs between hidden and visible text.
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', function (e) {
            e.preventDefault();
            const input = this.parentElement.querySelector('input');
            const icon = this.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                input.type = 'password';
                icon.className = 'fas fa-eye';
            }
        });
    });

    // Clear field errors as the user edits, and refresh password strength live.
    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('input', function () {
            this.classList.remove('input-error');
            const errorEl = this.closest('.form-group')?.querySelector('.error-msg');
            if (errorEl) errorEl.classList.remove('visible');
            if (this === regPassword) updateStrengthUI(this.value);
        });
    });

    // INIT
    // Starts the app by restoring a previous session or showing the login form.
    function init() {
        const session = getCurrentSession();
        if (session) {
            showDashboard(session);
            if (session.source === 'remember') showToast('Session restored. Welcome back!', 'success');
        } else {
            showAuth();
        }
    }
    init();
})();
