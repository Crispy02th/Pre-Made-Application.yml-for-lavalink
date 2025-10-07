# Configuration and Secrets

This document explains how to configure Lavalink with all necessary secrets and services for full functionality including Spotify, YouTube, and remote cipher services.

## Overview

Lavalink requires various API keys and tokens to access music services like Spotify and YouTube. This guide covers obtaining all necessary credentials and setting up supporting services.

## Secrets Required

### Core Lavalink Secrets
- **`LAVALINK_PASSWORD`** - Password for Lavalink REST and WebSocket connections
- **`SPOTIFY_CLIENT_ID`** & **`SPOTIFY_CLIENT_SECRET`** - Spotify API credentials
- **`YOUTUBE_CLIENT_ID`** & **`YOUTUBE_CLIENT_SECRET`** - Google OAuth credentials
- **`YOUTUBE_REFRESH_TOKEN`** - Long-lived YouTube refresh token
- **`YOUTUBE_POT_TOKEN`** & **`YOUTUBE_VISITOR_DATA`** - PoToken authentication (fallback)
- **`REMOTE_CIPHER_PASSWORD`** - Cipher server authentication
- **`REMOTE_CIPHER_USER_AGENT`** - Optional user agent for cipher requests

## Obtaining Secrets

### 1. Lavalink Password

Generate a strong random password:

```bash
# Using OpenSSL (64 character hex)
openssl rand -hex 32

# Using /dev/urandom
head -c32 /dev/urandom | base64

# Using PowerShell (Windows)
[Convert]::ToBase64String((1..32 | % { [byte](Get-Random -Max 256) }))
```

**Security Note:** Never commit this password to version control. Use environment variables or secret management.

### 2. Spotify Credentials

1. **Visit [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)**
2. **Log in** with your Spotify account
3. **Create an App:**
   - Click "Create App"
   - Fill in:
     - App name: `Your Lavalink Server`
     - App description: `Lavalink music server`
     - Redirect URI: `http://localhost:8080` (or your callback URL)
4. **Get Credentials:**
   - Note the **Client ID**
   - Click "Show client secret" to reveal **Client Secret**

**Configuration:**
```yaml
lavasrc:
  spotify:
    clientId: "your_spotify_client_id"
    clientSecret: "your_spotify_client_secret"
```

### 3. YouTube OAuth Credentials (Recommended)

#### Create Google Cloud Project

1. **Go to [Google Cloud Console](https://console.cloud.google.com/)**
2. **Create New Project:**
   - Click project dropdown
   - Select "New Project"
   - Enter project name: `lavalink-youtube`
   - Click "Create"

3. **Enable YouTube Data API v3:**
   - Navigation Menu → APIs & Services → Library
   - Search "YouTube Data API v3"
   - Click on it and press "Enable"

4. **Configure OAuth Consent Screen:**
   - APIs & Services → OAuth consent screen
   - Choose "External" (for public use) or "Internal" (for workspace use)
   - Fill required fields:
     - App name: `Lavalink YouTube`
     - User support email: Your email
     - Developer contact information: Your email
   - Add scopes: `.../auth/youtube.readonly`
   - Add test users (if external, during testing)

5. **Create OAuth Credentials:**
   - APIs & Services → Credentials
   - Click "Create Credentials" → OAuth 2.0 Client IDs
   - Application type: Web application
   - Name: `Lavalink Server`
   - Add authorized redirect URIs:
     - `https://developers.google.com/oauthplayground` (for easy token generation)
     - `http://localhost:8080/callback` (your local callback)

#### Get Refresh Token

**Method A: Using OAuth Playground**

1. **Go to [OAuth 2.0 Playground](https://developers.google.com/oauthplayground)**
2. **Settings (gear icon):**
   - Check "Use your own OAuth credentials"
   - Enter your Client ID and Client Secret
3. **Select & Authorize APIs:**
   - Step 1: Find "YouTube Data API v3"
   - Select required scopes (usually `https://www.googleapis.com/auth/youtube.readonly`)
   - Click "Authorize APIs"
4. **Exchange Authorization Code:**
   - Step 2: Click "Exchange authorization code for tokens"
   - Copy the **refresh_token** (not access token)

**Method B: Programmatic Approach**

```bash
# Construct authorization URL
AUTH_URL="https://accounts.google.com/o/oauth2/auth?\
client_id=YOUR_CLIENT_ID&\
redirect_uri=YOUR_REDIRECT_URI&\
scope=https://www.googleapis.com/auth/youtube.readonly&\
response_type=code&\
access_type=offline&\
prompt=consent"

# Visit URL in browser, get authorization code from callback
# Exchange for tokens
curl -X POST https://oauth2.googleapis.com/token \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code=AUTHORIZATION_CODE" \
  -d "grant_type=authorization_code" \
  -d "redirect_uri=YOUR_REDIRECT_URI"
```

### 4. PoToken and Visitor Data (Fallback)

Use only when OAuth is not possible. These emulate browser sessions and are fragile.

**Generation Methods:**

1. **Using youtube-trusted-session-generator:**
   ```bash
   git clone https://github.com/truedread/youtube-trusted-session-generator
   cd youtube-trusted-session-generator
   npm install
   node index.js
   ```

2. **Manual Browser Method:**
   - Open browser developer tools
   - Visit YouTube and monitor network requests
   - Look for requests with `poToken` and `visitorData` parameters
   - Extract from request headers or payloads

**Important:** Generate tokens from the same IP address as your server for better compatibility.

## Remote Cipher Server Setup

### Deno Cipher Server

Create `cipher-server.ts`:

```typescript
// cipher-server.ts - Minimal Deno server for remoteCipher endpoints
const PORT = Number(Deno.env.get("PORT") ?? "8001");
const PASSWORD = Deno.env.get("REMOTE_CIPHER_PASSWORD") ?? "";
const GOOGLE_CLIENT_ID = Deno.env.get("GOOGLE_CLIENT_ID") ?? "";
const GOOGLE_CLIENT_SECRET = Deno.env.get("GOOGLE_CLIENT_SECRET") ?? "";
const DATA_FILE = "./cipher-data.json";

type Stored = {
  refreshToken?: string | null;
  poToken?: string | null;
  visitorData?: string | null;
};

async function readData(): Promise<Stored> {
  try {
    const txt = await Deno.readTextFile(DATA_FILE);
    return JSON.parse(txt) as Stored;
  } catch {
    return {};
  }
}

async function writeData(obj: Stored) {
  await Deno.writeTextFile(DATA_FILE, JSON.stringify(obj, null, 2));
}

function unauthorized() {
  return new Response("Unauthorized", { status: 401 });
}

function badRequest(message: string) {
  return new Response(JSON.stringify({ error: message }), {
    status: 400,
    headers: { "content-type": "application/json" }
  });
}

Deno.serve({ port: PORT }, async (req) => {
  const url = new URL(req.url);
  const pathname = url.pathname;

  // CORS headers for browser requests
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  // GET /youtube - Return stored tokens
  if (req.method === "GET" && pathname === "/youtube") {
    const data = await readData();
    return new Response(JSON.stringify(data), {
      headers: { ...corsHeaders, "content-type": "application/json" },
    });
  }

  // POST /youtube - Store tokens (protected)
  if (req.method === "POST" && pathname === "/youtube") {
    const auth = req.headers.get("authorization") ?? "";
    if (!auth.startsWith("Bearer ") || auth.slice(7) !== PASSWORD) {
      return unauthorized();
    }
    
    let body: Partial<Stored> = {};
    try {
      body = await req.json();
    } catch (e) {
      return badRequest("Invalid JSON body");
    }
    
    const data = await readData();
    const merged: Stored = {
      refreshToken: body.refreshToken ?? data.refreshToken ?? null,
      poToken: body.poTokens ?? data.poTokens ?? null,
      visitorData: body.visitorData ?? data.visitorData ?? null,
    };
    
    await writeData(merged);
    return new Response(null, { 
      status: 204,
      headers: corsHeaders
    });
  }

  // GET /youtube/oauth/{refreshToken} - Exchange refresh token
  if (req.method === "GET" && pathname.startsWith("/youtube/oauth/")) {
    const refreshToken = decodeURIComponent(pathname.replace("/youtube/oauth/", ""));
    
    if (!refreshToken) {
      return badRequest("Refresh token required");
    }
    
    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
      return new Response(
        JSON.stringify({ error: "Google client credentials not configured" }), {
          status: 500,
          headers: { ...corsHeaders, "content-type": "application/json" }
        }
      );
    }

    try {
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: GOOGLE_CLIENT_ID,
          client_secret: GOOGLE_CLIENT_SECRET,
          refresh_token: refreshToken,
          grant_type: "refresh_token",
        }),
      });

      const payload = await tokenRes.text();
      return new Response(payload, {
        status: tokenRes.status,
        headers: { ...corsHeaders, "content-type": "application/json" }
      });
    } catch (error) {
      return new Response(
        JSON.stringify({ error: "Token exchange failed" }), {
          status: 500,
          headers: { ...corsHeaders, "content-type": "application/json" }
        }
      );
    }
  }

  // POST /decipher - Placeholder for signature deciphering
  if (req.method === "POST" && pathname === "/decipher") {
    return new Response(
      JSON.stringify({ error: "Decipher endpoint not implemented" }), {
        status: 501,
        headers: { ...corsHeaders, "content-type": "application/json" }
      }
    );
  }

  // Health check
  if (req.method === "GET" && pathname === "/health") {
    return new Response(JSON.stringify({ status: "ok" }), {
      headers: { ...corsHeaders, "content-type": "application/json" }
    });
  }

  return new Response("Not Found", { 
    status: 404,
    headers: corsHeaders
  });
});

console.log(`Cipher server running on http://localhost:${PORT}`);
```

### Running the Cipher Server

```bash
# Set required environment variables
export REMOTE_CIPHER_PASSWORD="your-secure-password-here"
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export PORT="8001"

# Run with Deno permissions
deno run --allow-net --allow-env --allow-read --allow-write cipher-server.ts
```

### Production Deployment

**Using systemd (Linux):**

Create `/etc/systemd/system/lavalink-cipher.service`:

```ini
[Unit]
Description=Lavalink Cipher Server
After=network.target

[Service]
Type=simple
User=lavalink
WorkingDirectory=/opt/lavalink/cipher
Environment=REMOTE_CIPHER_PASSWORD=your-password
Environment=GOOGLE_CLIENT_ID=your-client-id
Environment=GOOGLE_CLIENT_SECRET=your-client-secret
Environment=PORT=8001
ExecStart=/usr/bin/deno run --allow-net --allow-env --allow-read --allow-write cipher-server.ts
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Using Docker:**

Create `Dockerfile`:

```dockerfile
FROM denoland/deno:latest

WORKDIR /app

# Copy server file
COPY cipher-server.ts .

# Create data directory and set permissions
RUN mkdir -p /data && chown deno:deno /data

# Run as non-root user
USER deno

# Expose port
EXPOSE 8001

# Start server
CMD ["run", "--allow-net", "--allow-env", "--allow-read", "--allow-write", "cipher-server.ts"]
```

## Complete Lavalink Configuration

### application.yml

```yamllavalink:
    defaultPluginRepository: https://maven.lavalink.dev/releases
    defaultPluginSnapshotRepository: https://maven.lavalink.dev/snapshots
    plugins:
        - dependency: com.github.topi314.lavasrc:lavasrc-plugin:4.8.1
          snapshot: false
        - dependency: dev.lavalink.youtube:youtube-plugin:ff19b6f1751262ecba7b81fcf391b961008962d1
          snapshot: true
    pluginsDir: ./plugins
    server:
        bufferDurationMs: 400
        filters:
            channelMix: true
            distortion: true
            equalizer: true
            karaoke: true
            lowPass: true
            rotation: true
            timescale: true
            tremolo: true
            vibrato: true
            volume: true
        frameBufferDurationMs: 5000
        gc-warnings: true
        opusEncodingQuality: 10
        password: ""
        playerUpdateInterval: 5
        resamplingQuality: MEDIUM
        soundcloudSearchEnabled: true
        sources:
            bandcamp: true
            http: true
            local: true
            soundcloud: true
            spotify: true
            twitch: true
            vimeo: true
            youtube: false
        trackStuckThresholdMs: 10000
        useSeekGhosting: true
        youtubePlaylistLoadLimit: 6
        youtubeSearchEnabled: true

plugins:
    lavasrc:
        providers:
            - spotify
            - spsearch:%QUERY%
            - spsearch:%ISRC%
            - ytsearch:%ISRC%
            - ytsearch:%QUERY%
        sources:
            spotify: true
            youtube: true
        spotify:
            albumLoadLimit: 100
            clientId: ""
            clientSecret: ""
            countryCode: US
            market: US
            playlistLoadLimit: 100

    youtube:
        allowDirectPlaylistIds: true
        allowDirectVideoIds: true
        allowSearch: true
        clientOptions:
            TV:
                playback: true
                playlistLoading: false
                searching: false
                videoLoading: false
        clients:
            - TV
            - TVHTML5EMBEDDED
            - ANDROID_VR
            - WEB
            - MWEB
            - WEBEMBEDDED
            - MUSIC
            - ANDROID_MUSIC
            - IOS
        enabled: true
        oauth:
            enabled: true
            refreshToken: ""
            skipInitialization: true
        pot:
            token: ""
            visitorData: ""
        remoteCipher:
            url: https://cipher.kikkia.dev/api  # this is a public cipher API. To ensure guaranteed uptime, host your own.

server:
    address: 0.0.0.0
    http2:
        enabled: false
    port: 28523
```

## API Usage Examples

### Managing Cipher Server

**Store YouTube tokens:**
```bash
curl -X POST http://localhost:8001/youtube \
  -H "Authorization: Bearer your-remote-cipher-password" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "your-youtube-refresh-token",
    "poToken": "your-potoken-if-using",
    "visitorData": "your-visitor-data-if-using"
  }'
```

**Retrieve stored tokens:**
```bash
curl http://localhost:8001/youtube
```

**Exchange refresh token for access token:**
```bash
# URL encode the refresh token first
REFRESH_TOKEN_URL_ENCODED=$(echo "your-refresh-token" | jq -sRr @uri)

curl "http://localhost:8001/youtube/oauth/$REFRESH_TOKEN_URL_ENCODED"
```

**Health check:**
```bash
curl http://localhost:8001/health
```

### Testing Lavalink Connection

```bash
# Test Lavalink server
curl http://localhost:2333/v4/info \
  -H "Authorization: your-lavalink-password"

# Load a track
curl -X POST http://localhost:2333/v4/loadtracks?identifier=ytsearch:hello \
  -H "Authorization: your-lavalink-password" \
  -H "Content-Type: application/json"
```

## Security Best Practices

### 1. Secret Management

**Never store secrets in code:**
```bash
# Bad: Hardcoded secrets
password: "secret123"

# Good: Environment variables
password: "${LAVALINK_PASSWORD}"
```

**Use secret management:**
- HashiCorp Vault
- AWS Secrets Manager
- Kubernetes Secrets
- Docker Secrets

### 2. Network Security

**Firewall Configuration:**
```bash
# Only allow necessary ports
ufw allow 2333/tcp  # Lavalink
ufw allow 8001/tcp  # Cipher server (if external)
ufw allow 22/tcp    # SSH
ufw enable
```

**Reverse Proxy (Nginx):**
```nginx
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location /lavalink/ {
        proxy_pass http://localhost:2333/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Basic authentication
        auth_basic "Lavalink Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
    
    location /cipher/ {
        proxy_pass http://localhost:8001/;
        proxy_set_header Host $host;
        
        # IP restriction
        allow 10.0.0.0/8;
        allow 172.16.0.0/12;
        allow 192.168.0.0/16;
        deny all;
    }
}
```

### 3. Monitoring and Logging

**Set up monitoring:**
```yaml
# Prometheus metrics (if enabled)
metrics:
  prometheus:
    enabled: true
    endpoint: /metrics
```

**Log rotation:**
```bash
# Use logrotate for Lavalink logs
sudo nano /etc/logrotate.d/lavalink

# Content:
/opt/lavalink/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

## Troubleshooting

### Common Issues

1. **YouTube 403 Errors:**
   - Verify OAuth credentials
   - Check if YouTube Data API is enabled
   - Ensure refresh token is valid

2. **Spotify Track Loading Fails:**
   - Verify client ID and secret
   - Check Spotify app settings
   - Ensure correct redirect URI

3. **Cipher Server Connection Issues:**
   - Verify REMOTE_CIPHER_PASSWORD matches
   - Check firewall settings
   - Confirm cipher server is running

4. **Memory Issues:**
   ```bash
   # Increase memory for Java
   java -Xmx4G -jar Lavalink.jar
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```yaml
logging:
  level:
    root: DEBUG
    lavalink: DEBUG
    lavasrc: DEBUG
```

## Legal and Compliance Notes

- **YouTube Terms of Service:** Use official OAuth flows where possible
- **Spotify Developer Terms:** Adhere to rate limits and usage guidelines
- **Data Protection:** Store tokens securely and implement proper access controls
- **Rate Limiting:** Implement appropriate rate limiting for all APIs

## References

- [Lavalink Documentation](https://lavalink.dev/)
- [LavaSrc Plugin](https://github.com/topi314/LavaSrc)
- [YouTube Data API](https://developers.google.com/youtube/v3)
- [Spotify Web API](https://developer.spotify.com/documentation/web-api)
- [Deno Documentation](https://deno.land/manual)

## Support

For issues and questions:
1. Check Lavalink logs in `logs/` directory
2. Verify all environment variables are set
3. Ensure all services are running and accessible
4. Consult Lavalink Discord community for support

This configuration provides a complete setup for Lavalink with Spotify, YouTube, and remote cipher functionality while maintaining security best practices.
