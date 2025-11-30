# Standalone Google OAuth Connector Service

Provides OAuth 2.0 authentication for Google services (Docs, Sheets, Drive, etc.).
Returns access tokens that can be used directly with Google APIs.

## Features

- 🔐 **JWT Authentication** - Integrated with jwt.toolgate.dev
- 🎫 **Google OAuth 2.0** - Full OAuth flow with refresh token support
- 📋 **Flexible Scopes** - Request only the permissions you need
- 🔄 **Auto-Refresh** - Tokens automatically refreshed when expired
- 💾 **Session Management** - DynamoDB-backed sessions with 24-hour TTL
- 🌐 **Custom Domain** - Deployed at `https://google.toolgate.dev`
- ⚡ **Fast** - Serverless architecture with API Gateway + Lambda

## Architecture

```
User → google.toolgate.dev (API Gateway)
     → Lambda Function
     → Google OAuth
     → DynamoDB (toolgate-google-sessions)
     → Return Access Token
```

## Endpoints

### POST /connect

Initiate Google OAuth flow.

**Headers:**
- `Authorization: Bearer <jwt>` (from jwt.toolgate.dev)

**Body:**
```json
{
  "scopes": ["docs", "sheets", "drive"]
}
```

**Response:**
```json
{
  "authUrl": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "session_id": "uuid",
  "scopes": ["docs", "sheets", "drive"],
  "message": "Please complete Google OAuth login"
}
```

### GET /session/{session_id}

Poll for OAuth completion status.

**Response (pending):**
```json
{
  "status": "pending",
  "message": "Waiting for user to complete OAuth"
}
```

**Response (authenticated):**
```json
{
  "status": "authenticated",
  "user_email": "user@example.com",
  "google_email": "user@gmail.com",
  "scopes": ["docs", "sheets", "drive"]
}
```

### GET /credentials

Get Google access token (auto-refreshes if expired).

**Headers:**
- `Authorization: Bearer <jwt>`

**Response:**
```json
{
  "access_token": "ya29.a0AfH6SM...",
  "token_type": "Bearer",
  "expires_at": 1701234567000,
  "scopes": ["docs", "sheets", "drive"],
  "google_email": "user@gmail.com"
}
```

### POST /disconnect

Disconnect Google account.

**Headers:**
- `Authorization: Bearer <jwt>`

### GET /health

Health check.

### GET /info

API documentation.

## Scope Shortcuts

| Shortcut | Full Scope |
|----------|-----------|
| `email` | `userinfo.email` |
| `profile` | `userinfo.profile` |
| `docs` | `documents.readonly` |
| `docs.write` | `documents` |
| `sheets` | `spreadsheets.readonly` |
| `sheets.write` | `spreadsheets` |
| `drive` | `drive.readonly` |
| `drive.write` | `drive` |
| `calendar` | `calendar.readonly` |
| `gmail` | `gmail.readonly` |

Or pass full scope URLs directly.

## Usage Flow

### 1. Get JWT from jwt.toolgate.dev

```bash
# Login via browser, get one-time code, exchange for JWT
JWT=$(curl -s "https://jwt.toolgate.dev/code?code=XXXXXX" | jq -r '.jwt')
```

### 2. Initiate Google OAuth

```bash
curl -X POST https://google.toolgate.dev/connect \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"scopes": ["docs", "sheets", "drive"]}'
```

### 3. Complete OAuth in Browser

Open the `authUrl` from the response in your browser and authorize.

### 4. Poll for Completion (optional)

```bash
curl "https://google.toolgate.dev/session/$SESSION_ID"
```

### 5. Get Access Token

```bash
curl https://google.toolgate.dev/credentials \
  -H "Authorization: Bearer $JWT"
```

### 6. Use Token with Google APIs

```bash
ACCESS_TOKEN=$(curl -s ... | jq -r '.access_token')

# Google Docs
curl "https://docs.googleapis.com/v1/documents/$DOC_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Google Sheets
curl "https://sheets.googleapis.com/v4/spreadsheets/$SHEET_ID" \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Google Drive
curl "https://www.googleapis.com/drive/v3/files" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Deployment

### Prerequisites

1. **Google OAuth Credentials** in AWS Secrets Manager:
   ```bash
   aws secretsmanager create-secret \
     --name toolgate/google-oauth \
     --secret-string '{"client_id":"YOUR_CLIENT_ID","client_secret":"YOUR_CLIENT_SECRET"}' \
     --profile tpm-pprod --region us-east-1
   ```

2. **Add OAuth Redirect URI** in Google Console:
   - Go to: https://console.cloud.google.com/apis/credentials
   - Edit your OAuth client
   - Add redirect URI: `https://google.toolgate.dev/oauth/callback`

### Deploy

```bash
cd /Users/dschwartz/Dropbox/cc/toolgate/google
AWS_PROFILE=tpm-pprod ./deploy.sh
```

## Stack Resources

- **Lambda**: `toolgate-google-connector`
- **DynamoDB**: `toolgate-google-sessions`
- **API Gateway**: `google.toolgate.dev`
- **CloudFormation Stack**: `GoogleConnectorStack`

## Monitoring

```bash
# View logs
aws logs tail /aws/lambda/toolgate-google-connector \
  --follow --profile tpm-pprod --region us-east-1
```

## Troubleshooting

**"Not Connected" error:**
- Call `/connect` first to initiate OAuth
- Complete the OAuth flow in browser

**"Token Expired" error:**
- If refresh fails, reconnect via `/connect`

**OAuth redirect error:**
- Verify redirect URI in Google Console matches exactly

## Clean Up

```bash
aws cloudformation delete-stack \
  --stack-name GoogleConnectorStack \
  --profile tpm-pprod --region us-east-1
```
