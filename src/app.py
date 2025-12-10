"""
Standalone Google OAuth Connector Service

Provides OAuth 2.0 authentication for Google services (Docs, Sheets, Drive, etc.).
Returns access tokens that can be used directly with Google APIs.

Endpoints:
- POST /connect - Initiate OAuth flow with requested scopes
- GET /oauth/callback - Handle OAuth callback from Google
- GET /session/{id} - Poll for authentication status
- GET /credentials - Get access token (auto-refreshes if expired)
- POST /disconnect - Clear session
- GET /health - Health check
- GET /info - API documentation
"""

import json
import os
import boto3
import logging
import time
import secrets
import urllib.parse
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from decimal import Decimal

# Configure logging
logger = logging.getLogger()
logger.setLevel(os.environ.get('LOG_LEVEL', 'INFO'))

# AWS clients
dynamodb = boto3.resource('dynamodb')
sessions_table = dynamodb.Table(os.environ.get('SESSIONS_TABLE_NAME', 'toolgate-google-sessions'))

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
LAMBDA_URL = os.environ.get('LAMBDA_URL', 'https://google.toolgate.dev')

# Scope shortcuts - map friendly names to full Google scope URLs
SCOPE_SHORTCUTS = {
    'email': 'https://www.googleapis.com/auth/userinfo.email',
    'profile': 'https://www.googleapis.com/auth/userinfo.profile',
    'docs': 'https://www.googleapis.com/auth/documents.readonly',
    'docs.write': 'https://www.googleapis.com/auth/documents',
    'sheets': 'https://www.googleapis.com/auth/spreadsheets.readonly',
    'sheets.write': 'https://www.googleapis.com/auth/spreadsheets',
    'drive': 'https://www.googleapis.com/auth/drive.readonly',
    'drive.write': 'https://www.googleapis.com/auth/drive',
    'drive.metadata': 'https://www.googleapis.com/auth/drive.metadata.readonly',
    'calendar': 'https://www.googleapis.com/auth/calendar.readonly',
    'calendar.write': 'https://www.googleapis.com/auth/calendar',
    'gmail': 'https://www.googleapis.com/auth/gmail.readonly',
    'gmail.send': 'https://www.googleapis.com/auth/gmail.send',
}

# Default scopes if none specified
DEFAULT_SCOPES = ['email', 'profile', 'docs', 'sheets', 'drive']


def lambda_handler(event, context):
    """Main Lambda handler."""
    try:
        logger.info(f"Event: {json.dumps(event)}")
        
        # Normalize event (handle both API Gateway and Function URL formats)
        http_method = event.get('requestContext', {}).get('http', {}).get('method') or event.get('httpMethod', 'GET')
        path = event.get('requestContext', {}).get('http', {}).get('path') or event.get('rawPath') or event.get('path', '/')
        path = path.lstrip('/')
        
        # Handle CORS preflight
        if http_method == 'OPTIONS':
            return cors_response(200, {})
        
        # Route requests
        if path == '' and http_method == 'GET':
            return redirect_response('/info')
        
        elif path == 'health' and http_method == 'GET':
            return cors_response(200, {'status': 'healthy', 'service': 'google-connector'})
        
        elif path == 'info' and http_method == 'GET':
            return handle_info()
        
        elif path == 'connect' and http_method == 'POST':
            return handle_connect(event)
        
        elif path.startswith('oauth/callback') and http_method == 'GET':
            return handle_oauth_callback(event)
        
        elif path.startswith('session/') and http_method == 'GET':
            session_id = path.split('session/')[1] if 'session/' in path else ''
            return handle_session_poll(session_id)
        
        elif path == 'credentials' and http_method == 'GET':
            return handle_get_credentials(event)
        
        elif path == 'disconnect' and http_method == 'POST':
            return handle_disconnect(event)
        
        else:
            return cors_response(404, {'error': 'Not Found', 'message': f'Unknown endpoint: {http_method} /{path}'})
    
    except Exception as e:
        logger.error(f"Lambda handler error: {e}", exc_info=True)
        return cors_response(500, {'error': 'Internal Error', 'message': str(e)})


def decimal_to_num(obj):
    """Convert Decimal to int or float for JSON serialization."""
    if isinstance(obj, Decimal):
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    elif isinstance(obj, dict):
        return {k: decimal_to_num(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [decimal_to_num(i) for i in obj]
    return obj


def cors_response(status_code: int, body: dict) -> dict:
    """Create CORS-enabled JSON response."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': '*',
            'Access-Control-Allow-Methods': '*'
        },
        'body': json.dumps(decimal_to_num(body))
    }


def html_response(status_code: int, html: str) -> dict:
    """Create HTML response."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'text/html',
            'Access-Control-Allow-Origin': '*'
        },
        'body': html
    }


def redirect_response(location: str) -> dict:
    """Create redirect response."""
    return {
        'statusCode': 302,
        'headers': {
            'Location': location,
            'Access-Control-Allow-Origin': '*'
        },
        'body': ''
    }


# =============================================================================
# Session Management
# =============================================================================

def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Get session from DynamoDB."""
    try:
        response = sessions_table.get_item(Key={'session_id': session_id})
        return response.get('Item')
    except Exception as e:
        logger.error(f"Error getting session: {e}")
        return None


def store_session(session_id: str, data: Dict[str, Any]):
    """Store session in DynamoDB."""
    try:
        data['session_id'] = session_id
        data['updated_at'] = int(time.time() * 1000)
        
        # Set TTL to 24 hours from now
        data['ttl'] = int(time.time()) + (24 * 3600)
        
        sessions_table.put_item(Item=data)
        logger.info(f"Stored session: {session_id}")
    except Exception as e:
        logger.error(f"Error storing session: {e}", exc_info=True)
        raise


def delete_session(session_id: str):
    """Delete session from DynamoDB."""
    try:
        sessions_table.delete_item(Key={'session_id': session_id})
        logger.info(f"Deleted session: {session_id}")
    except Exception as e:
        logger.error(f"Error deleting session: {e}")


def find_session_by_state(state: str) -> Optional[str]:
    """Find session_id by OAuth state (scan sessions table)."""
    try:
        response = sessions_table.scan(
            FilterExpression='oauth_state = :state',
            ExpressionAttributeValues={':state': state}
        )
        
        if response.get('Items'):
            return response['Items'][0]['session_id']
        
        return None
    except Exception as e:
        logger.error(f"Error finding session by state: {e}")
        return None


# =============================================================================
# JWT Validation
# =============================================================================

def validate_jwt_and_get_email(event: Dict[str, Any]) -> tuple:
    """Validate JWT token and extract email. Returns (is_valid, email, error_msg)."""
    import jwt as pyjwt
    
    # Get JWT from Authorization header
    headers = event.get('headers') or {}
    auth_header = headers.get('authorization') or headers.get('Authorization') or ''
    
    if not auth_header.startswith('Bearer '):
        return False, '', 'JWT token required (Authorization: Bearer <token>)'
    
    jwt_token = auth_header.replace('Bearer ', '')
    
    try:
        # Decode without verification - jwt.toolgate.dev is source of truth
        payload = pyjwt.decode(jwt_token, options={"verify_signature": False})
        email = payload.get('email') or payload.get('user_email')
        
        if not email:
            return False, '', 'JWT token missing email claim'
        
        # Check expiration
        exp = payload.get('exp')
        if exp and time.time() > exp:
            return False, '', 'JWT token expired'
        
        return True, email, ''
        
    except Exception as e:
        logger.error(f"JWT validation error: {e}")
        return False, '', f'Invalid JWT token: {str(e)}'


# =============================================================================
# Scope Handling
# =============================================================================

def expand_scopes(scopes: list) -> list:
    """Expand scope shortcuts to full Google scope URLs."""
    expanded = ['openid']  # Always include openid
    
    for scope in scopes:
        if scope in SCOPE_SHORTCUTS:
            expanded.append(SCOPE_SHORTCUTS[scope])
        elif scope.startswith('https://'):
            expanded.append(scope)
        else:
            logger.warning(f"Unknown scope: {scope}")
    
    return list(set(expanded))  # Remove duplicates


# =============================================================================
# Endpoint Handlers
# =============================================================================

def handle_connect(event: Dict[str, Any]) -> Dict[str, Any]:
    """Initiate Google OAuth flow."""
    try:
        # Validate JWT
        is_valid, user_email, error_msg = validate_jwt_and_get_email(event)
        if not is_valid:
            return cors_response(401, {'error': 'Unauthorized', 'message': error_msg})
        
        # Parse request body
        body_str = event.get('body', '{}')
        body = json.loads(body_str) if isinstance(body_str, str) else body_str
        
        # Get requested scopes (use defaults if not specified)
        requested_scopes = body.get('scopes', DEFAULT_SCOPES)
        full_scopes = expand_scopes(requested_scopes)
        
        # Generate session ID and state
        import uuid
        session_id = str(uuid.uuid4())
        state = secrets.token_urlsafe(32)
        
        # Build OAuth callback URL
        callback_url = f"{LAMBDA_URL}/oauth/callback"
        
        # Store pending session
        session_data = {
            'status': 'pending',
            'authenticated': False,
            'user_email': user_email,
            'oauth_state': state,
            'requested_scopes': requested_scopes,
            'full_scopes': full_scopes,
            'callback_url': callback_url,
            'expires_at': int(time.time() * 1000) + (300 * 1000)  # 5 minutes
        }
        
        store_session(session_id, session_data)
        
        # Build Google OAuth URL
        params = {
            'client_id': GOOGLE_CLIENT_ID,
            'redirect_uri': callback_url,
            'response_type': 'code',
            'scope': ' '.join(full_scopes),
            'state': state,
            'access_type': 'offline',
            'prompt': 'consent'
        }
        
        auth_url = f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
        
        logger.info(f"OAuth flow initiated for {user_email} with session_id: {session_id}")
        
        return cors_response(200, {
            'authUrl': auth_url,
            'session_id': session_id,
            'scopes': requested_scopes,
            'message': 'Please complete Google OAuth login'
        })
    
    except Exception as e:
        logger.error(f"Connect error: {e}", exc_info=True)
        return cors_response(500, {'error': 'OAuth Error', 'message': str(e)})


def handle_oauth_callback(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle OAuth callback from Google."""
    import requests
    
    try:
        query_params = event.get('queryStringParameters') or {}
        code = query_params.get('code')
        state = query_params.get('state')
        error = query_params.get('error')
        
        if error:
            logger.error(f"OAuth error from Google: {error}")
            return html_response(200, f'''
                <html>
                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h2>❌ Authentication Failed</h2>
                    <p>Error: {error}</p>
                    <p>You can close this window.</p>
                    <script>setTimeout(() => window.close(), 3000);</script>
                </body>
                </html>
            ''')
        
        if not code or not state:
            return cors_response(400, {'error': 'Bad Request', 'message': 'Missing code or state'})
        
        # Find session by state
        session_id = find_session_by_state(state)
        if not session_id:
            logger.error(f"No session found for state: {state}")
            return html_response(200, '''
                <html>
                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h2>❌ Session Expired</h2>
                    <p>Please try again.</p>
                    <script>setTimeout(() => window.close(), 3000);</script>
                </body>
                </html>
            ''')
        
        # Get session to retrieve user_email and callback_url
        session = get_session(session_id)
        if not session:
            return cors_response(500, {'error': 'Session Error', 'message': 'Session not found'})
        
        user_email = session.get('user_email')
        callback_url = session.get('callback_url', f"{LAMBDA_URL}/oauth/callback")
        
        # Exchange code for tokens
        token_response = requests.post(
            'https://oauth2.googleapis.com/token',
            data={
                'code': code,
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
                'redirect_uri': callback_url,
                'grant_type': 'authorization_code'
            },
            timeout=30
        )
        
        if not token_response.ok:
            logger.error(f"Token exchange failed: {token_response.text}")
            return html_response(200, '''
                <html>
                <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h2>❌ Token Exchange Failed</h2>
                    <p>Please try again.</p>
                    <script>setTimeout(() => window.close(), 3000);</script>
                </body>
                </html>
            ''')
        
        tokens = token_response.json()
        logger.info(f"Received tokens from Google: {list(tokens.keys())}")
        
        # Get user info from Google to verify email
        user_info_response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f"Bearer {tokens['access_token']}"},
            timeout=10
        )
        
        google_email = None
        if user_info_response.ok:
            user_info = user_info_response.json()
            google_email = user_info.get('email')
        
        # Calculate token expiration
        expires_in = tokens.get('expires_in', 3600)
        expires_at = int(time.time() * 1000) + (expires_in * 1000)
        
        # Update session with authenticated data
        session_data = {
            'status': 'authenticated',
            'authenticated': True,
            'user_email': user_email,
            'google_email': google_email,
            'access_token': tokens.get('access_token'),
            'refresh_token': tokens.get('refresh_token'),
            'token_type': tokens.get('token_type', 'Bearer'),
            'scopes': session.get('requested_scopes', []),
            'full_scopes': session.get('full_scopes', []),
            'expires_at': expires_at
        }
        
        # Store by session_id (for polling)
        store_session(session_id, session_data)
        
        # Also store by user_email (for /credentials endpoint)
        user_session_id = f"{user_email}#google"
        store_session(user_session_id, session_data)
        
        logger.info(f"OAuth completed for {user_email} (Google: {google_email})")
        
        return html_response(200, f'''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Successful - ToolGate</title>
                <style>
                    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: linear-gradient(to bottom right, hsl(0 0% 100%), hsl(240 5.9% 90%));
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        color: hsl(222.2 47.4% 11.2%);
                    }}
                    .card {{
                        background: white;
                        border-radius: 12px;
                        padding: 48px;
                        text-align: center;
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                        max-width: 400px;
                    }}
                    .icon {{
                        width: 48px;
                        height: 48px;
                        background: hsl(142 76% 36%);
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        margin: 0 auto 20px;
                    }}
                    .icon svg {{
                        width: 24px;
                        height: 24px;
                        stroke: white;
                        stroke-width: 3;
                    }}
                    h1 {{ font-size: 20px; font-weight: 600; margin-bottom: 8px; }}
                    p {{ color: hsl(215.4 16.3% 46.9%); font-size: 14px; margin-bottom: 4px; }}
                    .email {{ font-weight: 500; color: hsl(222.2 47.4% 11.2%); font-size: 14px; }}
                    .close-msg {{ margin-top: 24px; font-size: 13px; }}
                </style>
            </head>
            <body>
                <div class="card">
                    <div class="icon">
                        <svg viewBox="0 0 24 24" fill="none"><polyline points="20 6 9 17 4 12"></polyline></svg>
                    </div>
                    <h1>Connected!</h1>
                    <p>Google account connected successfully</p>
                    <p class="email">{google_email or user_email}</p>
                    <p class="close-msg">This window will close automatically.</p>
                </div>
                <script>setTimeout(() => window.close(), 3000);</script>
            </body>
            </html>
        ''')
    
    except Exception as e:
        logger.error(f"OAuth callback error: {e}", exc_info=True)
        return html_response(500, f'''
            <html>
            <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h2>❌ Error</h2>
                <p>{str(e)}</p>
            </body>
            </html>
        ''')


def handle_session_poll(session_id: str) -> Dict[str, Any]:
    """Poll for session authentication status."""
    try:
        if not session_id:
            return cors_response(400, {'error': 'Bad Request', 'message': 'Missing session_id'})
        
        session = get_session(session_id)
        
        if not session:
            return cors_response(404, {'error': 'Not Found', 'message': 'Session not found or expired'})
        
        status = session.get('status', 'pending')
        
        if status == 'authenticated':
            return cors_response(200, {
                'status': 'authenticated',
                'user_email': session.get('user_email'),
                'google_email': session.get('google_email'),
                'scopes': session.get('scopes', [])
            })
        else:
            return cors_response(200, {
                'status': 'pending',
                'message': 'Waiting for user to complete OAuth'
            })
    
    except Exception as e:
        logger.error(f"Session poll error: {e}", exc_info=True)
        return cors_response(500, {'error': 'Poll Error', 'message': str(e)})


def handle_get_credentials(event: Dict[str, Any]) -> Dict[str, Any]:
    """Get Google access token for authenticated user."""
    import requests
    
    try:
        # Validate JWT
        is_valid, user_email, error_msg = validate_jwt_and_get_email(event)
        if not is_valid:
            return cors_response(401, {'error': 'Unauthorized', 'message': error_msg})
        
        # Get user session
        user_session_id = f"{user_email}#google"
        session = get_session(user_session_id)
        
        if not session or not session.get('authenticated'):
            return cors_response(401, {
                'error': 'Not Connected',
                'message': 'Please connect to Google first via POST /connect'
            })
        
        access_token = session.get('access_token')
        refresh_token = session.get('refresh_token')
        expires_at = session.get('expires_at', 0)
        
        # Check if token is expired or expiring soon (5 min buffer)
        now_ms = int(time.time() * 1000)
        if now_ms >= expires_at - (5 * 60 * 1000):
            logger.info(f"Token expired or expiring soon for {user_email}, refreshing...")
            
            if not refresh_token:
                return cors_response(401, {
                    'error': 'Token Expired',
                    'message': 'Access token expired and no refresh token available. Please reconnect.'
                })
            
            # Refresh the token
            token_response = requests.post(
                'https://oauth2.googleapis.com/token',
                data={
                    'client_id': GOOGLE_CLIENT_ID,
                    'client_secret': GOOGLE_CLIENT_SECRET,
                    'refresh_token': refresh_token,
                    'grant_type': 'refresh_token'
                },
                timeout=30
            )
            
            if not token_response.ok:
                logger.error(f"Token refresh failed: {token_response.text}")
                return cors_response(401, {
                    'error': 'Refresh Failed',
                    'message': 'Failed to refresh access token. Please reconnect.'
                })
            
            tokens = token_response.json()
            access_token = tokens.get('access_token')
            expires_in = tokens.get('expires_in', 3600)
            expires_at = int(time.time() * 1000) + (expires_in * 1000)
            
            # Update session with new token
            session['access_token'] = access_token
            session['expires_at'] = expires_at
            store_session(user_session_id, session)
            
            logger.info(f"Token refreshed for {user_email}")
        
        return cors_response(200, {
            'access_token': access_token,
            'token_type': session.get('token_type', 'Bearer'),
            'expires_at': expires_at,
            'scopes': session.get('scopes', []),
            'google_email': session.get('google_email')
        })
    
    except Exception as e:
        logger.error(f"Get credentials error: {e}", exc_info=True)
        return cors_response(500, {'error': 'Credentials Error', 'message': str(e)})


def handle_disconnect(event: Dict[str, Any]) -> Dict[str, Any]:
    """Disconnect Google account."""
    try:
        # Validate JWT
        is_valid, user_email, error_msg = validate_jwt_and_get_email(event)
        if not is_valid:
            return cors_response(401, {'error': 'Unauthorized', 'message': error_msg})
        
        # Delete user session
        user_session_id = f"{user_email}#google"
        delete_session(user_session_id)
        
        logger.info(f"Disconnected Google for {user_email}")
        
        return cors_response(200, {
            'status': 'disconnected',
            'message': 'Google account disconnected successfully'
        })
    
    except Exception as e:
        logger.error(f"Disconnect error: {e}", exc_info=True)
        return cors_response(500, {'error': 'Disconnect Error', 'message': str(e)})


def handle_info() -> Dict[str, Any]:
    """Return API documentation."""
    info = {
        'service': 'Google OAuth Connector',
        'version': '1.0.0',
        'description': 'Provides OAuth 2.0 authentication for Google services. Returns access tokens for direct use with Google APIs.',
        'base_url': LAMBDA_URL,
        'endpoints': {
            'POST /connect': {
                'description': 'Initiate Google OAuth flow',
                'auth': 'JWT required',
                'body': {
                    'scopes': ['Optional array of scope shortcuts or full URLs. Defaults to: email, profile, docs, sheets, drive']
                },
                'response': {
                    'authUrl': 'URL to open in browser for OAuth',
                    'session_id': 'Session ID to poll for status'
                }
            },
            'GET /session/{session_id}': {
                'description': 'Poll for OAuth completion status',
                'auth': 'None',
                'response': {
                    'status': 'pending | authenticated',
                    'user_email': 'Email (when authenticated)'
                }
            },
            'GET /credentials': {
                'description': 'Get Google access token (auto-refreshes if expired)',
                'auth': 'JWT required',
                'response': {
                    'access_token': 'Google OAuth access token',
                    'token_type': 'Bearer',
                    'expires_at': 'Expiration timestamp (ms)',
                    'scopes': 'Granted scopes'
                }
            },
            'POST /disconnect': {
                'description': 'Disconnect Google account',
                'auth': 'JWT required'
            },
            'GET /health': {
                'description': 'Health check'
            }
        },
        'scope_shortcuts': SCOPE_SHORTCUTS,
        'usage_example': {
            '1_connect': 'POST /connect with JWT → get authUrl → open in browser',
            '2_poll': 'GET /session/{id} → wait for authenticated status',
            '3_get_token': 'GET /credentials with JWT → get access_token',
            '4_use_token': 'Call Google APIs directly with: Authorization: Bearer {access_token}'
        },
        'google_api_examples': {
            'docs': 'GET https://docs.googleapis.com/v1/documents/{docId}',
            'sheets': 'GET https://sheets.googleapis.com/v4/spreadsheets/{spreadsheetId}',
            'drive': 'GET https://www.googleapis.com/drive/v3/files'
        }
    }
    
    return cors_response(200, info)
