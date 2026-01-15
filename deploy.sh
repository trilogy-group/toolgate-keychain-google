#!/bin/bash
set -e

echo "🚀 Deploying Google OAuth Connector Service with SAM..."

# Use profile only when running locally (not in CI)
if [ -z "$CI" ]; then
    AWS_PROFILE=${AWS_PROFILE:-tpm-pprod}
    PROFILE_ARG="--profile $AWS_PROFILE"
    echo "✓ Using AWS profile: $AWS_PROFILE"
else
    PROFILE_ARG=""
    echo "✓ Running in CI mode"
fi

# Build with SAM
echo ""
echo "🔨 Building Lambda function..."
sam build

# Note: JWT_SECRET no longer needed - using Google RS256 JWTs

# Deploy with SAM
echo ""
echo "🚀 Deploying to AWS..."
sam deploy \
    --stack-name toolgate-keychain-google-connector \
    --capabilities CAPABILITY_IAM \
    --region us-east-1 \
    $PROFILE_ARG \
    --resolve-s3 \
    --no-confirm-changeset \
    --no-fail-on-empty-changeset

echo ""
echo "✅ Deployment complete!"
echo ""
echo "🌐 Service URL: https://google.toolgate.dev"
echo ""
echo "📝 Endpoints:"
echo "   POST /connect       - Initiate OAuth (requires JWT)"
echo "   GET  /session/{id}  - Poll for auth status"
echo "   GET  /credentials   - Get access token (requires JWT)"
echo "   POST /disconnect    - Clear session (requires JWT)"
echo "   GET  /health        - Health check"
echo "   GET  /info          - API documentation"
echo ""
echo "📖 Usage:"
echo ""
echo "   # 1. Get JWT from jwt.toolgate.dev first"
echo "   JWT=\$(curl -s https://jwt.toolgate.dev/code?code=XXXXXX | jq -r '.jwt')"
echo ""
echo "   # 2. Initiate Google OAuth"
echo "   curl -X POST https://google.toolgate.dev/connect \\"
echo "     -H 'Authorization: Bearer \$JWT' \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"scopes\": [\"docs\", \"sheets\", \"drive\"]}'"
echo ""
echo "   # 3. Open authUrl in browser, complete OAuth"
echo ""
echo "   # 4. Get access token"
echo "   curl https://google.toolgate.dev/credentials \\"
echo "     -H 'Authorization: Bearer \$JWT'"
echo ""
echo "   # 5. Use token with Google APIs"
echo "   ACCESS_TOKEN=\$(curl -s ... | jq -r '.access_token')"
echo "   curl https://docs.googleapis.com/v1/documents/{docId} \\"
echo "     -H 'Authorization: Bearer \$ACCESS_TOKEN'"
echo ""

# Self-register with the tool registry
echo "Registering connector with registry..."
curl -s -X POST "https://tools.toolgate.dev/tools/register" \
    -H "Content-Type: application/json" \
    -d @tool-config.json || echo "Warning: Registry registration failed (non-blocking)"
echo ""
echo "✅ Deployment and registration complete!"
