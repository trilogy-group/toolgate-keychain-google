"""
Tests for Google OAuth Connector Service Lambda Handler.
"""
import json
import pytest
from unittest.mock import Mock, patch, MagicMock
import os
import sys

os.environ['SESSIONS_TABLE_NAME'] = 'test-google-sessions'
os.environ['LOG_LEVEL'] = 'DEBUG'
os.environ['GOOGLE_CLIENT_ID'] = 'test-client-id'
os.environ['GOOGLE_CLIENT_SECRET'] = 'test-client-secret'
os.environ['LAMBDA_URL'] = 'https://test.example.com'


class TestGoogleConnector:
    """Tests for Google OAuth Connector functions."""
    
    @pytest.fixture
    def mock_aws(self):
        with patch('boto3.resource') as mock_resource:
            mock_ddb = MagicMock()
            mock_table = MagicMock()
            mock_ddb.Table.return_value = mock_table
            mock_resource.return_value = mock_ddb
            yield {'ddb': mock_ddb, 'table': mock_table}
    
    def test_module_imports(self, mock_aws):
        """Test module can be imported."""
        import src.app
        assert src.app is not None
    
    def test_scope_shortcuts_defined(self, mock_aws):
        """Test scope shortcuts are defined."""
        from src.app import SCOPE_SHORTCUTS
        
        assert 'email' in SCOPE_SHORTCUTS
        assert 'docs' in SCOPE_SHORTCUTS
        assert 'sheets' in SCOPE_SHORTCUTS
        assert 'drive' in SCOPE_SHORTCUTS
        assert 'calendar' in SCOPE_SHORTCUTS
        assert 'gmail' in SCOPE_SHORTCUTS
        assert 'chat' in SCOPE_SHORTCUTS
    
    def test_default_scopes(self, mock_aws):
        """Test default scopes are defined."""
        from src.app import DEFAULT_SCOPES
        
        assert 'email' in DEFAULT_SCOPES
        assert 'profile' in DEFAULT_SCOPES
    
    def test_lambda_handler_options(self, mock_aws):
        """Test CORS preflight."""
        from src.app import lambda_handler
        
        event = {
            'requestContext': {'http': {'method': 'OPTIONS', 'path': '/'}},
            'rawPath': '/'
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 200
        assert 'Access-Control-Allow-Origin' in result['headers']
    
    def test_lambda_handler_health(self, mock_aws):
        """Test health endpoint."""
        from src.app import lambda_handler
        
        event = {
            'requestContext': {'http': {'method': 'GET', 'path': '/health'}},
            'rawPath': '/health'
        }
        
        result = lambda_handler(event, {})
        
        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['status'] == 'ok'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
