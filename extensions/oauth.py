from authlib.integrations.flask_client import OAuth
import os
from dotenv import load_dotenv

load_dotenv()

oauth = OAuth()

github = oauth.register(
    name='github',
    client_id=os.getenv('GITHUB_OAUTH_CLIENT_ID'),
    client_secret=os.getenv('GITHUB_OAUTH_CLIENT_SECRET'),
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    api_base_url='https://api.github.com/',
    client_kwargs={
        'scope': 'read:user user:email',
        # For fine-grained apps or GitHub apps, enable refresh tokens:
        'token_endpoint_auth_method': 'client_secret_post',
    },
)