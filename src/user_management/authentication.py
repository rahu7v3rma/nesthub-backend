from rest_framework.authentication import TokenAuthentication

from user_management.models import CustomToken


class CustomTokenAuthentication(TokenAuthentication):
    def authenticate(self, request):
        print('Authorization Header:', request.headers.get('X-Authorization'))
        token_key = request.headers.get('X-Authorization', '').split(' ')[
            -1
        ]  # Extract token key from header

        # Look up the token in your custom Token model
        token = CustomToken.objects.filter(key=token_key).first()

        if not token:
            print('Authentication failed: Token is invalid or missing.')
            return None

        print(f'Authentication successful: User={token.user}, Token={token.key}')
        return (token.user, token)
