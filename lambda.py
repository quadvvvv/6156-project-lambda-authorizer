import json
import jwt

def lambda_handler(event, context):
    # Extract the authorization token from the request headers using get
    authorization_header = event.get('headers', {}).get('Authorization')

    # Check if the Authorization header is present
    if not authorization_header:
        return generate_policy('user', 'Deny', '/*')

    # Extract the token from the Authorization header
    print(token)
    token = authorization_header.split(' ')[-1]

    # Validate the token
    try:
        # Decode the token using the provided secret
        decoded = jwt.decode(token, 'secrettogethired', algorithms=['HS256'])
        print("hello from lambda")
        # If the token is valid, allow the request
        return generate_policy('user', 'Allow', '/init_testing/*')
    except jwt.InvalidTokenError:
        # Token is invalid
        print("not hello from lambda")
        return generate_policy('user', 'Deny', '/init_testing/*')

def generate_policy(principal_id, effect, resource):
    # Generate an IAM policy for the Lambda authorizer
    policy = {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': resource
                }
            ]
        }
    }
    return policy
