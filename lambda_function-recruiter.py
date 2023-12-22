import json
import jwt

def lambda_handler(event, context):
    # Retrieve the token from the Authorization header
    token = event['authorizationToken']

    # Dummy secret key
    secret_key = 'secretToRecruiting'

    try:
        # Decode and verify the JWT
        decoded_token = jwt.decode(token, secret_key, algorithms=['HS256'])

        # If the token is valid, generate an IAM policy allowing the request
        policy = generate_policy(decoded_token['username'], 'Allow', event['methodArn'])
        return policy
    except jwt.InvalidTokenError:
        policy = generate_policy('None', 'Deny', event['methodArn'])
        return policy
    except Exception as e:
        policy = generate_policy('None', 'Deny', event['methodArn'])
        return policy
        
def generate_policy(principal_id, effect, resource):
    auth_response = {
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
    return auth_response
