# Lambda Authorizers for API Authentication

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![AWS Lambda](https://img.shields.io/badge/AWS%20Lambda-FF9900?style=for-the-badge&logo=aws-lambda&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=json-web-tokens&logoColor=white)

This repository contains AWS Lambda authorizers for API authentication using JSON Web Tokens (JWT).

## Project Structure

```
Lambda-Authorizers/
├── admin_authorizer.py
├── newuser_authorizer.py
├── recruiter_authorizer.py
└── base_authorizer.py
```

## Features

- JWT token validation
- Generation of IAM policies based on token validity
- Role-specific secret keys
- Designed for use with AWS API Gateway

## Tech Stack

- 🐍 Python
- 🔐 PyJWT
- ☁️ AWS Lambda

## Authorizers

1. **Admin Authorizer** (`admin_authorizer.py`)
   - Secret Key: 'allmighty'

2. **New User Authorizer** (`newuser_authorizer.py`)
   - Secret Key: 'secretToGetHired'

3. **Recruiter Authorizer** (`recruiter_authorizer.py`)
   - Secret Key: 'secretToRecruiting'

4. **Base Authorizer** (`base_authorizer.py`)
   - Secret Key: 'goodLuck'

## Functionality

Each authorizer follows this general flow:

1. Retrieves the JWT token from the Authorization header
2. Decodes and verifies the token using a role-specific secret key
3. Generates an "Allow" policy if the token is valid, or a "Deny" policy if it's invalid

## Usage

These authorizers can be attached to different API Gateway routes to enforce role-based access control. Here's a general guide on how to use them:

1. Deploy each authorizer function to AWS Lambda
2. In API Gateway, create a new authorizer for each Lambda function
3. Attach the appropriate authorizer to each route in your API

For example, you might use the admin authorizer for sensitive admin-only routes, the recruiter authorizer for recruiter-specific functionality, and so on.

## Deployment

To deploy these authorizers:

1. Ensure you have the AWS CLI configured with appropriate credentials
2. For each authorizer, create a deployment package:
   ```
   zip -r authorizer.zip authorizer_name.py
   ```
3. Deploy to AWS Lambda:
   ```
   aws lambda create-function --function-name authorizer-name \
       --zip-file fileb://authorizer.zip --handler authorizer_name.lambda_handler \
       --runtime python3.8 --role arn:aws:iam::your-account-id:role/your-lambda-role
   ```

## Security Note

🔒 Important security considerations:

- The secret keys in this code are for demonstration purposes only. In a production environment, use AWS Secrets Manager or similar service to securely store and retrieve these keys.
- Ensure that your Lambda functions have the minimum required permissions.
- Regularly rotate your JWT secret keys.
- Consider implementing additional security measures such as token expiration and audience validation.

## Additional Notes

- These authorizers are part of a larger application ecosystem. Ensure that the JWT tokens generated by your authentication service match the expected format and encryption method used in these authorizers.
- Regular security audits of these authorizers and your overall authentication system are recommended.

## Contributing

Contributions to improve these authorizers are welcome. Please submit a pull request or open an issue to discuss proposed changes.

## License

[Specify your license here]