# Cloud MFA API (AWS Serverless)

This directory contains the modernized, cloud-ready version of the original local FastAPI prototype. It has been refactored to be deployed natively on AWS using the "Fat Lambda" pattern.

## What Changed From The Local Prototype?

1. **The Mangum Adapter ("Fat Lambda")**:
   - **Before**: The app ran locally using `uvicorn main:app` on a single server.
   - **After**: The app is wrapped with `mangum.Mangum(app)` (at the bottom of `main.py`). AWS API Gateway receives all HTTP requests and forwards them to a single AWS Lambda function, which translates the request for FastAPI to handle.
   
2. **Persistent Storage (boto3 & DynamoDB)**:
   - **Before**: State was stored in local Python dictionaries (`users` and `pre_auth`). If the server restarted, all data was lost.
   - **After**: The app uses `boto3` to store users in a DynamoDB table (`MfaUsersTable`) and temporary OTP sessions in another table (`MfaOTPStoreTable`).
   - **TTL**: The `MfaOTPStoreTable` is configured with a Time-to-Live (TTL) attribute (`expiresAt`). AWS will automatically delete expired session tokens to save space without any custom cleanup code.

3. **Cryptography Upgrade (RS256 & AWS SSM)**:
   - **Before**: The app used symmetric encryption (`HS256`) with an ephemeral secret key generated locally in memory every time the server started.
   - **After**: The app now uses asymmetric encryption (`RS256`). The RSA Private and Public keys are fetched securely from AWS Systems Manager (SSM) Parameter Store.

4. **Infrastructure as Code (AWS SAM)**:
   - **Before**: No infrastructure deployment strategy.
   - **After**: The `template.yaml` file natively defines the API Gateway, Lambda Function, IAM Policies, and DynamoDB tables using AWS Serverless Application Model (SAM).

## How To Deploy & Use

### Prerequisites
1. You must have an AWS Account and the AWS CLI installed and configured.
2. You must install the **AWS SAM CLI**.
   - **Windows**: Download the MSI installer from the AWS website or use `winget install -e --id Amazon.SAM-CLI`.
   - **Mac**: `brew tap aws/tap && brew install aws-sam-cli`
   - **Linux**: Use the zip installer from the AWS website.
3. You must install **OpenSSL** to generate your RSA keys.

### Step 1: Generate & Store RSA Keys
First, generate an RSA key pair locally:
```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Extract public key
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

Next, upload these keys to your AWS Systems Manager (SSM) Parameter Store securely:
```bash
aws ssm put-parameter \
    --name "/mfa/jwt/private_key" \
    --value "$(cat private_key.pem)" \
    --type "SecureString"

aws ssm put-parameter \
    --name "/mfa/jwt/public_key" \
    --value "$(cat public_key.pem)" \
    --type "String"
```
*(Note: on Windows Powershell, `$(cat file)` might need to be `Get-Content -Raw private_key.pem`)*

### Step 2: Deploy Infrastructure
Navigate to the `cloud_prototype` folder and run the AWS SAM build and deploy commands:

```bash
cd cloud_prototype

# Build the project (downloads dependencies in requirements.txt)
sam build

# Deploy the project to AWS
sam deploy --guided
```
Follow the prompts in the guided deployment. When asked `FastAPIFunction may not have authorization defined, Is this okay?`, answer **Y** (since we handle auth inside our FastAPI code).

### Step 3: Test the API
After deployment, SAM will output an `ApiUrl`. You can test your cloud-hosted API using curl or Postman:

1. **Register**: `POST {ApiUrl}/auth/register` with `{"username": "test", "password": "password"}`
2. **Enroll TOTP**: `POST {ApiUrl}/auth/enroll-totp` (Scan the QR code with Google Authenticator).
3. **Login**: `POST {ApiUrl}/auth/login` to get the `pre_auth_token`.
4. **Verify**: `POST {ApiUrl}/auth/verify-mfa` with the token and your 6-digit TOTP code to get the JWT.
5. **Access Protected Route**: `GET {ApiUrl}/api/profile` with header `Authorization: Bearer <your-jwt-token>`.
