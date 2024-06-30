# Automatic Security Group Remediation in AWS

This repository contains a solution to automatically remediate AWS security group rules that open ports to `0.0.0.0/0`, excluding ports 80 and 443. (real-time remediation of new security group changes)


## Deployment Guide

### Part 1: Automatic Remediation for New Security Group Changes

#### Step 1: Create an IAM Role for the Lambda Function

1. **Go to AWS IAM Console**:
   - Open the AWS Management Console and go to the IAM service.
   
2. **Create a new role**:
   - Click on "Roles".
   - Click the "Create role".
   - Choose "Lambda" as the trusted entity.
   - Click "Next: Permissions".

3. **Attach the necessary policies**:
   - Attach the policy provided in `LambdaSecurityGroupMitigatorRole.json`.
   - Click "Next: Tags" (you can skip adding tags).
   - Click "Next: Review".
   - Name the role (e.g., `LambdaSecurityGroupMitigatorRole`) and complete the creation process.

#### Step 2: Create the Lambda Function

1. **Go to AWS Lambda Console**:
   - Open the AWS Management Console and go to the Lambda service.

2. **Create a new Lambda function**:
   - Click "Create function".
   - Choose "Author from scratch".
   - Enter a function name (e.g., `MitigateOpenPorts`).
   - Choose the runtime (e.g., Python 3.8 or later).
   - Under "Permissions", choose "Use an existing role" and select the role you created earlier (`LambdaSecurityGroupMitigatorRole`).
   - Click "Create function".

3. **Add the Lambda function code**:
   - Copy and paste the code from `MitigateOpenPorts.py` into the Lambda function editor.
   - Click "Deploy".

#### Step 3: Create a CloudWatch Event Rule

1. **Go to CloudWatch Console**:
   - Open the AWS Management Console and go to CloudWatch.

2. **Create a new rule**:
   - Under "Events", click "Rules".
   - Click "Create rule".
   - For "Event Source", choose "AWS API Call via CloudTrail".
   - Select "Specific operations by specific services".
   - Select "EC2" as the service name.
   - Select "AuthorizeSecurityGroupIngress" as the operation name.

3. **Add the target**:
   - Choose "Lambda function".
   - Select the Lambda function you created earlier (`MitigateOpenPorts`).
   - Click "Configure details".
   - Name the rule (e.g., `MitigateOpenPortsRule`) and complete the creation process.

#### Step 4: Enable CloudTrail (if not already enabled)

1. **Go to CloudTrail Console**:
   - Open the AWS Management Console and go to CloudTrail.

2. **Create a trail**:
   - Ensure that CloudTrail is set up to log API calls for your account.
   - Follow the instructions to create a trail if you don't already have one set up.
