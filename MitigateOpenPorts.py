import json
import boto3
import logging

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    logger.info("Event: " + json.dumps(event))
    
    try:
        # Extract groupId safely
        security_group_id = event.get('detail', {}).get('requestParameters', {}).get('groupId', '')
        if not security_group_id:
            raise ValueError("groupId not found in the event")
        
        # Log the security group ID
        logger.info("Security Group ID: " + security_group_id)
        
        # Get current security group rules
        response = ec2.describe_security_groups(GroupIds=[security_group_id])
        logger.info("DescribeSecurityGroups response: " + json.dumps(response))
        
        security_group = response['SecurityGroups'][0]
        ip_permissions = security_group['IpPermissions']
        
        for permission in ip_permissions:
            for ip_range in permission['IpRanges']:
                if ip_range['CidrIp'] == '0.0.0.0/0':
                    from_port = permission['FromPort']
                    to_port = permission['ToPort']
                    
                    # Skip ports 80 and 443
                    if from_port in [80, 443] and to_port in [80, 443]:
                        logger.info(f"Skipping open port {from_port} - {to_port} in security group {security_group_id}")
                        continue
                    
                    # Revoke the insecure rule
                    ec2.revoke_security_group_ingress(
                        GroupId=security_group_id,
                        IpProtocol=permission['IpProtocol'],
                        FromPort=from_port,
                        ToPort=to_port,
                        CidrIp='0.0.0.0/0'
                    )
                    logger.info(f"Revoked open port {from_port} - {to_port} in security group {security_group_id}")

    except Exception as e:
        logger.error("Error processing event: " + str(e))
        raise

    return {
        'statusCode': 200,
        'body': json.dumps('Mitigation complete')
    }