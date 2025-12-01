import boto3
import logging
import json

logger = logging.getLogger(__name__)

class RemediationManager:
    def __init__(self):
        pass

    def get_ai_explanation(self, issue_type):
        """
        Returns a simulated AI explanation for the fix.
        """
        explanations = {
            "S3_PUBLIC_ACCESS": {
                "title": "Blocking Public Access",
                "why": "Publicly accessible buckets are a leading cause of data breaches. Attackers scan for these buckets to steal sensitive data or host malware.",
                "what": "I will enable the 'Block Public Access' setting on this bucket. This overrides any existing ACLs or policies that allow public access.",
                "risk": "Low. However, if this bucket hosts a public website, it will become inaccessible to the public."
            },
            "S3_VERSIONING": {
                "title": "Enabling Versioning",
                "why": "Without versioning, overwriting or deleting a file is permanent. Ransomware or accidental deletion can cause data loss.",
                "what": "I will enable 'Bucket Versioning'. This keeps multiple variants of an object in the same bucket.",
                "risk": "Low. Storage costs may increase slightly if you frequently overwrite large files."
            },
            "EC2_OPEN_SECURITY_GROUP": {
                "title": "Restricting Security Group",
                "why": "Allowing 0.0.0.0/0 (all IPs) on sensitive ports exposes your instance to the entire internet, making it a prime target for brute-force attacks.",
                "what": "I will revoke the ingress rule allowing 0.0.0.0/0. You should replace it with your specific IP address later.",
                "risk": "Medium. If you are connecting from a dynamic IP, you might lose access until you add your new IP."
            },
            "IAM_NO_MFA": {
                "title": "Enforcing MFA",
                "why": "Passwords can be stolen. MFA adds a second layer of defense. Accounts without MFA are easily compromised.",
                "what": "I will attach a strict 'ForceMFA' policy to this user. They will be denied all actions until they enable MFA.",
                "risk": "High. The user will be locked out of most actions until they set up an MFA device."
            }
        }
        return explanations.get(issue_type, {
            "title": "Applying Fix",
            "why": "This configuration violates security best practices.",
            "what": "I will apply the recommended security setting.",
            "risk": "Unknown."
        })

    def remediate_finding(self, credentials, finding_id, resource_id, issue_type, region):
        """
        Executes the remediation logic.
        """
        logger.info(f"Remediating {issue_type} on {resource_id} in {region}")
        
        try:
            if issue_type == "S3_PUBLIC_ACCESS":
                return self._fix_s3_public_access(credentials, resource_id, region)
            elif issue_type == "S3_VERSIONING":
                return self._fix_s3_versioning(credentials, resource_id, region)
            elif issue_type == "EC2_OPEN_SECURITY_GROUP":
                return self._fix_ec2_security_group(credentials, resource_id, region)
            elif issue_type == "IAM_NO_MFA":
                return self._fix_iam_mfa(credentials, resource_id)
            else:
                return {"success": False, "message": f"No remediation available for {issue_type}"}
        except Exception as e:
            logger.error(f"Remediation failed: {e}")
            return {"success": False, "message": str(e)}

    def _get_s3_client(self, credentials, region):
        return boto3.client(
            's3',
            aws_access_key_id=credentials['accessKeyId'],
            aws_secret_access_key=credentials['secretAccessKey'],
            region_name=region
        )

    def _fix_s3_public_access(self, credentials, resource_id, region):
        s3 = self._get_s3_client(credentials, region)
        
        # 1. Enable Block Public Access
        s3.put_public_access_block(
            Bucket=resource_id,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        return {"success": True, "message": f"Public access blocked for bucket {resource_id}"}

    def _fix_s3_versioning(self, credentials, resource_id, region):
        s3 = self._get_s3_client(credentials, region)
        
        s3.put_bucket_versioning(
            Bucket=resource_id,
            VersioningConfiguration={
                'Status': 'Enabled'
            }
        )
        
        return {"success": True, "message": f"Versioning enabled for bucket {resource_id}"}

    def _fix_ec2_security_group(self, credentials, resource_id, region):
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=credentials['accessKeyId'],
            aws_secret_access_key=credentials['secretAccessKey'],
            region_name=region
        )
        
        try:
            # Describe to find the bad rule
            sg = ec2.describe_security_groups(GroupIds=[resource_id])['SecurityGroups'][0]
            permissions = sg['IpPermissions']
            
            revoked_count = 0
            for perm in permissions:
                for range in perm.get('IpRanges', []):
                    if range.get('CidrIp') == '0.0.0.0/0':
                        # Revoke this specific permission
                        ec2.revoke_security_group_ingress(
                            GroupId=resource_id,
                            IpPermissions=[{
                                'IpProtocol': perm['IpProtocol'],
                                'FromPort': perm.get('FromPort', -1),
                                'ToPort': perm.get('ToPort', -1),
                                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                            }]
                        )
                        revoked_count += 1
            
            if revoked_count > 0:
                return {"success": True, "message": f"Revoked {revoked_count} open rules (0.0.0.0/0) from {resource_id}"}
            else:
                return {"success": False, "message": "No 0.0.0.0/0 rules found to revoke."}
                
        except Exception as e:
            raise e

    def _fix_iam_mfa(self, credentials, resource_id):
        iam = boto3.client(
            'iam',
            aws_access_key_id=credentials['accessKeyId'],
            aws_secret_access_key=credentials['secretAccessKey']
        )
        
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyAllExceptMFA",
                    "Effect": "Deny",
                    "NotAction": [
                        "iam:EnableMFADevice",
                        "iam:ListMFADevices",
                        "iam:ResyncMFADevice",
                        "iam:GetUser",
                        "iam:ChangePassword"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "BoolIfExists": {
                            "aws:MultiFactorAuthPresent": "false"
                        }
                    }
                }
            ]
        }
        
        iam.put_user_policy(
            UserName=resource_id,
            PolicyName="ForceMFA",
            PolicyDocument=json.dumps(policy_doc)
        )
        
        return {"success": True, "message": f"Attached 'ForceMFA' inline policy to user {resource_id}"}
