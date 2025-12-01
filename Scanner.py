#!/usr/bin/env python3
"""
AWS Cloud Misconfiguration Scanner
A comprehensive security scanner for detecting AWS misconfigurations
and vulnerabilities across multiple services including S3, EC2, RDS, IAM, and CloudTrail.
Generates detailed findings, summary statistics, and saves results to a JSON file.
"""

import boto3
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('aws_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class Finding:
    """Data class for security findings"""
    service: str
    resource_id: str
    resource_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    recommendation: str
    region: str
    account_id: str
    timestamp: str = None
    id: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
        if self.id is None:
            import uuid
            self.id = f"finding-{uuid.uuid4().hex[:8]}"

class AWSMisconfigurationScanner:
    """Main scanner class for AWS misconfigurations"""
    
    def __init__(self, session=None, profile_name: str = None):
        try:
            if session is not None:
                self.session = session
            elif profile_name is not None:
                self.session = boto3.Session(profile_name=profile_name)
            else:
                self.session = boto3.Session()
            self.account_id = self.session.client('sts').get_caller_identity()['Account']
            self.findings: List[Finding] = []
            logger.info(f"Initialized scanner for AWS Account: {self.account_id}")
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {e}")
            raise
    
    def get_available_regions(self, service: str = 'ec2') -> List[str]:
        """Get available regions for a service"""
        try:
            return self.session.get_available_regions(service)
        except Exception as e:
            logger.error(f"Error getting regions: {e}")
            return ['us-east-1']  # Default fallback
    
    def scan_s3_buckets(self) -> List[Finding]:
        """Scan S3 buckets for misconfigurations"""
        findings = []
        logger.info("Scanning S3 buckets...")
        
        try:
            s3_client = self.session.client('s3')
            buckets = s3_client.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check public read access
                try:
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            findings.append(Finding(
                                id=f"s3-public-access-{bucket_name}",
                                service='S3',
                                resource_id=bucket_name,
                                resource_type='Bucket',
                                severity='CRITICAL',
                                title='S3 Bucket Publicly Readable',
                                description=f'Bucket {bucket_name} allows public read access',
                                recommendation='Remove public read permissions and use IAM policies instead',
                                region='global',
                                account_id=self.account_id
                            ))
                except Exception as e:
                    logger.warning(f"Could not check ACL for bucket {bucket_name}: {e}")
                
                # Check encryption
                try:
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                except s3_client.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append(Finding(
                            service='S3',
                            resource_id=bucket_name,
                            resource_type='Bucket',
                            severity='HIGH',
                            title='S3 Bucket Not Encrypted',
                            description=f'Bucket {bucket_name} does not have server-side encryption enabled',
                            recommendation='Enable server-side encryption (SSE-S3, SSE-KMS, or SSE-C)',
                            region='global',
                            account_id=self.account_id
                        ))
                
                # Check versioning
                try:
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        findings.append(Finding(
                            id=f"s3-versioning-{bucket_name}",
                            service='S3',
                            resource_id=bucket_name,
                            resource_type='Bucket',
                            severity='MEDIUM',
                            title='S3 Bucket Versioning Disabled',
                            description=f'Bucket {bucket_name} does not have versioning enabled',
                            recommendation='Enable versioning to protect against accidental deletion/modification',
                            region='global',
                            account_id=self.account_id
                        ))
                except Exception as e:
                    logger.warning(f"Could not check versioning for bucket {bucket_name}: {e}")
        
        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {e}")
        
        return findings
    
    def scan_ec2_instances(self, region: str) -> List[Finding]:
        """Scan EC2 instances for misconfigurations"""
        findings = []
        logger.info(f"Scanning EC2 instances in {region}...")
        
        try:
            ec2_client = self.session.client('ec2', region_name=region)
            instances = ec2_client.describe_instances()
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    
                    # Check for public IP without proper security groups
                    if instance.get('PublicIpAddress'):
                        security_groups = instance.get('SecurityGroups', [])
                        for sg in security_groups:
                            sg_details = ec2_client.describe_security_groups(
                                GroupIds=[sg['GroupId']]
                            )['SecurityGroups'][0]
                            
                            for rule in sg_details.get('IpPermissions', []):
                                for ip_range in rule.get('IpRanges', []):
                                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                                        findings.append(Finding(
                                            id=f"ec2-sg-open-{instance_id}",
                                            service='EC2',
                                            resource_id=instance_id,
                                            resource_type='Instance',
                                            severity='HIGH',
                                            title='EC2 Instance with Overly Permissive Security Group',
                                            description=f'Instance {instance_id} has security group allowing 0.0.0.0/0 access',
                                            recommendation='Restrict security group rules to specific IP ranges',
                                            region=region,
                                            account_id=self.account_id
                                        ))
                    
                    # Check EBS encryption
                    for bdm in instance.get('BlockDeviceMappings', []):
                        if 'Ebs' in bdm:
                            volume_id = bdm['Ebs']['VolumeId']
                            volume = ec2_client.describe_volumes(VolumeIds=[volume_id])['Volumes'][0]
                            if not volume.get('Encrypted', False):
                                findings.append(Finding(
                                    service='EC2',
                                    resource_id=volume_id,
                                    resource_type='EBS Volume',
                                    severity='HIGH',
                                    title='Unencrypted EBS Volume',
                                    description=f'EBS volume {volume_id} is not encrypted',
                                    recommendation='Enable EBS encryption for data at rest',
                                    region=region,
                                    account_id=self.account_id
                                ))
        
        except Exception as e:
            logger.error(f"Error scanning EC2 instances in {region}: {e}")
        
        return findings
    
    def scan_rds_instances(self, region: str) -> List[Finding]:
        """Scan RDS instances for misconfigurations"""
        findings = []
        logger.info(f"Scanning RDS instances in {region}...")
        
        try:
            rds_client = self.session.client('rds', region_name=region)
            
            # Check RDS instances
            instances = rds_client.describe_db_instances()['DBInstances']
            for instance in instances:
                db_instance_id = instance['DBInstanceIdentifier']
                
                # Check encryption
                if not instance.get('StorageEncrypted', False):
                    findings.append(Finding(
                        service='RDS',
                        resource_id=db_instance_id,
                        resource_type='DB Instance',
                        severity='HIGH',
                        title='RDS Instance Not Encrypted',
                        description=f'RDS instance {db_instance_id} storage is not encrypted',
                        recommendation='Enable encryption at rest for RDS instances',
                        region=region,
                        account_id=self.account_id
                    ))
                
                # Check public accessibility
                if instance.get('PubliclyAccessible', False):
                    findings.append(Finding(
                        service='RDS',
                        resource_id=db_instance_id,
                        resource_type='DB Instance',
                        severity='CRITICAL',
                        title='RDS Instance Publicly Accessible',
                        description=f'RDS instance {db_instance_id} is publicly accessible',
                        recommendation='Disable public accessibility and use VPC endpoints',
                        region=region,
                        account_id=self.account_id
                    ))
                
                # Check backup retention
                if instance.get('BackupRetentionPeriod', 0) == 0:
                    findings.append(Finding(
                        service='RDS',
                        resource_id=db_instance_id,
                        resource_type='DB Instance',
                        severity='MEDIUM',
                        title='RDS Backup Retention Disabled',
                        description=f'RDS instance {db_instance_id} has backup retention disabled',
                        recommendation='Enable automated backups with appropriate retention period',
                        region=region,
                        account_id=self.account_id
                    ))
        
        except Exception as e:
            logger.error(f"Error scanning RDS instances in {region}: {e}")
        
        return findings
    
    def scan_iam_policies(self) -> List[Finding]:
        """Scan IAM policies for misconfigurations"""
        findings = []
        logger.info("Scanning IAM policies...")
        
        try:
            iam_client = self.session.client('iam')
            
            # Check for overly permissive policies
            policies = iam_client.list_policies(Scope='Local')['Policies']
            for policy in policies:
                policy_arn = policy['Arn']
                
                # Get policy document
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy['DefaultVersionId']
                )
                
                policy_doc = policy_version['PolicyVersion']['Document']
                
                # Check for wildcard permissions
                for statement in policy_doc.get('Statement', []):
                    if isinstance(statement, dict):
                        actions = statement.get('Action', [])
                        resources = statement.get('Resource', [])
                        
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        
                        # Check for admin access
                        if '*' in actions and '*' in resources:
                            findings.append(Finding(
                                service='IAM',
                                resource_id=policy_arn,
                                resource_type='Policy',
                                severity='CRITICAL',
                                title='IAM Policy with Full Admin Access',
                                description=f'Policy {policy["PolicyName"]} grants full administrative access',
                                recommendation='Follow principle of least privilege and restrict permissions',
                                region='global',
                                account_id=self.account_id
                            ))
            
            # Check for users with programmatic access but no MFA
            users = iam_client.list_users()['Users']
            for user in users:
                username = user['UserName']
                
                # Check if user has access keys
                access_keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
                if access_keys:
                    # Check if MFA is enabled
                    mfa_devices = iam_client.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        findings.append(Finding(
                            id=f"iam-no-mfa-{username}",
                            service='IAM',
                            resource_id=username,
                            resource_type='User',
                            severity='HIGH',
                            title='IAM User with Access Keys but No MFA',
                            description=f'User {username} has programmatic access but no MFA enabled',
                            recommendation='Enable MFA for all users with programmatic access',
                            region='global',
                            account_id=self.account_id
                        ))
        
        except Exception as e:
            logger.error(f"Error scanning IAM policies: {e}")
        
        return findings
    
    def scan_cloudtrail(self, region: str) -> List[Finding]:
        """Scan CloudTrail for misconfigurations"""
        findings = []
        logger.info(f"Scanning CloudTrail in {region}...")
        
        try:
            cloudtrail_client = self.session.client('cloudtrail', region_name=region)
            trails = cloudtrail_client.describe_trails()['trailList']
            
            if not trails:
                findings.append(Finding(
                    service='CloudTrail',
                    resource_id='No trails found',
                    resource_type='Trail',
                    severity='CRITICAL',
                    title='No CloudTrail Enabled',
                    description='No CloudTrail trails are configured for logging',
                    recommendation='Enable CloudTrail for audit logging and compliance',
                    region=region,
                    account_id=self.account_id
                ))
            
            for trail in trails:
                trail_name = trail['Name']
                
                # Check if trail is logging
                status = cloudtrail_client.get_trail_status(Name=trail_name)
                if not status.get('IsLogging', False):
                    findings.append(Finding(
                        service='CloudTrail',
                        resource_id=trail_name,
                        resource_type='Trail',
                        severity='HIGH',
                        title='CloudTrail Not Logging',
                        description=f'CloudTrail {trail_name} is not actively logging',
                        recommendation='Enable logging for the CloudTrail',
                        region=region,
                        account_id=self.account_id
                    ))
                
                # Check if S3 bucket has appropriate encryption
                if not trail.get('KMSKeyId'):
                    findings.append(Finding(
                        service='CloudTrail',
                        resource_id=trail_name,
                        resource_type='Trail',
                        severity='MEDIUM',
                        title='CloudTrail Logs Not Encrypted with KMS',
                        description=f'CloudTrail {trail_name} logs are not encrypted with KMS',
                        recommendation='Enable KMS encryption for CloudTrail logs',
                        region=region,
                        account_id=self.account_id
                    ))
        
        except Exception as e:
            logger.error(f"Error scanning CloudTrail in {region}: {e}")
        
        return findings
    
    def scan_region(self, region: str) -> List[Finding]:
        """Scan a specific region for all services"""
        region_findings = []
        
        # Scan EC2 instances
        region_findings.extend(self.scan_ec2_instances(region))
        
        # Scan RDS instances
        region_findings.extend(self.scan_rds_instances(region))
        
        # Scan CloudTrail
        region_findings.extend(self.scan_cloudtrail(region))
        
        return region_findings
    
    def run_scan(self, regions: List[str] = None, max_workers: int = 5) -> Dict[str, Any]:
        """Run comprehensive security scan"""
        logger.info("Starting comprehensive AWS security scan...")
        
        if regions is None:
            regions = ['us-east-1', 'us-west-2', 'eu-west-1']  # Default regions
        
        # Scan global services first
        self.findings.extend(self.scan_s3_buckets())
        self.findings.extend(self.scan_iam_policies())
        
        # Scan regional services with thread pool
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_region = {executor.submit(self.scan_region, region): region for region in regions}
            
            for future in as_completed(future_to_region):
                region = future_to_region[future]
                try:
                    region_findings = future.result()
                    self.findings.extend(region_findings)
                except Exception as e:
                    logger.error(f"Error scanning region {region}: {e}")
        
        # Generate summary
        summary = self.generate_summary()
        
        logger.info(f"Scan completed. Found {len(self.findings)} issues.")
        return summary
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate scan summary and statistics"""
        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        service_counts = {}
        
        for finding in self.findings:
            severity_counts[finding.severity] += 1
            service_counts[finding.service] = service_counts.get(finding.service, 0) + 1
        
        summary = {
            'scan_metadata': {
                'account_id': self.account_id,
                'timestamp': datetime.now().isoformat(),
                'total_findings': len(self.findings)
            },
            'severity_distribution': severity_counts,
            'service_distribution': service_counts,
            'findings': [asdict(finding) for finding in self.findings]
        }
        
        return summary
    
    def save_results(self, filename: str = None) -> None:
        """Save scan results to JSON file"""
        if filename is None:
            filename = f"aws_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        summary = self.generate_summary()
        
        with open(filename, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
        
        logger.info(f"Results saved to {filename}")
    
    def print_summary(self) -> None:
        """Print scan summary to console"""
        summary = self.generate_summary()
        
        print("\n" + "="*60)
        print("AWS SECURITY SCAN SUMMARY")
        print("="*60)
        print(f"Account ID: {summary['scan_metadata']['account_id']}")
        print(f"Scan Time: {summary['scan_metadata']['timestamp']}")
        print(f"Total Findings: {summary['scan_metadata']['total_findings']}")
        
        print("\nSeverity Distribution:")
        for severity, count in summary['severity_distribution'].items():
            print(f"  {severity}: {count}")
        
        print("\nService Distribution:")
        for service, count in summary['service_distribution'].items():
            print(f"  {service}: {count}")
        
        print("\nTop Issues:")
        critical_findings = [f for f in self.findings if f.severity == 'CRITICAL'][:5]
        for finding in critical_findings:
            print(f"  • {finding.title} ({finding.service})")

def main():
    """Main function to run the scanner"""
    parser = argparse.ArgumentParser(description='AWS Cloud Misconfiguration Scanner')
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--regions', nargs='+', help='AWS regions to scan')
    parser.add_argument('--output', help='Output filename for results')
    parser.add_argument('--workers', type=int, default=5, help='Number of worker threads')
    
    args = parser.parse_args()
    
    try:
        # Initialize scanner
        scanner = AWSMisconfigurationScanner(profile_name=args.profile)
        
        # Run scan
        results = scanner.run_scan(regions=args.regions, max_workers=args.workers)
        
        # Print summary
        scanner.print_summary()
        
        # Save results
        scanner.save_results(args.output)
        
    except Exception as e:
        logger.error(f"Scanner failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())