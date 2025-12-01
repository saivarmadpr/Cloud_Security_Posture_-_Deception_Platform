import boto3
import json
import os
import time
import logging
import requests
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HoneypotManager:
    def __init__(self, db_path='honeypots.json'):
        self.db_path = db_path
        self.active_honeypots = self._load_honeypots()

    def _load_honeypots(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load honeypots: {e}")
                return []
        return []

    def _save_honeypots(self):
        try:
            with open(self.db_path, 'w') as f:
                json.dump(self.active_honeypots, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save honeypots: {e}")

    def deploy_honeypot(self, credentials, hp_type, region, name=None):
        session = boto3.Session(
            aws_access_key_id=credentials['accessKeyId'],
            aws_secret_access_key=credentials['secretAccessKey'],
            region_name=region
        )

        honeypot_id = f"hp-{int(time.time())}"
        deployed_resource = None

        try:
            if hp_type == 's3':
                deployed_resource = self._deploy_s3_honeypot(session, region, name, honeypot_id)
            elif hp_type in ['ssh', 'database', 'web']:
                deployed_resource = self._deploy_ec2_honeypot(session, region, name, hp_type, honeypot_id)
            else:
                raise ValueError(f"Unknown honeypot type: {hp_type}")

            if deployed_resource:
                self.active_honeypots.append(deployed_resource)
                self._save_honeypots()
                return deployed_resource

        except Exception as e:
            logger.error(f"Failed to deploy honeypot: {e}")
            raise e

    def _deploy_s3_honeypot(self, session, region, name, honeypot_id):
        s3 = session.client('s3')
        bucket_name = name if name else f"prod-backup-{honeypot_id}"
        
        # Create bucket
        if region == 'us-east-1':
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        
        # Enable versioning (to track changes)
        # Enable versioning (to track changes)
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )

        # MISCONFIGURATION 1: Disable Block Public Access
        try:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': False,
                    'IgnorePublicAcls': False,
                    'BlockPublicPolicy': False,
                    'RestrictPublicBuckets': False
                }
            )
            time.sleep(5) # Wait for BPA to propagate
        except Exception as e:
            logger.warning(f"Failed to disable Block Public Access: {e}")

        # MISCONFIGURATION 1.5: Enable ACLs (Required for new buckets)
        try:
            s3.put_bucket_ownership_controls(
                Bucket=bucket_name,
                OwnershipControls={
                    'Rules': [
                        {'ObjectOwnership': 'BucketOwnerPreferred'}
                    ]
                }
            )
            time.sleep(5) # Wait for Ownership to propagate
        except Exception as e:
            logger.warning(f"Failed to enable ACLs: {e}")

        # MISCONFIGURATION 2: Set Public ACL & Bucket Policy
        try:
            s3.put_bucket_acl(
                Bucket=bucket_name,
                ACL='public-read-write'
            )
            
            # ALSO set a bucket policy to be sure
            bucket_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "PublicReadGetObject",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/*"
                    }
                ]
            }
            s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))
            time.sleep(5) # Wait for Policy to propagate
            
        except Exception as e:
            logger.warning(f"Failed to set Public ACL/Policy: {e}")

        # MISCONFIGURATION 3: Upload Bait File
        try:
            bait_content = "username=admin\npassword=Password123!\nsecret_key=AKIAIOSFODNN7EXAMPLE"
            s3.put_object(
                Bucket=bucket_name,
                Key='admin-credentials.txt',
                Body=bait_content,
                ContentType='text/plain',
                ACL='public-read'
            )
            
            # HONEYTOKEN: Upload HTML file with tracking pixel
            # Points to LOCALHOST for demo purposes
            tracking_url = f"http://127.0.0.1:8080/api/honeytoken/{honeypot_id}"
            html_content = f"""
            <html>
            <head><title>Confidential Dashboard</title></head>
            <body style="background-color:#f0f0f0; font-family:sans-serif; text-align:center; padding-top:50px;">
                <h1 style="color:#d00;">CONFIDENTIAL INTERNAL DASHBOARD</h1>
                <p>Loading secure data...</p>
                <!-- Image for automatic tracking (might be blocked by Mixed Content) -->
                <img src="{tracking_url}" style="display:none;" />
                
                <div style="margin-top: 20px; padding: 20px; background: white; border: 1px solid #ccc; display: inline-block;">
                    <p>If data does not load automatically, please click below:</p>
                    <a href="{tracking_url}" style="background: #d00; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Access Secure Data</a>
                </div>

                <script>
                    setTimeout(() => {{ document.body.innerHTML += "<p style='color:red'>Access Denied. IP Logged.</p>"; }}, 2000);
                </script>
            </body>
            </html>
            """
            s3.put_object(
                Bucket=bucket_name,
                Key='confidential-dashboard.html',
                Body=html_content,
                ContentType='text/html',
                ACL='public-read'
            )
            
        except Exception as e:
            logger.error(f"Failed to upload bait/honeytoken files: {e}")
            # Re-raise to see it in the frontend if needed, or just log it
            # raise e

        return {
            "id": honeypot_id,
            "type": "s3",
            "name": bucket_name,
            "region": region,
            "resource_id": bucket_name,
            "ip": "N/A",
            "deployedAt": datetime.now().isoformat(),
            "status": "Active"
        }

    def _deploy_ec2_honeypot(self, session, region, name, hp_type, honeypot_id):
        ec2 = session.resource('ec2')
        client = session.client('ec2')
        
        # 1. Create Security Group
        sg_name = f"honeypot-sg-{honeypot_id}"
        try:
            vpcs = client.describe_vpcs()['Vpcs']
            if not vpcs:
                raise Exception(f"No VPCs found in region {region}. Please create a default VPC.")
            
            vpc_id = vpcs[0]['VpcId']
            sg = ec2.create_security_group(GroupName=sg_name, Description='Honeypot Security Group', VpcId=vpc_id)
            
            port_map = {'ssh': 22, 'database': 5432, 'web': 80}
            port = port_map.get(hp_type, 22)
            
            sg.authorize_ingress(
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
            sg_id = sg.id
        except Exception as e:
            logger.error(f"SG Creation failed: {e}")
            raise

        # 2. Run Instance
        image_id = None
        try:
            # Method 1: SSM Parameter Store (Recommended)
            ssm = session.client('ssm')
            response = ssm.get_parameter(
                Name='/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64',
                WithDecryption=False
            )
            image_id = response['Parameter']['Value']
            logger.info(f"Found AMI via SSM: {image_id}")
        except Exception as e:
            logger.warning(f"SSM Lookup failed: {e}")
            
            # Method 2: Hardcoded Fallback for common regions (Nov 2023 AL2023)
            # This is a safety net if SSM fails (e.g. permission issues)
            fallback_amis = {
                'us-east-1': 'ami-0230bd60aa48260c6',
                'us-west-2': 'ami-0cd3c7f72edd5b06d',
                'eu-west-1': 'ami-01dd271720c1ba44f'
            }
            image_id = fallback_amis.get(region)
            
            if not image_id:
                # Method 3: Last Resort Describe Images (Broad search)
                try:
                    ami_response = client.describe_images(
                        Owners=['amazon'],
                        Filters=[
                            {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                            {'Name': 'state', 'Values': ['available']}
                        ]
                    )
                    if ami_response['Images']:
                        images = sorted(ami_response['Images'], key=lambda x: x['CreationDate'], reverse=True)
                        image_id = images[0]['ImageId']
                except Exception as inner_e:
                    logger.error(f"Describe Images failed: {inner_e}")

        if not image_id:
            raise Exception(f"Could not find a suitable AMI in region {region}. Please check permissions or region support.")

        instances = ec2.create_instances(
            ImageId=image_id,
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.micro',
            SecurityGroupIds=[sg_id],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': name if name else f"Honeypot-{hp_type}-{honeypot_id}"},
                    {'Key': 'Type', 'Value': 'Honeypot'},
                    {'Key': 'HoneypotType', 'Value': hp_type}
                ]
            }]
        )
        
        instance = instances[0]
        instance.wait_until_running()
        instance.reload()

        return {
            "id": honeypot_id,
            "type": hp_type,
            "name": name if name else f"Honeypot-{hp_type}",
            "region": region,
            "resource_id": instance.id,
            "ip": instance.public_ip_address,
            "deployedAt": datetime.now().isoformat(),
            "status": "Active"
        }

    def terminate_honeypot(self, credentials, honeypot_id):
        hp = next((h for h in self.active_honeypots if h['id'] == honeypot_id), None)
        if not hp:
            return False

        session = boto3.Session(
            aws_access_key_id=credentials['accessKeyId'],
            aws_secret_access_key=credentials['secretAccessKey'],
            region_name=hp['region']
        )

        try:
            if hp['type'] == 's3':
                s3 = session.resource('s3')
                bucket = s3.Bucket(hp['resource_id'])
                bucket.objects.all().delete() # Empty bucket first
                bucket.object_versions.all().delete()
                bucket.delete()
            else:
                ec2 = session.resource('ec2')
                instance = ec2.Instance(hp['resource_id'])
                instance.terminate()
            
            self.active_honeypots = [h for h in self.active_honeypots if h['id'] != honeypot_id]
            self._save_honeypots()
            return True
        except Exception as e:
            logger.error(f"Failed to terminate honeypot: {e}")
            raise e

    def simulate_attack(self, honeypot_id):
        hp = next((h for h in self.active_honeypots if h['id'] == honeypot_id), None)
        if not hp:
            return {"success": False, "error": "Honeypot not found"}

        try:
            if hp['type'] == 's3':
                # Simulate S3 Attack: Try to access the bait file publicly
                import requests
                url = f"https://{hp['resource_id']}.s3.amazonaws.com/admin-credentials.txt"
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        return {
                            "success": True, 
                            "alert_type": "Data Exfiltration",
                            "severity": "CRITICAL",
                            "message": f"Unauthorized access to s3://{hp['resource_id']}/admin-credentials.txt detected from IP {self._get_public_ip()}",
                            "details": "Attacker downloaded sensitive file via public URL."
                        }
                    else:
                        return {"success": False, "error": f"Bait file not accessible (Status: {response.status_code})"}
                except Exception as e:
                    return {"success": False, "error": f"Connection failed: {str(e)}"}

            elif hp['type'] in ['ssh', 'web', 'database']:
                # Simulate Network Attack: Port Scan
                import socket
                port_map = {'ssh': 22, 'database': 5432, 'web': 80}
                port = port_map.get(hp['type'], 80)
                ip = hp['ip']
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    return {
                        "success": True,
                        "alert_type": "Port Scan / Service Discovery",
                        "severity": "HIGH",
                        "message": f"Suspicious connection attempt on port {port} ({hp['type'].upper()}) from IP {self._get_public_ip()}",
                        "details": "Potential brute-force or reconnaissance activity detected."
                    }
                else:
                    return {"success": False, "error": f"Port {port} is closed or unreachable on {ip}"}
            
            return {"success": False, "error": "Unknown honeypot type"}

        except Exception as e:
            logger.error(f"Attack simulation failed: {e}")
            return {"success": False, "error": str(e)}

    def _get_public_ip(self):
        try:
            import requests
            return requests.get('https://api.ipify.org', timeout=3).text
        except:
            return "Unknown External IP"

    def get_active_honeypots(self):
        return self.active_honeypots
