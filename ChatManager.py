import logging

logger = logging.getLogger(__name__)

class ChatManager:
    def __init__(self):
        self.context = {}

    def get_response(self, message):
        """
        Returns a simulated AI response based on keywords.
        """
        message = message.lower()
        
        if "hello" in message or "hi" in message:
            return "Hello! I am your CloudShield AI Assistant. How can I help you secure your AWS environment today?"
        
        elif "help" in message:
            return "I can help you with:\n- Understanding security findings\n- Running scans\n- Fixing issues (S3, EC2, IAM)\n- General AWS security advice"
        
        elif "scan" in message:
            return "To run a scan, click the 'Start Scan' button on the dashboard. I will analyze your environment for misconfigurations."
        
        elif "s3" in message:
            if "public" in message:
                return "Public S3 buckets are risky. Use the 'Auto-Fix' button to block public access, or configure a Bucket Policy to restrict access to specific IPs or IAM roles."
            return "S3 security is critical. Ensure you have Block Public Access enabled, Versioning turned on, and Server-Side Encryption active."
        
        elif "ec2" in message:
            if "security group" in message or "sg" in message:
                return "Security Groups act as a virtual firewall. Avoid allowing 0.0.0.0/0 (all traffic) on sensitive ports like 22 (SSH) or 3389 (RDP)."
            return "For EC2, always use minimal Security Group rules, enable EBS encryption, and use IAM roles instead of hardcoded credentials."
        
        elif "iam" in message:
            if "mfa" in message:
                return "MFA (Multi-Factor Authentication) adds a critical layer of security. You should enforce MFA for all users, especially those with console access."
            return "IAM best practices: Grant least privilege, rotate access keys regularly, and enforce MFA."
        
        elif "honeypot" in message:
            return "Honeypots are decoy resources. We can deploy fake S3 buckets or EC2 instances to lure attackers. If they touch them, you get an alert!"
        
        elif "remediate" in message or "fix" in message:
            return "I can automatically fix certain issues like S3 Public Access or missing MFA. Look for the '✨ Auto-Fix' button in your scan results."
        
        else:
            return "I'm not sure about that. Try asking about 'S3', 'EC2', 'IAM', 'Honeypots', or 'Scanning'."
