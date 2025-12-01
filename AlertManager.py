import json
import os
import logging
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, config_path='alert_settings.json'):
        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load alert config: {e}")
        return {
            "slack_enabled": False,
            "slack_webhook": "",
            "email_enabled": False,
            "email_recipient": "",
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_user": "",
            "smtp_password": ""
        }

    def save_config(self, new_config):
        self.config.update(new_config)
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            logger.error(f"Failed to save alert config: {e}")
            return False

    def dispatch_alert(self, finding):
        """
        Dispatch alert to enabled channels.
        finding: dict containing 'title', 'severity', 'description', 'resource_id', etc.
        """
        results = {"slack": False, "email": False}
        
        if self.config.get("slack_enabled") and self.config.get("slack_webhook"):
            results["slack"] = self.send_slack_alert(finding)
            
        if self.config.get("email_enabled") and self.config.get("email_recipient"):
            results["email"] = self.send_email_alert(finding)
            
        return results

    def send_slack_alert(self, finding):
        webhook_url = self.config.get("slack_webhook")
        if not webhook_url:
            return False
            
        color = "#ff0000" if finding.get("severity") == "CRITICAL" else "#ffaa00"
        
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": f"🚨 {finding.get('title')} ({finding.get('severity')})",
                    "text": finding.get('description'),
                    "fields": [
                        {"title": "Resource ID", "value": finding.get('resource_id'), "short": True},
                        {"title": "Service", "value": finding.get('service'), "short": True},
                        {"title": "Recommendation", "value": finding.get('recommendation'), "short": False}
                    ],
                    "footer": "CloudShield Honeypot System",
                    "ts": int(os.path.getmtime(self.config_path)) if os.path.exists(self.config_path) else 0 # Dummy TS or current time
                }
            ]
        }
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=5)
            if response.status_code == 200:
                logger.info(f"Slack alert sent for {finding.get('id')}")
                return True
            else:
                logger.error(f"Slack alert failed: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Slack alert error: {e}")
            return False

    def send_email_alert(self, finding):
        recipient = self.config.get("email_recipient")
        smtp_user = self.config.get("smtp_user")
        smtp_password = self.config.get("smtp_password")
        
        if not recipient or not smtp_user or not smtp_password:
            logger.warning("Email alert skipped: Missing credentials")
            return False
            
        subject = f"🚨 SECURITY ALERT: {finding.get('title')} ({finding.get('severity')})"
        
        body = f"""
        SECURITY ALERT
        --------------
        Title: {finding.get('title')}
        Severity: {finding.get('severity')}
        Resource ID: {finding.get('resource_id')}
        Service: {finding.get('service')}
        
        Description:
        {finding.get('description')}
        
        Recommendation:
        {finding.get('recommendation')}
        
        Timestamp: {finding.get('timestamp')}
        """
        
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = recipient
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            server = smtplib.SMTP(self.config.get("smtp_server"), self.config.get("smtp_port"))
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            server.quit()
            logger.info(f"Email alert sent to {recipient}")
            return True
        except Exception as e:
            logger.error(f"Email alert failed: {e}")
            return False
