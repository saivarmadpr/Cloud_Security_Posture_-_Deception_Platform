from flask import Flask, request, jsonify, send_file, send_from_directory
import boto3
from Scanner import AWSMisconfigurationScanner
from HoneypotManager import HoneypotManager
import pandas as pd
import io
import logging
import time
from datetime import datetime

from AlertManager import AlertManager
from RemediationManager import RemediationManager
from ChatManager import ChatManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Store last scan results in memory
LAST_SCAN_RESULTS = {}

# Initialize Managers
honeypot_manager = HoneypotManager()
alert_manager = AlertManager
remediation_manager = RemediationManager()
chat_manager = ChatManager()

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')  # Serves index.html from current folder

@app.route('/styles.css')
def styles():
    return send_from_directory('.', 'styles.css')

@app.route('/scanner')
def scanner_page():
    return send_from_directory('.', 'scanner.html')

@app.route('/honeypot')
def honeypot_page():
    return send_from_directory('.', 'honeypot.html')

@app.route('/script.js')
def script():
    return send_from_directory('.', 'script.js')

@app.route('/api/honeypots', methods=['GET'])
def get_honeypots():
    return jsonify(honeypot_manager.get_active_honeypots())

@app.route('/api/honeypots/deploy', methods=['POST'])
def deploy_honeypot():
    data = request.get_json()
    credentials = {
        'accessKeyId': data.get('accessKeyId'),
        'secretAccessKey': data.get('secretAccessKey')
    }
    hp_type = data.get('type')
    region = data.get('region')
    name = data.get('name')

    try:
        result = honeypot_manager.deploy_honeypot(credentials, hp_type, region, name)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/honeypots/terminate', methods=['POST'])
def terminate_honeypot():
    data = request.get_json()
    credentials = {
        'accessKeyId': data.get('accessKeyId'),
        'secretAccessKey': data.get('secretAccessKey')
    }
    honeypot_id = data.get('id')

    try:
        honeypot_manager.terminate_honeypot(credentials, honeypot_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/honeypots/simulate-attack', methods=['POST'])
def simulate_attack():
    data = request.get_json()
    honeypot_id = data.get('id')
    
    result = honeypot_manager.simulate_attack(honeypot_id)
    
    # Trigger Alert if simulation was successful (optional, but good for testing)
    if result.get('success'):
        # Construct a finding object from the result
        finding = {
            "id": f"sim-{int(time.time())}",
            "title": result.get('alert_type', 'Attack Simulated'),
            "severity": result.get('severity', 'HIGH'),
            "description": result.get('message'),
            "resource_id": honeypot_id,
            "service": "Honeypot",
            "recommendation": "This was a simulation.",
            "timestamp": datetime.now().isoformat()
        }
        alert_manager.dispatch_alert(finding)
        
    return jsonify(result)

@app.route('/api/honeytoken/<honeypot_id>', methods=['GET'])
def honeytoken_trigger(honeypot_id):
    # Log the access
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    logger.warning(f"HONEYTOKEN TRIGGERED: {honeypot_id} from IP {ip}")
    
    # Create a finding
    finding = {
        "id": f"ht-{int(time.time())}",
        "title": "Honeytoken Triggered",
        "severity": "CRITICAL",
        "resource_type": "Honeytoken",
        "resource_id": honeypot_id,
        "service": "S3/Web",
        "description": f"Confidential file accessed via Honeytoken. IP: {ip}, UA: {user_agent}",
        "timestamp": datetime.now().isoformat(),
        "recommendation": "Investigate immediately. This indicates a user opened the decoy file."
    }
    
    # Dispatch Alert
    alert_manager.dispatch_alert(finding)
    
    global RECENT_ALERTS
    if 'RECENT_ALERTS' not in globals():
        RECENT_ALERTS = []
    RECENT_ALERTS.append(finding)
    
    # Return a 1x1 transparent pixel
    # minimal 1x1 gif
    pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
    return send_file(io.BytesIO(pixel), mimetype='image/gif')

@app.route('/api/settings/alerts', methods=['GET', 'POST'])
def alert_settings():
    if request.method == 'POST':
        new_config = request.get_json()
        success = alert_manager.save_config(new_config)
        return jsonify({'success': success})
    else:
        return jsonify(alert_manager.config)

@app.route('/api/remediate', methods=['POST'])
def remediate():
    data = request.get_json()
    credentials = {
        'accessKeyId': data.get('accessKeyId'),
        'secretAccessKey': data.get('secretAccessKey')
    }
    finding_id = data.get('finding_id')
    resource_id = data.get('resource_id')
    issue_type = data.get('issue_type')
    region = data.get('region', 'us-east-1') # Default if not provided
    
    # Get AI Explanation first
    explanation = remediation_manager.get_ai_explanation(issue_type)
    
    # Perform Remediation
    result = remediation_manager.remediate_finding(credentials, finding_id, resource_id, issue_type, region)
    
    # Combine results
    result['explanation'] = explanation
    return jsonify(result)

@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.get_json()
    message = data.get('message', '')
    response = chat_manager.get_response(message)
    return jsonify({'response': response})

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    global RECENT_ALERTS
    if 'RECENT_ALERTS' not in globals():
        RECENT_ALERTS = []
    return jsonify(RECENT_ALERTS)

@app.route('/scan', methods=['POST'])
def scan():
    global LAST_SCAN_RESULTS
    data = request.get_json()
    access_key = data['accessKeyId']
    secret_key = data['secretAccessKey']

    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )

    scanner = AWSMisconfigurationScanner(session=session)
    results = scanner.run_scan()  # <-- adapt as needed for your class
    
    LAST_SCAN_RESULTS = results
    return jsonify(results)

@app.route('/demo-scan', methods=['POST'])
def demo_scan():
    global LAST_SCAN_RESULTS
    # Mock data for demonstration
    import time
    time.sleep(1.5) # Simulate network delay
    
    mock_results = {
        "scan_metadata": {
            "account_id": "123456789012",
            "timestamp": "2023-10-27T10:30:00",
            "total_findings": 5
        },
        "severity_distribution": {
            "CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM": 1,
            "LOW": 1
        },
        "service_distribution": {
            "S3": 2,
            "EC2": 1,
            "IAM": 1,
            "RDS": 1
        },
        "findings": [
            {
                "id": "s3-public-access-1",
                "service": "S3",
                "resource_id": "demo-public-bucket",
                "resource_type": "Bucket",
                "severity": "CRITICAL",
                "title": "S3 Bucket Publicly Readable",
                "description": "Bucket demo-public-bucket allows public read access",
                "recommendation": "Remove public read permissions and use IAM policies instead",
                "region": "global",
                "account_id": "123456789012",
                "timestamp": "2023-10-27T10:30:00"
            },
            {
                "id": "ec2-sg-open-1",
                "service": "EC2",
                "resource_id": "i-0abcdef1234567890",
                "resource_type": "Instance",
                "severity": "HIGH",
                "title": "EC2 Instance with Overly Permissive Security Group",
                "description": "Instance i-0abcdef1234567890 has security group allowing 0.0.0.0/0 access",
                "recommendation": "Restrict security group rules to specific IP ranges",
                "region": "us-east-1",
                "account_id": "123456789012",
                "timestamp": "2023-10-27T10:30:00"
            },
            {
                "id": "rds-no-encrypt-1",
                "service": "RDS",
                "resource_id": "demo-db-instance",
                "resource_type": "DB Instance",
                "severity": "HIGH",
                "title": "RDS Instance Not Encrypted",
                "description": "RDS instance demo-db-instance storage is not encrypted",
                "recommendation": "Enable encryption at rest for RDS instances",
                "region": "us-west-2",
                "account_id": "123456789012",
                "timestamp": "2023-10-27T10:30:00"
            },
            {
                "id": "iam-no-mfa-1",
                "service": "IAM",
                "resource_id": "demo-user",
                "resource_type": "User",
                "severity": "MEDIUM",
                "title": "IAM User with Access Keys but No MFA",
                "description": "User demo-user has programmatic access but no MFA enabled",
                "recommendation": "Enable MFA for all users with programmatic access",
                "region": "global",
                "account_id": "123456789012",
                "timestamp": "2023-10-27T10:30:00"
            },
            {
                "id": "s3-versioning-1",
                "service": "S3",
                "resource_id": "demo-logs-bucket",
                "resource_type": "Bucket",
                "severity": "LOW",
                "title": "S3 Bucket Versioning Disabled",
                "description": "Bucket demo-logs-bucket does not have versioning enabled",
                "recommendation": "Enable versioning to protect against accidental deletion/modification",
                "region": "global",
                "account_id": "123456789012",
                "timestamp": "2023-10-27T10:30:00"
            }
        ]
    }
    LAST_SCAN_RESULTS = mock_results
    return jsonify(mock_results)

import pandas as pd
import io

@app.route('/download-report')
def download_report():
    global LAST_SCAN_RESULTS
    if not LAST_SCAN_RESULTS:
        return jsonify({"error": "No scan results available"}), 404
    
    # Create Excel writer
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        # Findings Sheet
        findings = LAST_SCAN_RESULTS.get('findings', [])
        if findings:
            df_findings = pd.DataFrame(findings)
            df_findings.to_excel(writer, sheet_name='Findings', index=False)
        else:
            pd.DataFrame({'Info': ['No findings found']}).to_excel(writer, sheet_name='Findings', index=False)
            
        # Summary Sheet
        summary_data = {
            'Metric': ['Total Findings', 'Critical', 'High', 'Medium', 'Low', 'Account ID', 'Timestamp'],
            'Value': [
                LAST_SCAN_RESULTS.get('scan_metadata', {}).get('total_findings', 0),
                LAST_SCAN_RESULTS.get('severity_distribution', {}).get('CRITICAL', 0),
                LAST_SCAN_RESULTS.get('severity_distribution', {}).get('HIGH', 0),
                LAST_SCAN_RESULTS.get('severity_distribution', {}).get('MEDIUM', 0),
                LAST_SCAN_RESULTS.get('severity_distribution', {}).get('LOW', 0),
                LAST_SCAN_RESULTS.get('scan_metadata', {}).get('account_id', 'N/A'),
                LAST_SCAN_RESULTS.get('scan_metadata', {}).get('timestamp', 'N/A')
            ]
        }
        pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)

    output.seek(0)
    
    return send_file(
        output,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name='cloudshield_report.xlsx'
    )

if __name__ == '__main__':
    app.run(debug=True, port=8080)
