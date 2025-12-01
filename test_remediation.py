from RemediationManager import RemediationManager
import json

try:
    rm = RemediationManager()
    explanation = rm.get_ai_explanation("S3_PUBLIC_ACCESS")
    print("Explanation retrieved successfully")
    print(json.dumps(explanation, indent=2))
except Exception as e:
    print(f"Error: {e}")
