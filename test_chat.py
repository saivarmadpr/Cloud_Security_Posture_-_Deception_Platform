from ChatManager import ChatManager

cm = ChatManager()

queries = [
    "Hello",
    "How to fix S3?",
    "What is a honeypot?",
    "Run scan",
    "Help me"
]

for q in queries:
    print(f"User: {q}")
    print(f"Bot: {cm.get_response(q)}")
    print("-" * 20)
