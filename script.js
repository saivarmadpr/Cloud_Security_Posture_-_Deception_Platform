// Mock data for security findings
const securityFindings = [
    {
        id: "SEC-001",
        title: "S3 Bucket Publicly Accessible",
        severity: "critical",
        service: "S3",
        resource: "production-backup-bucket",
        description: "S3 bucket is configured with public read access, exposing sensitive data to unauthorized users.",
        recommendation: "Remove public access and implement IAM policies with least privilege access.",
        lastSeen: "2 hours ago"
    },
    {
        id: "SEC-002",
        title: "IAM Role with Admin Privileges",
        severity: "high",
        service: "IAM",
        resource: "ec2-instance-role",
        description: "IAM role has unnecessary administrative privileges attached.",
        recommendation: "Apply principle of least privilege and remove excessive permissions.",
        lastSeen: "2 hours ago"
    },
    {
        id: "SEC-003",
        title: "Security Group Open to Internet",
        severity: "high",
        service: "EC2",
        resource: "web-servers-sg",
        description: "Security group allows inbound traffic from 0.0.0.0/0 on port 22 (SSH).",
        recommendation: "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager.",
        lastSeen: "2 hours ago"
    },
    {
        id: "SEC-004",
        title: "Unencrypted RDS Instance",
        severity: "medium",
        service: "RDS",
        resource: "production-database",
        description: "RDS instance is not encrypted at rest, potentially exposing sensitive data.",
        recommendation: "Enable encryption at rest for the RDS instance and take encrypted snapshot.",
        lastSeen: "2 hours ago"
    }
];

// Mock messages for bot assistant
const initialMessages = [
    {
        type: "bot",
        content: "Welcome to CyberShield! I'm your security assistant. I can help you understand scan results, guide you through AWS configuration, or explain security findings.",
        timestamp: "now"
    },
    {
        type: "bot",
        content: "I notice you have 3 critical security issues. Would you like me to prioritize them by risk level?",
        timestamp: "2 min ago"
    }
];

let messages = [...initialMessages];
let isBotOpen = false;

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    renderFindings();
    renderMessages();
});

// Render security findings
function renderFindings() {
    const findingsList = document.getElementById('findingsList');
    
    findingsList.innerHTML = securityFindings.map(finding => `
        <div class="finding-item ${finding.severity}" onclick="toggleRecommendation('${finding.id}')">
            <div class="finding-header">
                <span class="severity-badge ${finding.severity}">${finding.severity}</span>
                <div class="finding-title">${finding.title}</div>
                <span class="finding-id">#${finding.id}</span>
            </div>
            
            <div class="finding-meta">
                <span>🏢 ${finding.service}</span>
                <span>📦 ${finding.resource}</span>
                <span>⏰ ${finding.lastSeen}</span>
            </div>
            
            <div class="finding-description">
                ${finding.description}
            </div>
            
            <div class="recommendation" id="rec-${finding.id}" style="display: none;">
                <div class="recommendation-text">
                    💡 <strong>Recommendation:</strong> ${finding.recommendation}
                </div>
            </div>
        </div>
    `).join('');
}

// Toggle recommendation visibility
function toggleRecommendation(findingId) {
    const recommendation = document.getElementById(`rec-${findingId}`);
    if (recommendation.style.display === 'none') {
        recommendation.style.display = 'block';
    } else {
        recommendation.style.display = 'none';
    }
}

// Bot assistant functions
function toggleBot() {
    const chatWindow = document.getElementById('chatWindow');
    const botIcon = document.getElementById('botIcon');
    
    isBotOpen = !isBotOpen;
    
    if (isBotOpen) {
        chatWindow.classList.add('open');
        botIcon.textContent = '✕';
    } else {
        chatWindow.classList.remove('open');
        botIcon.textContent = '💬';
    }
}

function renderMessages() {
    const chatMessages = document.getElementById('chatMessages');
    
    chatMessages.innerHTML = messages.map(message => `
        <div class="message ${message.type}">
            ${message.content}
            <div class="message-time">${message.timestamp}</div>
        </div>
    `).join('');
    
    // Scroll to bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    
    if (!message) return;
    
    // Add user message
    messages.push({
        type: "user",
        content: message,
        timestamp: "now"
    });
    
    input.value = '';
    renderMessages();
    
    // Simulate bot response
    setTimeout(() => {
        const botResponses = [
            "I understand you want to know more about that. Let me analyze your security posture and provide recommendations...",
            "Based on your current scan results, I recommend prioritizing the S3 bucket misconfiguration as it poses the highest risk.",
            "Would you like me to walk you through the steps to remediate this security finding?",
            "I can help you understand the AWS security best practices for this configuration.",
            "Let me provide you with a detailed remediation guide for this security issue."
        ];
        
        const randomResponse = botResponses[Math.floor(Math.random() * botResponses.length)];
        
        messages.push({
            type: "bot",
            content: randomResponse,
            timestamp: "now"
        });
        
        renderMessages();
    }, 1000);
}

function handleKeyPress(event) {
    if (event.key === 'Enter') {
        sendMessage();
    }
}

// Button click handlers
function startScan() {
    alert('Starting new AWS security scan...\n\nThis would typically open a configuration form to collect AWS credentials and scan parameters.');
}

function showCritical() {
    // Filter and highlight critical findings
    const criticalFindings = document.querySelectorAll('.finding-item.critical');
    criticalFindings.forEach(finding => {
        finding.style.animation = 'glow 1s ease-in-out 3';
        finding.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
}

function viewAllFindings() {
    alert('This would navigate to a detailed findings page with advanced filtering and export options.');
}

// Add some interactive animations
document.addEventListener('DOMContentLoaded', function() {
    // Animate status cards on load
    const statusCards = document.querySelectorAll('.status-card');
    statusCards.forEach((card, index) => {
        setTimeout(() => {
            card.style.animation = 'slideInUp 0.6s ease-out forwards';
        }, index * 100);
    });
    
    // Add hover effects to findings
    const findings = document.querySelectorAll('.finding-item');
    findings.forEach(finding => {
        finding.addEventListener('mouseenter', function() {
            this.style.transform = 'translateX(4px)';
        });
        
        finding.addEventListener('mouseleave', function() {
            this.style.transform = 'translateX(0)';
        });
    });
});

// Add slide-in animation
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInUp {
        from {
            opacity: 0;
            transform: translateY(30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);