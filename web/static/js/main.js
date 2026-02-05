/**
 * Secure Encryption Web Interface JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltips.forEach(tooltip => {
        new bootstrap.Tooltip(tooltip);
    });
    
    // File upload drag and drop
    const fileUploadAreas = document.querySelectorAll('.file-upload-area');
    fileUploadAreas.forEach(area => {
        const input = area.querySelector('input[type="file"]');
        
        area.addEventListener('click', () => input.click());
        
        area.addEventListener('dragover', (e) => {
            e.preventDefault();
            area.classList.add('dragover');
        });
        
        area.addEventListener('dragleave', () => {
            area.classList.remove('dragover');
        });
        
        area.addEventListener('drop', (e) => {
            e.preventDefault();
            area.classList.remove('dragover');
            
            if (e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                updateFileName(area, e.dataTransfer.files[0].name);
                triggerValidation(input);
            }
        });
        
        input.addEventListener('change', () => {
            if (input.files.length) {
                updateFileName(area, input.files[0].name);
            }
        });
    });
    
    // Password visibility toggle
    const togglePasswordBtns = document.querySelectorAll('.toggle-password');
    togglePasswordBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const input = this.previousElementSibling;
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
            
            // Toggle icon
            this.querySelector('i').className = type === 'password' 
                ? 'bi bi-eye' 
                : 'bi bi-eye-slash';
        });
    });
    
    // File size validation
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            const maxSize = 100 * 1024 * 1024; // 100MB
            const file = this.files[0];
            
            if (file && file.size > maxSize) {
                alert('File size exceeds 100MB limit. Please choose a smaller file.');
                this.value = '';
                
                // Reset file upload area
                const area = this.closest('.file-upload-area');
                if (area) {
                    const fileName = area.querySelector('.file-name');
                    if (fileName) fileName.textContent = 'No file chosen';
                }
            }
        });
    });
    
    // Form submission protection
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = this.querySelector('button[type="submit"]');
            
            // Prevent double submission
            if (submitBtn.disabled) {
                e.preventDefault();
                return;
            }
            
            // Add loading state
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner"></span> Processing...';
            
            // Add delay for encryption simulation
            if (this.id === 'encryptForm' || this.id === 'decryptForm') {
                setTimeout(() => {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = this.id === 'encryptForm' 
                        ? '<i class="bi bi-lock"></i> Encrypt File' 
                        : '<i class="bi bi-unlock"></i> Decrypt File';
                }, 1000);
            }
        });
    });
    
    // Security warnings
    const deleteOriginalCheckbox = document.querySelector('#delete_original');
    if (deleteOriginalCheckbox) {
        deleteOriginalCheckbox.addEventListener('change', function() {
            if (this.checked) {
                if (!confirm('⚠️ WARNING: This will PERMANENTLY delete your original file.\n\nMake sure you have backed up your file elsewhere.\n\nContinue?')) {
                    this.checked = false;
                }
            }
        });
    }
    
    // Auto-clear sensitive fields on page hide
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            const sensitiveInputs = document.querySelectorAll('input[type="password"]');
            sensitiveInputs.forEach(input => {
                // Don't clear if user is typing
                if (input !== document.activeElement) {
                    input.value = '';
                }
            });
        }
    });
    
    // Clipboard security
    document.addEventListener('copy', function(e) {
        const activeElement = document.activeElement;
        if (activeElement.type === 'password') {
            e.preventDefault();
            alert('For security reasons, copying from password fields is disabled.');
        }
    });
    
    // Initialize security badges
    updateSecurityBadges();
    
    // Performance monitoring
    if ('performance' in window) {
        const perfData = {
            pageLoad: performance.now(),
            memory: performance.memory ? performance.memory.usedJSHeapSize : 0
        };
        
        window.addEventListener('beforeunload', () => {
            perfData.pageUnload = performance.now();
            // Could send to analytics (anonymized)
        });
    }
});

/**
 * Update file name in upload area
 */
function updateFileName(area, fileName) {
    const fileNameElement = area.querySelector('.file-name');
    if (fileNameElement) {
        fileNameElement.textContent = fileName;
        fileNameElement.classList.add('text-success');
    }
}

/**
 * Trigger validation on input
 */
function triggerValidation(input) {
    const event = new Event('input', { bubbles: true });
    input.dispatchEvent(event);
}

/**
 * Update security badges based on page
 */
function updateSecurityBadges() {
    const badgesContainer = document.querySelector('.security-badges');
    if (!badgesContainer) return;
    
    const badges = [
        { text: 'AES-256-GCM', type: 'encrypted' },
        { text: 'End-to-End', type: 'secure' },
        { text: 'Client-Side', type: 'secure' },
        { text: 'Zero-Knowledge', type: 'secure' }
    ];
    
    badgesContainer.innerHTML = badges.map(badge => 
        `<span class="security-badge badge-${badge.type}">${badge.text}</span>`
    ).join('');
}

/**
 * Generate random password
 */
function generatePassword(length = 16) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let password = '';
    
    // Ensure at least one of each type
    password += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random() * 26)];
    password += 'abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random() * 26)];
    password += '0123456789'[Math.floor(Math.random() * 10)];
    password += '!@#$%^&*()'[Math.floor(Math.random() * 10)];
    
    // Fill rest randomly
    for (let i = 4; i < length; i++) {
        password += charset[Math.floor(Math.random() * charset.length)];
    }
    
    // Shuffle
    password = password.split('').sort(() => Math.random() - 0.5).join('');
    
    return password;
}

/**
 * Estimate password entropy
 */
function estimateEntropy(password) {
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
    
    if (charsetSize === 0) return 0;
    
    const entropy = password.length * Math.log2(charsetSize);
    return Math.round(entropy);
}

// Export functions for use in templates
window.SecureEncrypt = {
    generatePassword,
    estimateEntropy
};