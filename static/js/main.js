// Government Visitor Pass Management System - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize the application
    initializeApp();
});

function initializeApp() {
    // Auto-hide flash messages
    setTimeout(function() {
        const flashMessages = document.getElementById('flash-messages');
        if (flashMessages) {
            flashMessages.style.opacity = '0';
            setTimeout(() => flashMessages.remove(), 300);
        }
    }, 5000);

    // Initialize user type selection on login page
    initializeUserTypeSelection();
    
    // Initialize form validations
    initializeFormValidations();
    
    // Initialize tooltips and help text
    initializeTooltips();
    
    // Initialize keyboard shortcuts
    initializeKeyboardShortcuts();
    
    // Initialize accessibility features
    initializeAccessibility();
}

function initializeUserTypeSelection() {
    const userTypeCards = document.querySelectorAll('.user-type-card');
    const userTypeSelect = document.getElementById('userType');
    
    if (userTypeCards.length > 0 && userTypeSelect) {
        userTypeCards.forEach(card => {
            card.addEventListener('click', function() {
                const userType = this.getAttribute('data-type');
                
                // Remove selected class from all cards
                userTypeCards.forEach(c => c.classList.remove('selected'));
                
                // Add selected class to clicked card
                this.classList.add('selected');
                
                // Update select value
                userTypeSelect.value = userType;
                
                // Add visual feedback
                this.style.transform = 'scale(0.95)';
                setTimeout(() => {
                    this.style.transform = 'scale(1)';
                }, 150);
            });
        });
    }
}

function initializeFormValidations() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(this)) {
                e.preventDefault();
                showValidationErrors();
            }
        });
        
        // Real-time validation
        const inputs = form.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            input.addEventListener('blur', function() {
                validateField(this);
            });
            
            input.addEventListener('input', function() {
                clearFieldError(this);
            });
        });
    });
}

function validateForm(form) {
    let isValid = true;
    const requiredFields = form.querySelectorAll('[required]');
    
    requiredFields.forEach(field => {
        if (!validateField(field)) {
            isValid = false;
        }
    });
    
    return isValid;
}

function validateField(field) {
    const value = field.value.trim();
    const fieldType = field.type;
    let isValid = true;
    let errorMessage = '';
    
    // Required field validation
    if (field.hasAttribute('required') && !value) {
        isValid = false;
        errorMessage = 'This field is required';
    }
    
    // Email validation
    if (fieldType === 'email' && value) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(value)) {
            isValid = false;
            errorMessage = 'Please enter a valid email address';
        }
    }
    
    // Phone validation
    if (fieldType === 'tel' && value) {
        const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
        if (!phoneRegex.test(value.replace(/[\s\-$$$$]/g, ''))) {
            isValid = false;
            errorMessage = 'Please enter a valid phone number';
        }
    }
    
    // Password validation
    if (fieldType === 'password' && value) {
        if (value.length < 8) {
            isValid = false;
            errorMessage = 'Password must be at least 8 characters long';
        }
    }
    
    // Show/hide error
    if (isValid) {
        clearFieldError(field);
    } else {
        showFieldError(field, errorMessage);
    }
    
    return isValid;
}

function showFieldError(field, message) {
    clearFieldError(field);
    
    field.classList.add('form-error');
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'field-error text-red-600 text-sm mt-1';
    errorDiv.textContent = message;
    
    field.parentNode.appendChild(errorDiv);
}

function clearFieldError(field) {
    field.classList.remove('form-error');
    
    const existingError = field.parentNode.querySelector('.field-error');
    if (existingError) {
        existingError.remove();
    }
}

function showValidationErrors() {
    const firstError = document.querySelector('.form-error');
    if (firstError) {
        firstError.scrollIntoView({ behavior: 'smooth', block: 'center' });
        firstError.focus();
    }
}

function initializeTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', function() {
            showTooltip(this, this.getAttribute('data-tooltip'));
        });
        
        element.addEventListener('mouseleave', function() {
            hideTooltip();
        });
    });
}

function showTooltip(element, text) {
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip absolute bg-gray-900 text-white text-sm px-2 py-1 rounded shadow-lg z-50';
    tooltip.textContent = text;
    tooltip.id = 'active-tooltip';
    
    document.body.appendChild(tooltip);
    
    const rect = element.getBoundingClientRect();
    tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
    tooltip.style.top = rect.top - tooltip.offsetHeight - 5 + 'px';
}

function hideTooltip() {
    const tooltip = document.getElementById('active-tooltip');
    if (tooltip) {
        tooltip.remove();
    }
}

function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + / for help
        if ((e.ctrlKey || e.metaKey) && e.key === '/') {
            e.preventDefault();
            showKeyboardShortcuts();
        }
        
        // Escape to close modals
        if (e.key === 'Escape') {
            closeAllModals();
        }
        
        // Alt + L for logout
        if (e.altKey && e.key === 'l') {
            e.preventDefault();
            const logoutLink = document.querySelector('a[href*="logout"]');
            if (logoutLink) {
                logoutLink.click();
            }
        }
    });
}

function showKeyboardShortcuts() {
    const shortcuts = [
        { key: 'Ctrl + /', description: 'Show keyboard shortcuts' },
        { key: 'Escape', description: 'Close modals' },
        { key: 'Alt + L', description: 'Logout' },
        { key: 'Tab', description: 'Navigate between elements' },
        { key: 'Enter', description: 'Submit forms' }
    ];
    
    let shortcutHtml = '<div class="keyboard-shortcuts-modal fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">';
    shortcutHtml += '<div class="bg-white rounded-lg p-6 max-w-md w-full mx-4">';
    shortcutHtml += '<h3 class="text-lg font-semibold mb-4">Keyboard Shortcuts</h3>';
    shortcutHtml += '<div class="space-y-2">';
    
    shortcuts.forEach(shortcut => {
        shortcutHtml += `<div class="flex justify-between">`;
        shortcutHtml += `<span class="font-mono text-sm bg-gray-100 px-2 py-1 rounded">${shortcut.key}</span>`;
        shortcutHtml += `<span class="text-sm">${shortcut.description}</span>`;
        shortcutHtml += `</div>`;
    });
    
    shortcutHtml += '</div>';
    shortcutHtml += '<button onclick="this.parentElement.parentElement.remove()" class="mt-4 w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700">Close</button>';
    shortcutHtml += '</div></div>';
    
    document.body.insertAdjacentHTML('beforeend', shortcutHtml);
}

function closeAllModals() {
    const modals = document.querySelectorAll('.modal, .keyboard-shortcuts-modal, [id$="-modal"]');
    modals.forEach(modal => {
        if (modal.classList.contains('flex')) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        } else {
            modal.remove();
        }
    });
}

function initializeAccessibility() {
    // Add skip to content link
    const skipLink = document.createElement('a');
    skipLink.href = '#main-content';
    skipLink.className = 'skip-link';
    skipLink.textContent = 'Skip to main content';
    document.body.insertBefore(skipLink, document.body.firstChild);
    
    // Add main content landmark
    const mainContent = document.querySelector('main') || document.querySelector('.container');
    if (mainContent && !mainContent.id) {
        mainContent.id = 'main-content';
    }
    
    // Enhance focus management
    enhanceFocusManagement();
    
    // Add ARIA labels where needed
    addAriaLabels();
}

function enhanceFocusManagement() {
    // Trap focus in modals
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Tab') {
            const activeModal = document.querySelector('.modal:not(.hidden), [id$="-modal"]:not(.hidden)');
            if (activeModal) {
                trapFocus(e, activeModal);
            }
        }
    });
}

function trapFocus(e, container) {
    const focusableElements = container.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    
    if (e.shiftKey) {
        if (document.activeElement === firstElement) {
            e.preventDefault();
            lastElement.focus();
        }
    } else {
        if (document.activeElement === lastElement) {
            e.preventDefault();
            firstElement.focus();
        }
    }
}

function addAriaLabels() {
    // Add labels to buttons without text
    const iconButtons = document.querySelectorAll('button:not([aria-label]) i.fas');
    iconButtons.forEach(icon => {
        const button = icon.closest('button');
        if (button && !button.textContent.trim()) {
            const iconClass = Array.from(icon.classList).find(cls => cls.startsWith('fa-'));
            if (iconClass) {
                const label = iconClass.replace('fa-', '').replace('-', ' ');
                button.setAttribute('aria-label', label);
            }
        }
    });
    
    // Add labels to form controls
    const unlabeledInputs = document.querySelectorAll('input:not([aria-label]):not([id])');
    unlabeledInputs.forEach(input => {
        const placeholder = input.getAttribute('placeholder');
        if (placeholder) {
            input.setAttribute('aria-label', placeholder);
        }
    });
}

// Utility functions
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 ${getNotificationClass(type)}`;
    notification.innerHTML = `
        <div class="flex items-center">
            <i class="fas ${getNotificationIcon(type)} mr-2"></i>
            <span>${message}</span>
            <button onclick="this.parentElement.parentElement.remove()" class="ml-4 text-lg font-bold">&times;</button>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

function getNotificationClass(type) {
    const classes = {
        success: 'bg-green-100 text-green-800 border border-green-200',
        error: 'bg-red-100 text-red-800 border border-red-200',
        warning: 'bg-yellow-100 text-yellow-800 border border-yellow-200',
        info: 'bg-blue-100 text-blue-800 border border-blue-200'
    };
    return classes[type] || classes.info;
}

function getNotificationIcon(type) {
    const icons = {
        success: 'fa-check-circle',
        error: 'fa-exclamation-circle',
        warning: 'fa-exclamation-triangle',
        info: 'fa-info-circle'
    };
    return icons[type] || icons.info;
}

function formatDate(date) {
    return new Date(date).toLocaleDateString('en-IN', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}

function formatTime(time) {
    return new Date(`2000-01-01 ${time}`).toLocaleTimeString('en-IN', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    });
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// API helper functions
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    const config = { ...defaultOptions, ...options };
    
    try {
        const response = await fetch(url, config);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'An error occurred');
        }
        
        return data;
    } catch (error) {
        console.error('API Request Error:', error);
        showNotification(error.message, 'error');
        throw error;
    }
}

// Export functions for use in other scripts
window.GovVMS = {
    showNotification,
    apiRequest,
    formatDate,
    formatTime,
    debounce,
    throttle,
    validateForm,
    closeAllModals
};

// Service Worker registration for offline support
if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
        navigator.serviceWorker.register('/static/js/sw.js')
            .then(function(registration) {
                console.log('ServiceWorker registration successful');
            })
            .catch(function(error) {
                console.log('ServiceWorker registration failed');
            });
    });
}

// Performance monitoring
window.addEventListener('load', function() {
    // Log page load time
    const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
    console.log('Page load time:', loadTime + 'ms');
    
    // Monitor long tasks
    if ('PerformanceObserver' in window) {
        const observer = new PerformanceObserver((list) => {
            for (const entry of list.getEntries()) {
                if (entry.duration > 50) {
                    console.warn('Long task detected:', entry.duration + 'ms');
                }
            }
        });
        observer.observe({ entryTypes: ['longtask'] });
    }
});

// Error handling
window.addEventListener('error', function(e) {
    console.error('JavaScript Error:', e.error);
    // In production, you might want to send this to an error tracking service
});

window.addEventListener('unhandledrejection', function(e) {
    console.error('Unhandled Promise Rejection:', e.reason);
    // In production, you might want to send this to an error tracking service
});
