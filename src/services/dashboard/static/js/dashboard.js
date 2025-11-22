/**
 * CobaltGraph Dashboard - Common JavaScript
 * Shared functionality across all dashboard pages
 */

// Initialize WebSocket connection on page load
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 CobaltGraph Dashboard initializing...');

    // Note: WebSocket connection is initialized by page-specific scripts
    // This file contains shared utilities
});

/**
 * Format timestamp for display
 * @param {string} timestamp - ISO timestamp string
 * @returns {string} Formatted time ago string
 */
function formatTimeAgo(timestamp) {
    if (!timestamp) return '-';

    const date = new Date(timestamp);
    const now = new Date();
    const diff = Math.floor((now - date) / 1000); // seconds

    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
}

/**
 * Format timestamp as locale string
 * @param {string} timestamp - ISO timestamp string
 * @returns {string} Formatted date/time string
 */
function formatDateTime(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Show toast notification (Bootstrap 5)
 * @param {string} title - Toast title
 * @param {string} message - Toast message
 * @param {string} type - Toast type (success, warning, danger, info)
 */
function showToast(title, message, type = 'info') {
    console.log(`📬 ${title}: ${message}`);
    // TODO: Implement Bootstrap toast UI
    // For now, just log to console
}

// Export utilities to global scope
window.formatTimeAgo = formatTimeAgo;
window.formatDateTime = formatDateTime;
window.escapeHtml = escapeHtml;
window.showToast = showToast;
