// Toast notifications and HTMX event handling
document.body.addEventListener('showToast', function(e) {
    var toast = document.getElementById('toast');
    if (toast) {
        toast.textContent = (e.detail && e.detail.message) || 'Done';
        toast.className = 'toast';
        setTimeout(function() { toast.className = ''; }, 3000);
    }
});
