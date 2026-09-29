// History page — delete scan entries

document.addEventListener('DOMContentLoaded', function () {
    var deleteButtons = document.querySelectorAll('.btn-sm--delete');

    deleteButtons.forEach(function (btn) {
        btn.addEventListener('click', function () {
            var scanId = this.getAttribute('data-scan-id');
            if (!confirm('Are you sure you want to delete this scan record?')) return;

            var row = this.closest('tr');

            fetch('/scan/' + scanId + '/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(function (resp) { return resp.json(); })
            .then(function (data) {
                if (data.success) {
                    row.style.transition = 'opacity 0.3s';
                    row.style.opacity = '0';
                    setTimeout(function () {
                        row.remove();
                        checkEmpty();
                    }, 300);
                }
            })
            .catch(function () {
                alert('Failed to delete scan. Please try again.');
            });
        });
    });

    function checkEmpty() {
        var rows = document.querySelectorAll('.history-table tbody tr');
        if (rows.length === 0) {
            var panel = document.querySelector('.panel');
            panel.innerHTML = '<div class="empty-state"><div class="empty-icon">📋</div><p>No scan history found.</p><a href="/scan" class="btn-primary">Run Your First Scan</a></div>';
        }
    }
});
