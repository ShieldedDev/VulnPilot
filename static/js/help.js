// Help page — smooth navigation & active link highlighting

document.addEventListener('DOMContentLoaded', function () {

    var navLinks = document.querySelectorAll('.help-nav-link');

    // Highlight active section on scroll
    var sections = document.querySelectorAll('.help-section');

    function onScroll() {
        var scrollPos = window.scrollY + 100;
        sections.forEach(function (section) {
            var top = section.offsetTop;
            var bottom = top + section.offsetHeight;
            var id = section.getAttribute('id');

            if (scrollPos >= top && scrollPos < bottom) {
                navLinks.forEach(function (link) {
                    link.style.borderLeftColor = 'transparent';
                    link.style.color = '';
                });
                var active = document.querySelector('.help-nav-link[href="#' + id + '"]');
                if (active) {
                    active.style.borderLeftColor = 'var(--accent)';
                    active.style.color = 'var(--accent)';
                }
            }
        });
    }

    window.addEventListener('scroll', onScroll);
    onScroll();
});
