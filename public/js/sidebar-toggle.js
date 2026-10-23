(() => {
    const button = document.querySelector('.sidebar-toggle');
    if (!button) return;

    const storageKey = 'faculty-booking-sidebar-hidden';
    const setHidden = (hidden) => {
        document.body.classList.toggle('sidebar-collapsed', hidden);
        button.setAttribute('aria-expanded', String(!hidden));
        const label = hidden ? 'Show navigation' : 'Hide navigation';
        button.setAttribute('aria-label', label);
        button.setAttribute('title', label);
    };

    let hidden = false;
    try { hidden = window.localStorage.getItem(storageKey) === 'true'; } catch (_) {}
    setHidden(hidden);

    button.addEventListener('click', () => {
        hidden = !document.body.classList.contains('sidebar-collapsed');
        setHidden(hidden);
        try { window.localStorage.setItem(storageKey, String(hidden)); } catch (_) {}
    });
})();
