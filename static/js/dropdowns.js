// Click-to-toggle dropdowns with basic keyboard support.
// - Click a .dropbtn to toggle its sibling .dropdown-content
// - Close on Escape or click outside
// - Enter/Space will activate a focused .dropbtn
(function(){
  function closeAll(){
    document.querySelectorAll('.dropdown-content.show').forEach(el=>el.classList.remove('show'));
    document.querySelectorAll('.dropbtn.open').forEach(b=>b.classList.remove('open'));
  }

  document.addEventListener('click', function(e){
    const btn = e.target.closest('.dropbtn');
    if(btn){
      e.preventDefault();
      const wrapper = btn.closest('.dropdown');
      if(!wrapper) return;
      const content = wrapper.querySelector('.dropdown-content');
      const wasOpen = content && content.classList.contains('show');
      // close others
      closeAll();
      if(!wasOpen && content){
        content.classList.add('show');
        btn.classList.add('open');
        // optional: focus first interactive inside
        const first = content.querySelector('a, button, [tabindex]');
        if(first) first.setAttribute('tabindex','0');
      }
      return;
    }
    // click outside any dropdown closes them
    if(!e.target.closest('.dropdown')) closeAll();
  });

  document.addEventListener('keydown', function(e){
    if(e.key === 'Escape'){
      closeAll();
      return;
    }
    if((e.key === 'Enter' || e.key === ' ') && document.activeElement && document.activeElement.classList.contains('dropbtn')){
      e.preventDefault();
      document.activeElement.click();
    }
  });

  document.addEventListener('DOMContentLoaded', function(){
    // Make dropbtns keyboard-focusable if they are anchors
    document.querySelectorAll('.dropbtn').forEach(b=>{
      if(b.tagName.toLowerCase() === 'a' && !b.hasAttribute('role')){
        b.setAttribute('role','button');
        b.setAttribute('aria-haspopup','true');
      }
    });
    // ensure all dropdowns start closed
    closeAll();
    // Mark the active sidebar link based on current path (accessible)
    (function markActiveNav(){
      try {
        const rawPath = window.location.pathname || '/';
        const curPath = rawPath.replace(/\/+$/,'') || '/';
        const anchors = document.querySelectorAll('.sidebar nav a');
        anchors.forEach(a => {
          try {
            const href = a.getAttribute('href') || '';
            // Resolve relative URLs against origin
            const url = new URL(href, window.location.origin);
            const aPath = (url.pathname || '/').replace(/\/+$/,'') || '/';
            if (aPath === curPath) {
              a.classList.add('active-page');
              a.setAttribute('aria-current','page');
            } else {
              a.classList.remove('active-page');
              a.removeAttribute('aria-current');
            }
          } catch(e) {
            // ignore malformed hrefs
          }
        });
      } catch (e) {
        console.warn('markActiveNav error', e);
      }
    })();
  });
})();
