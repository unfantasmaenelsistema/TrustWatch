/* Tema e idioma guardados, antes de pintar. */
(function () {
  var d = document.documentElement;
  try {
    var t = localStorage.getItem('tw_theme');
    if (t === 'light' || t === 'dark') d.setAttribute('data-theme', t);
    else if (window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches) d.setAttribute('data-theme', 'light');
    var l = localStorage.getItem('tw_lang');
    d.lang = l === 'en' || l === 'es' ? l : (/^es\b/i.test(navigator.language || '') ? 'es' : 'en');
  } catch (e) { d.lang = 'es'; }
})();
