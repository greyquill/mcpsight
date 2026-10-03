// Google Analytics (GA4) for mcpsight.dev. See /privacy/ for what it collects.
(function () {
  "use strict";
  var GA_ID = "G-SPJPW7S0HT";
  // Count only the live site, so local previews do not pollute the numbers.
  if (location.hostname !== "mcpsight.dev") return;
  window.dataLayer = window.dataLayer || [];
  window.gtag = function () { window.dataLayer.push(arguments); };
  window.gtag("js", new Date());
  window.gtag("config", GA_ID);
  var s = document.createElement("script");
  s.async = true;
  s.src = "https://www.googletagmanager.com/gtag/js?id=" + GA_ID;
  document.head.appendChild(s);
})();
