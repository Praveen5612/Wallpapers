// static/js/script.js

document.addEventListener("DOMContentLoaded", function () {
    const themeSelect = document.getElementById("themeSwitcher");
    const body = document.body;

    // Load saved theme
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme) {
        body.classList.add("theme-" + savedTheme);
        themeSelect.value = savedTheme;
    }

    themeSelect.addEventListener("change", function () {
        const value = this.value;

        // Remove all themes
        body.classList.remove("theme-light", "theme-dark", "theme-bg");

        // Apply selected theme
        body.classList.add("theme-" + value);

        // Save it to localStorage
        localStorage.setItem("theme", value);
    });
});
