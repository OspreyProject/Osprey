/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"use strict";

globalThis.OspreyToast = (() => {
    // Global variables
    const formHelpers = globalThis.OspreyFormHelpers;

    const maxToasts = 5;
    const durationMs = 5000;
    let container = null;

    function getContainer() {
        if (container) {
            return container;
        }

        container = formHelpers.createElement('div', {
            className: 'toast-container'
        });

        // Append to documentElement rather than body for consistent behavior
        (document.body ?? document.documentElement).appendChild(container);
        return container;
    }

    function dismiss(card) {
        card.classList.remove('toast-visible');
        card.addEventListener('transitionend', () => card.remove(), {once: true});
    }

    function show(message, isError = false) {
        const toastContainer = getContainer();

        if (toastContainer.childElementCount >= maxToasts) {
            dismiss(toastContainer.querySelector('.toast-notification'));
        }

        const card = formHelpers.createElement('div', {
            className: `toast-notification ${isError ? 'toast-error' : 'toast-success'}`,
            textContent: message,
        });

        toastContainer.appendChild(card);
        card.getBoundingClientRect();
        card.classList.add('toast-visible');

        const timer = globalThis.setTimeout(() => dismiss(card), durationMs);
        card.style.pointerEvents = 'auto';

        card.addEventListener('click', () => {
            globalThis.clearTimeout(timer);
            dismiss(card);
        }, {once: true});
    }

    // Public API
    return Object.freeze({
        show
    });
})();
