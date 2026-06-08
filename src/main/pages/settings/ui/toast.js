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
    const formHelpers = globalThis.OspreyFormHelpers;

    const maxToasts = 5;
    const durationMs = 5000;
    let container = null;

    const nodes = new Array(maxToasts);
    const timers = new Int32Array(maxToasts);
    const sequenceIds = new Float64Array(maxToasts);
    const activeStates = new Uint8Array(maxToasts);
    let sequenceCounter = 0;

    function getContainer() {
        if (container) {
            return container;
        }

        container = formHelpers.createElement('div', {
            className: 'toast-container'
        });

        container.addEventListener('click', (e) => {
            const card = e.target.closest('.toast-notification');

            if (card?._poolIndex !== undefined) {
                const idx = card._poolIndex;

                if (activeStates[idx] === 1) {
                    dismiss(idx);
                }
            }
        });

        container.addEventListener('transitionend', (e) => {
            const card = e.target;

            if (card.classList?.contains('toast-notification') && !card.classList.contains('toast-visible')) {
                card.style.display = 'none';
            }
        });

        (document.body ?? document.documentElement).appendChild(container);
        return container;
    }

    function dismiss(index) {
        if (activeStates[index] === 0) {
            return;
        }

        const card = nodes[index];
        card.classList.remove('toast-visible');

        if (timers[index] !== 0) {
            globalThis.clearTimeout(timers[index]);
            timers[index] = 0;
        }

        activeStates[index] = 0;
    }

    function show(message, isError = false) {
        const toastContainer = getContainer();

        let targetIndex = -1;
        let oldestIndex = -1;
        let oldestSeq = Infinity;

        for (let i = 0; i < maxToasts; i++) {
            if (activeStates[i] === 0) {
                targetIndex = i;
                break;
            }

            if (sequenceIds[i] < oldestSeq) {
                oldestSeq = sequenceIds[i];
                oldestIndex = i;
            }
        }

        if (targetIndex === -1) {
            targetIndex = oldestIndex;
            dismiss(targetIndex);
        }

        let card = nodes[targetIndex];

        if (!card) {
            card = formHelpers.createElement('div', {
                className: 'toast-notification'
            });

            card._poolIndex = targetIndex;
            card.style.display = 'none';
            toastContainer.appendChild(card);
            nodes[targetIndex] = card;
        }

        sequenceIds[targetIndex] = ++sequenceCounter;
        activeStates[targetIndex] = 1;

        card.textContent = message;
        card.className = `toast-notification ${isError ? 'toast-error' : 'toast-success'}`;
        card.style.display = '';
        card.style.pointerEvents = 'auto';

        globalThis.requestAnimationFrame(() => {
            globalThis.requestAnimationFrame(() => {
                if (activeStates[targetIndex] === 1) {
                    card.classList.add('toast-visible');
                }
            });
        });

        timers[targetIndex] = globalThis.setTimeout(() => dismiss(targetIndex), durationMs);
    }

    return Object.freeze({
        show
    });
})();
