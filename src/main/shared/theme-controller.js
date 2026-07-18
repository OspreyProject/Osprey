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
'use strict';

globalThis.OspreyTheme = globalThis.OspreyTheme || (() => {
    const storageKey = 'darkMode';
    const mirrorKey = 'osprey_dark_mode';
    const defaultDarkMode = true;

    const api = globalThis.chrome ?? globalThis.browser;
    const root = document.documentElement;

    let currentDarkMode = defaultDarkMode;

    const readMirror = () => {
        try {
            const stored = globalThis.localStorage?.getItem(mirrorKey);

            if (stored === '0') {
                return false;
            }

            if (stored === '1') {
                return true;
            }
        } catch {
            // ignored
        }
        return defaultDarkMode;
    };

    const writeMirror = darkMode => {
        try {
            globalThis.localStorage?.setItem(mirrorKey, darkMode ? '1' : '0');
        } catch {
            // ignored
        }
    };

    const applyAttribute = darkMode => {
        root.dataset.theme = darkMode ? 'dark' : 'light';
    };

    const apply = (darkMode, {persistMirror = true} = {}) => {
        currentDarkMode = Boolean(darkMode);
        applyAttribute(currentDarkMode);

        if (persistMirror) {
            writeMirror(currentDarkMode);
        }
    };

    apply(readMirror(), {persistMirror: false});

    const readStored = () => new Promise(resolve => {
        try {
            const result = api?.storage?.local?.get?.(storageKey);

            if (result && typeof result.then === 'function') {
                result.then(
                    data => resolve(data),
                    () => resolve(null),
                );
                return;
            }

            api?.storage?.local?.get?.(storageKey, data => resolve(data));
        } catch {
            resolve(null);
        }
    });

    const writeStored = darkMode => {
        try {
            const result = api?.storage?.local?.set?.({[storageKey]: darkMode});

            if (result && typeof result.catch === 'function') {
                result.catch(error => console.error('OspreyTheme failed to persist darkMode', error));
            }
        } catch (error) {
            console.error('OspreyTheme failed to persist darkMode', error);
        }
    };

    readStored().then(data => {
        const stored = data?.[storageKey];
        const darkMode = typeof stored === 'boolean' ? stored : defaultDarkMode;

        apply(darkMode);
    });

    const setDarkMode = darkMode => {
        apply(darkMode);
        writeStored(currentDarkMode);
    };

    const toggle = () => setDarkMode(!currentDarkMode);

    document.addEventListener('click', event => {
        const target = event.target;

        if (target && typeof target.closest === 'function' && target.closest('.theme-toggle')) {
            toggle();
        }
    });

    try {
        api?.storage?.onChanged?.addListener?.((changes, area) => {
            if (area === 'local' && changes && Object.hasOwn(changes, storageKey)) {
                const next = changes[storageKey].newValue;
                apply(typeof next === 'boolean' ? next : defaultDarkMode);
            }
        });
    } catch {
        // ignored
    }

    return Object.freeze({
        isDarkMode: () => currentDarkMode,
        setDarkMode,
        toggle,
    });
})();
