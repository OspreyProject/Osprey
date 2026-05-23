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

globalThis.OspreyI18n = (() => {
    const translate = (key, substitutions) => {
        if (typeof key !== 'string' || key.length === 0) {
            console.warn(`OspreyI18n.translate called with invalid key: '${key}'`);
            return '';
        }

        try {
            return globalThis.OspreyBrowserAPI.api?.i18n?.getMessage?.(key, substitutions) || key;
        } catch (error) {
            console.error(`OspreyI18n: failed to translate key '${key}'`, error);
            return key;
        }
    };

    // Public API
    return Object.freeze({
        translate,
    });
})();
