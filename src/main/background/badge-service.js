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

globalThis.OspreyBadgeService = (() => {
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;

    const ignore = () => undefined;
    const badgeCounts = new Map();
    const setColor = (tabId, method, color) => browserAPI[method]({tabId, color});
    const clear = tabId => {
        if (badgeCounts.get(tabId) === 0) {
            return Promise.resolve();
        }

        badgeCounts.set(tabId, 0);
        return browserAPI.actionSetBadgeText({tabId, text: ""}).catch(ignore);
    };

    const set = (tabId, count) => {
        if (badgeCounts.get(tabId) === count) {
            return Promise.resolve();
        }

        badgeCounts.set(tabId, count);
        return Promise.all([
        // Sets the badge text to the block count
        browserAPI.actionSetBadgeText({tabId, text: String(count)}),

        // Sets the badge background color to red
        setColor(tabId, "actionSetBadgeBackgroundColor", "#ff4b4b"),

        // Sets the badge text color to white
        setColor(tabId, "actionSetBadgeTextColor", "#ffffff")
    ]).catch(ignore);
    };

    const syncWithContext = (tabId, context) => {
        // Sets the count on the badge if there are blocked origins, otherwise clears the badge
        const count = Array.isArray(context?.origins) ? context.origins.length : 0;
        return (count > 0 ? set : clear)(tabId, count);
    };

    // Public API
    return Object.freeze({
        clear,
        set,
        syncWithContext,
    });
})();
