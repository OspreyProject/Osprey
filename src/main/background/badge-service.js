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

    const coalesceMs = 50;

    const appliedCountByTab = new Map();
    const desiredCountByTab = new Map();
    const pendingTimerByTab = new Map();

    const setColor = (tabId, method, color) => browserAPI[method]({color, tabId});

    const applyState = tabId => {
        pendingTimerByTab.delete(tabId);

        if (!desiredCountByTab.has(tabId)) {
            return Promise.resolve();
        }

        const count = desiredCountByTab.get(tabId);
        desiredCountByTab.delete(tabId);

        if (appliedCountByTab.get(tabId) === count) {
            return Promise.resolve();
        }

        appliedCountByTab.set(tabId, count);

        if (count === 0) {
            return browserAPI.actionSetBadgeText({tabId, text: ""}).catch(() => {
                // ignored
            });
        }

        return Promise.all([
            // Sets the badge text to the block count
            browserAPI.actionSetBadgeText({tabId, text: String(count)}),

            // Sets the badge background color to red
            setColor(tabId, "actionSetBadgeBackgroundColor", "#ff4b4b"),

            // Sets the badge text color to white
            setColor(tabId, "actionSetBadgeTextColor", "#ffffff")
        ]).catch(() => {
            // ignored
        });
    };

    const scheduleApply = tabId => {
        if (pendingTimerByTab.has(tabId)) {
            return;
        }

        pendingTimerByTab.set(tabId, setTimeout(() => {
            applyState(tabId).catch(() => {
                // ignored
            });
        }, coalesceMs));
    };

    const request = (tabId, count) => {
        if (typeof tabId !== "number") {
            return Promise.resolve();
        }

        desiredCountByTab.set(tabId, count);
        scheduleApply(tabId);
        return Promise.resolve();
    };

    const clear = tabId => request(tabId, 0);

    const clearTab = tabId => {
        if (typeof tabId !== "number") {
            return;
        }

        const pendingTimer = pendingTimerByTab.get(tabId);

        if (pendingTimer) {
            clearTimeout(pendingTimer);
        }

        pendingTimerByTab.delete(tabId);
        desiredCountByTab.delete(tabId);
        appliedCountByTab.delete(tabId);
    };

    const syncWithContext = (tabId, context) => {
        const count = Array.isArray(context?.origins) ? context.origins.length : 0;
        return request(tabId, count);
    };

    // Public API
    return Object.freeze({
        clear,
        clearTab,
        syncWithContext,
    });
})();
