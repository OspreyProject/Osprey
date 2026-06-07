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

globalThis.OspreyNavigationService = (() => {
    // Global variables
    const blockingService = globalThis.OspreyBlockingService;
    const browserAPI = globalThis.OspreyBrowserAPI;
    const urlService = globalThis.OspreyUrlService;

    const recentNavigations = new Map();
    const tapsUpdatedDedupeDuration = 2000;

    const recentWarningReady = new Map();
    const warningReadyDedupeDuration = 1500;

    const webNavigationEvents = [
        "onBeforeNavigate",
        "onCompleted",
        "onHistoryStateUpdated",
        "onReferenceFragmentUpdated",
        "onCreatedNavigationTarget",
    ];

    const getNavigationKey = (tabId, url) => {
        if (typeof tabId !== "number") {
            return "";
        }

        const parsed = urlService.parseHttpUrl(url);
        return parsed ? `${tabId}::${urlService.normalizeUrl(parsed)}` : "";
    };

    const isRecentNavigationDuplicate = (tabId, url, source) => {
        const key = getNavigationKey(tabId, url);
        const recent = key && recentNavigations.get(key);

        if (!key) {
            return false;
        }

        if (recent) {
            if (Date.now() - recent.timestamp > tapsUpdatedDedupeDuration) {
                recentNavigations.delete(key);
            } else if (source === "tabs.onUpdated") {
                return recent.source === "webNavigation";
            } else if (source === "webNavigation") {
                return recent.source === "tabs.onUpdated" || recent.source === "webNavigation";
            }
        }

        recentNavigations.set(key, {source, timestamp: Date.now()});
        return false;
    };

    const pruneRecentNavigations = () => {
        const now = Date.now();

        for (const [key, recent] of recentNavigations) {
            if (now - recent.timestamp > tapsUpdatedDedupeDuration) {
                recentNavigations.delete(key);
            }
        }

        for (const [key, timestamp] of recentWarningReady) {
            if (now - timestamp > warningReadyDedupeDuration) {
                recentWarningReady.delete(key);
            }
        }
    };

    const isWarningReadyDuplicate = (tabId, url) => {
        if (typeof tabId !== "number") {
            return false;
        }

        const key = `${tabId}::${url}`;
        const now = Date.now();
        const last = recentWarningReady.get(key);

        if (last && now - last <= warningReadyDedupeDuration) {
            return true;
        }

        recentWarningReady.set(key, now);
        return false;
    };

    const handleNavigation = (eventName, details, source) => {
        pruneRecentNavigations();

        if (details?.frameId !== 0) {
            return;
        }

        if (urlService.isWarningPageUrl(details?.url)) {
            if (isWarningReadyDuplicate(details.tabId, details.url)) {
                return;
            }

            blockingService.markWarningPageReady(details.tabId).catch(error => {
                console.error(`${eventName} warning-page update failed`, error);
            });
            return;
        }

        if (isRecentNavigationDuplicate(details.tabId, details.url, source)) {
            return;
        }

        blockingService.handleNavigation(details).catch(error => {
            console.error(`${eventName} failed`, error);
        });
    };

    const register = () => {
        const tabs = browserAPI.api?.tabs;

        for (const eventName of webNavigationEvents) {
            browserAPI.api?.webNavigation?.[eventName]?.addListener(details => {
                handleNavigation(eventName, details, "webNavigation");
            });
        }

        tabs?.onUpdated?.addListener((tabId, changeInfo) => {
            if (!changeInfo?.url) {
                return;
            }

            handleNavigation(
                `tabs.onUpdated for tab ${tabId}`,
                {tabId, frameId: 0, url: changeInfo.url},
                "tabs.onUpdated"
            );
        });

        tabs?.onRemoved?.addListener(tabId => {
            for (const key of recentNavigations.keys()) {
                if (key.startsWith(`${tabId}::`)) {
                    recentNavigations.delete(key);
                }
            }

            for (const key of recentWarningReady.keys()) {
                if (key.startsWith(`${tabId}::`)) {
                    recentWarningReady.delete(key);
                }
            }
        });
    };

    // Public API
    return Object.freeze({
        register
    });
})();
