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
    const blockingService = globalThis.OspreyBlockingService;
    const browserAPI = globalThis.OspreyBrowserAPI;
    const urlService = globalThis.OspreyUrlService;

    const tapsUpdatedDedupeDuration = 2000;
    const warningReadyDedupeDuration = 1500;
    const maxCacheSize = 1000;

    const navMap = new Map();
    const warnMap = new Map();

    const webNavigationEvents = [
        "onBeforeNavigate",
        "onCompleted",
        "onHistoryStateUpdated",
        "onReferenceFragmentUpdated",
        "onCreatedNavigationTarget",
    ];

    const setCache = (map, tabId, data) => {
        if (!map.has(tabId) && map.size >= maxCacheSize) {
            map.delete(map.keys().next().value);
        }
        map.set(tabId, data);
    };

    const isRecentNavigationDuplicate = (tabId, url, source) => {
        if (typeof tabId !== "number") {
            return false;
        }

        const now = Date.now();
        const state = navMap.get(tabId);

        if (state && state.url === url && now - state.timestamp <= tapsUpdatedDedupeDuration) {
            const prevSource = state.source;

            if (source === "tabs.onUpdated") {
                if (prevSource === "webNavigation") {
                    return true;
                }
            } else if (source === "webNavigation") {
                if (prevSource === "tabs.onUpdated" || prevSource === "webNavigation") {
                    return true;
                }
            }
        }

        if (state) {
            state.url = url;
            state.source = source;
            state.timestamp = now;
        } else {
            setCache(navMap, tabId, {url, source, timestamp: now});
        }
        return false;
    };

    const isWarningReadyDuplicate = (tabId, url) => {
        if (typeof tabId !== "number") {
            return false;
        }

        const now = Date.now();
        const state = warnMap.get(tabId);

        if (state && state.url === url && now - state.timestamp <= warningReadyDedupeDuration) {
            return true;
        }

        if (state) {
            state.url = url;
            state.timestamp = now;
        } else {
            setCache(warnMap, tabId, {url, timestamp: now});
        }
        return false;
    };

    const handleNavigation = (eventName, details, source) => {
        if (details?.frameId !== 0) {
            return;
        }

        const tabId = details.tabId;
        const url = details.url;

        if (urlService.isWarningPageUrl(url)) {
            if (isWarningReadyDuplicate(tabId, url)) {
                return;
            }

            blockingService.markWarningPageReady(tabId).catch(error => {
                console.error(`${eventName} warning-page update failed`, error);
            });
            return;
        }

        if (isRecentNavigationDuplicate(tabId, url, source)) {
            return;
        }

        blockingService.handleNavigation(details).catch(error => {
            console.error(`${eventName} failed`, error);
        });
    };

    const register = () => {
        const api = browserAPI.api;

        if (!api) {
            return;
        }

        const webNavigation = api.webNavigation;

        if (webNavigation) {
            for (const eventName of webNavigationEvents) {
                const eventObj = webNavigation[eventName];

                if (eventObj && typeof eventObj.addListener === "function") {
                    eventObj.addListener(details => {
                        handleNavigation(eventName, details, "webNavigation");
                    });
                }
            }
        }

        const tabs = api.tabs;

        if (tabs?.onUpdated && typeof tabs.onUpdated.addListener === "function") {
            tabs.onUpdated.addListener((tabId, changeInfo) => {
                if (!changeInfo?.url) {
                    return;
                }

                handleNavigation(
                    "tabs.onUpdated",
                    {tabId: tabId, frameId: 0, url: changeInfo.url},
                    "tabs.onUpdated"
                );
            });
        }

        if (tabs?.onRemoved && typeof tabs.onRemoved.addListener === "function") {
            tabs.onRemoved.addListener(tabObject => {
                const tabId = tabObject && typeof tabObject === "object" ? tabObject.tabId : tabObject;

                if (typeof tabId !== "number") {
                    return;
                }

                navMap.delete(tabId);
                warnMap.delete(tabId);
            });
        }
    };

    return Object.freeze({
        register
    });
})();
