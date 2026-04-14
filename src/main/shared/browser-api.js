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

globalThis.OspreyBrowserAPI = (() => {
    const api = globalThis.chrome ?? globalThis.browser;
    const isFirefox = api !== globalThis.chrome;

    const withCallback = (fn, context, args = []) => new Promise((resolve, reject) => {
        if (typeof fn !== "function") {
            console.warn("OspreyBrowserAPI.withCallback called with an unavailable API function");
            resolve(undefined);
            return;
        }

        let settled = false;

        const settle = (done, value) => {
            if (!settled) {
                settled = true;
                done(value);
            }
        };

        const callback = result => {
            const lastError = api?.runtime?.lastError;

            if (lastError) {
                settle(reject, new Error(lastError.message));
                return;
            }

            settle(resolve, result);
        };

        try {
            if (isFirefox) {
                const maybePromise = fn.call(context, ...args);
                Promise.resolve(maybePromise).then(
                    value => settle(resolve, value),
                    error => settle(reject, error)
                );
                return;
            }

            fn.call(context, ...args, callback);
        } catch (error) {
            console.error('Browser API call threw before completion', error);
            settle(reject, error);
        }
    });

    const call = (path, ...args) => {
        const context = path.slice(0, -1).reduce((value, key) => value?.[key], api);
        return withCallback(context?.[path[path.length - 1]], context, args);
    };

    const safeRuntimeURL = path => {
        try {
            return api?.runtime?.getURL ? api.runtime.getURL(path) : path;
        } catch (error) {
            console.warn(`Failed to resolve runtime URL for path '${path}'`, error);
            return path;
        }
    };

    // Public API
    return Object.freeze({
        api,
        withCallback,
        call,

        storageGet: (area, keys = null) => call(['storage', area, 'get'], keys),
        storageSet: (area, value) => call(['storage', area, 'set'], value),
        tabsGet: tabId => call(['tabs', 'get'], tabId),
        tabsUpdate: (tabId, updateProperties) => call(['tabs', 'update'], tabId, updateProperties),
        tabsCreate: createProperties => call(['tabs', 'create'], createProperties),
        tabsSendMessage: (tabId, message) => call(['tabs', 'sendMessage'], tabId, message),

        notificationsCreate: (options, notificationId = undefined) => notificationId ?
            call(['notifications', 'create'], notificationId, options) :
            call(['notifications', 'create'], options),

        actionSetBadgeText: details => call(['action', 'setBadgeText'], details),
        actionSetBadgeBackgroundColor: details => call(['action', 'setBadgeBackgroundColor'], details),
        actionSetBadgeTextColor: details => call(['action', 'setBadgeTextColor'], details),
        runtimeSendMessage: message => call(['runtime', 'sendMessage'], message),
        runtimeOpenOptionsPage: () => call(['runtime', 'openOptionsPage']),

        safeRuntimeURL,
    });
})();
