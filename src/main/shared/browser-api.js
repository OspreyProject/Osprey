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

globalThis.OspreyBrowserAPI = (() => {
    const api = globalThis.browser ?? globalThis.chrome;

    const invoke = (context, fn, argCount, arg1, arg2) => {
        if (typeof fn !== 'function') {
            return Promise.resolve(undefined);
        }

        try {
            let result;

            if (argCount === 2) {
                result = fn.call(context, arg1, arg2);
            } else if (argCount === 1) {
                result = fn.call(context, arg1);
            } else {
                result = fn.call(context);
            }

            if (result != null && typeof result.then === 'function') {
                return result;
            }
            return Promise.resolve(result);
        } catch (error) {
            return Promise.reject(error);
        }
    };

    const withCallback = (fn, context, args = []) => {
        if (typeof fn !== 'function') {
            console.warn('OspreyBrowserAPI.withCallback called with an unavailable API function');
            return Promise.resolve(undefined);
        }

        try {
            const result = fn.apply(context, args);

            if (result != null && typeof result.then === 'function') {
                return result;
            }
            return Promise.resolve(result);
        } catch (error) {
            console.error('Browser API call threw before completion', error);
            return Promise.reject(error);
        }
    };

    let cachedGetURL;

    const safeRuntimeURL = path => {
        try {
            if (cachedGetURL === undefined) {
                cachedGetURL = api?.runtime?.getURL || null;
            }
            return cachedGetURL ? cachedGetURL.call(api.runtime, path) : path;
        } catch (error) {
            console.warn('Failed to resolve runtime URL', error);
            return path;
        }
    };

    return Object.freeze({
        api,
        withCallback,

        storageGet: (area, keys = null) => {
            const ctx = api?.storage?.[area];
            return invoke(ctx, ctx?.get, 1, keys);
        },

        storageSet: (area, value) => {
            const ctx = api?.storage?.[area];
            return invoke(ctx, ctx?.set, 1, value);
        },

        storageRemove: (area, keys) => {
            const ctx = api?.storage?.[area];
            return invoke(ctx, ctx?.remove, 1, keys);
        },

        tabsUpdate: (tabId, updateProperties) => invoke(api?.tabs, api?.tabs?.update, 2, tabId, updateProperties),
        tabsCreate: createProperties => invoke(api?.tabs, api?.tabs?.create, 1, createProperties),

        actionSetBadgeText: details => invoke(api?.action, api?.action?.setBadgeText, 1, details),
        actionSetBadgeBackgroundColor: details => invoke(api?.action, api?.action?.setBadgeBackgroundColor, 1, details),
        actionSetBadgeTextColor: details => invoke(api?.action, api?.action?.setBadgeTextColor, 1, details),

        runtimeSendMessage: message => invoke(api?.runtime, api?.runtime?.sendMessage, 1, message),
        runtimeOpenOptionsPage: () => invoke(api?.runtime, api?.runtime?.openOptionsPage, 0),

        safeRuntimeURL,
    });
})();
