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
    const api = globalThis.browser ?? globalThis.chrome;

    const noOpResolve = Promise.resolve(undefined);

    const invoke = (context, fn, argCount, arg1, arg2) => {
        if (typeof fn !== "function") {
            return noOpResolve;
        }

        return new Promise((resolve, reject) => {
            let settled = false;

            const settle = (isErr, val) => {
                if (settled) {
                    return;
                }

                settled = true;

                if (isErr) {
                    reject(val);
                } else {
                    resolve(val);
                }
            };

            const cb = (result) => {
                if (settled) {
                    return;
                }

                const err = api?.runtime?.lastError;

                if (err) {
                    settle(true, new Error(err.message));
                } else {
                    settle(false, result);
                }
            };

            try {
                let result;

                if (argCount === 2) {
                    result = fn.call(context, arg1, arg2, cb);
                } else if (argCount === 1) {
                    result = fn.call(context, arg1, cb);
                } else {
                    result = fn.call(context, cb);
                }

                if (result != null && typeof result.then === "function") {
                    result.then(
                        (res) => settle(false, res),
                        (err) => settle(true, err)
                    );
                }
            } catch (error) {
                settle(true, error);
            }
        });
    };

    const withCallback = (fn, context, args = []) => {
        if (typeof fn !== "function") {
            console.warn("OspreyBrowserAPI.withCallback called with an unavailable API function");
            return noOpResolve;
        }

        return new Promise((resolve, reject) => {
            let settled = false;

            const settle = (isErr, val) => {
                if (settled) {
                    return;
                }

                settled = true;

                if (isErr) {
                    reject(val);
                } else {
                    resolve(val);
                }
            };

            const cb = (result) => {
                if (settled) {
                    return;
                }

                const err = api?.runtime?.lastError;

                if (err) {
                    settle(true, new Error(err.message));
                } else {
                    settle(false, result);
                }
            };

            try {
                const len = args.length;
                const callArgs = new Array(len + 1);

                for (let i = 0; i < len; i++) {
                    callArgs[i] = args[i];
                }

                callArgs[len] = cb;
                const result = fn.apply(context, callArgs);

                if (result != null && typeof result.then === "function") {
                    result.then(
                        (res) => settle(false, res),
                        (err) => settle(true, err)
                    );
                }
            } catch (error) {
                console.error("Browser API call threw before completion", error);
                settle(true, error);
            }
        });
    };

    let cachedGetURL;

    const safeRuntimeURL = (path) => {
        try {
            if (cachedGetURL === undefined) {
                cachedGetURL = api?.runtime?.getURL || null;
            }
            return cachedGetURL ? cachedGetURL.call(api.runtime, path) : path;
        } catch (error) {
            console.warn("Failed to resolve runtime URL", error);
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
        tabsCreate: (createProperties) => invoke(api?.tabs, api?.tabs?.create, 1, createProperties),

        notificationsCreate: (options, notificationId = undefined) => notificationId === undefined ?
            invoke(api?.notifications, api?.notifications?.create, 1, options) :
            invoke(api?.notifications, api?.notifications?.create, 2, notificationId, options),

        actionSetBadgeText: (details) => invoke(api?.action, api?.action?.setBadgeText, 1, details),
        actionSetBadgeBackgroundColor: (details) => invoke(api?.action, api?.action?.setBadgeBackgroundColor, 1, details),
        actionSetBadgeTextColor: (details) => invoke(api?.action, api?.action?.setBadgeTextColor, 1, details),

        runtimeSendMessage: (message) => invoke(api?.runtime, api?.runtime?.sendMessage, 1, message),
        runtimeOpenOptionsPage: () => invoke(api?.runtime, api?.runtime?.openOptionsPage, 0),

        safeRuntimeURL,
    });
})();
