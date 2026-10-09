/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
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

/**
 * Blocks the notification permission for origins Osprey has flagged, so a scam site the
 * user proceeds past can never weaponize the notification prompt. A persisted registry
 * records every origin Osprey set, and only registry entries are ever cleared: the user's
 * own notification choices on other sites are never touched. Firefox has no
 * chrome.contentSettings; the service feature-detects and degrades, recording once.
 */
globalThis.OspreyNotificationService = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const storageKey = 'osprey_notification_origins';

    const contentSettings = () => globalThis.chrome?.contentSettings || globalThis.browser?.contentSettings;
    const storage = () => browserAPI?.storage?.local || globalThis.chrome?.storage?.local;

    let unavailableLogged = false;
    let queue = Promise.resolve();

    // Registry updates are read-modify-write, so they run one at a time or concurrent updates drop each other's entries.
    const serialize = task => {
        const run = queue.then(task);

        queue = run.catch(() => {
            // ignored
        });
        return run;
    };

    const originPattern = url => {
        try {
            const parsed = new URL(url);
            return parsed.protocol.startsWith('http') ? parsed.origin + '/*' : null;
        } catch {
            return null;
        }
    };

    // Resolves null when the registry cannot be read, so callers never write back a registry that looks empty.
    const readRegistry = async () => {
        const store = storage();

        if (!store?.get) {
            return null;
        }

        const data = await new Promise(resolve => {
            try {
                const result = store.get(storageKey, value => {
                    resolve(globalThis.chrome?.runtime?.lastError ? null : value || {});
                });

                if (result?.then) {
                    result.then(value => resolve(value || {}), () => resolve(null));
                }
            } catch {
                resolve(null);
            }
        });

        if (data === null) {
            return null;
        }

        const entry = data[storageKey];
        return entry && typeof entry === 'object' ? entry : {};
    };

    const writeRegistry = async registry => {
        const store = storage();

        if (!store?.set) {
            return false;
        }

        return new Promise(resolve => {
            try {
                const result = store.set({[storageKey]: registry}, () => resolve(!globalThis.chrome?.runtime?.lastError));

                if (result?.then) {
                    result.then(() => resolve(true), () => resolve(false));
                }
            } catch {
                resolve(false);
            }
        });
    };

    const setNotificationSetting = (pattern, setting) => new Promise(resolve => {
        const api = contentSettings();

        if (!api?.notifications?.set) {
            resolve(false);
            return;
        }

        try {
            // No per-pattern clear exists in the API, so the reset path re-sets the
            // pattern to 'ask', the browser default.
            const result = api.notifications.set({
                primaryPattern: pattern,
                setting: setting === null ? 'ask' : setting
            }, () => resolve(!globalThis.chrome?.runtime?.lastError));

            if (result?.then) {
                result.then(() => resolve(true), () => resolve(false));
            }
        } catch {
            resolve(false);
        }
    });

    /**
     * Blocks notifications for the origin of a flagged URL and records it, so only
     * Osprey-created entries are ever reverted.
     */
    const blockForUrl = async url => {
        if (!contentSettings()) {
            if (!unavailableLogged) {
                unavailableLogged = true;
                await globalThis.OspreyEventLogService?.recordLocal?.('notification_protection_unavailable');
            }
            return {ok: false, reason: 'unsupported'};
        }

        const pattern = originPattern(url);

        if (!pattern) {
            return {ok: false, reason: 'unsupported_scheme'};
        }

        return serialize(async () => {
            const registry = await readRegistry();

            if (registry === null) {
                return {ok: false, reason: 'registry_unavailable'};
            }

            if (registry[pattern]) {
                return {ok: true, already: true};
            }

            const applied = await setNotificationSetting(pattern, 'block');

            if (!applied) {
                return {ok: false};
            }

            registry[pattern] = Date.now();

            if (!await writeRegistry(registry)) {
                // An unrecorded block could never be reverted, so undo it.
                await setNotificationSetting(pattern, null);
                return {ok: false, reason: 'registry_unavailable'};
            }
            return {ok: true};
        });
    };

    /**
     * Reverts the block for a host Osprey previously set (allowlist addition or a later
     * clean verdict). Origins outside the registry are never touched.
     */
    const resetForHost = host => serialize(async () => {
        const target = String(host || '').toLowerCase();

        if (!target) {
            return {ok: true, cleared: 0};
        }

        const registry = await readRegistry();

        if (registry === null) {
            return {ok: false, reason: 'registry_unavailable'};
        }

        const patterns = Object.keys(registry).filter(pattern => {
            try {
                const hostname = new URL(pattern.slice(0, -2)).hostname;
                return hostname === target;
            } catch {
                return false;
            }
        });

        let cleared = 0;

        for (const pattern of patterns) {
            if (await setNotificationSetting(pattern, null)) {
                delete registry[pattern];
                cleared++;
            }
        }

        if (cleared > 0) {
            await writeRegistry(registry);
        }
        return {ok: cleared === patterns.length, cleared};
    });

    return Object.freeze({
        blockForUrl,
        resetForHost,
        originPattern,
    });
})();
