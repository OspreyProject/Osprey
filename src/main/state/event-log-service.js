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

globalThis.OspreyEventLogService = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const policyService = globalThis.OspreyPolicyService;

    const logKey = 'osprey_event_log';
    const schemaVersion = 1;
    const maxEvents = 1000;
    const flushDelay = 250;

    const idb = (() => {
        const dbName = 'osprey_cache';
        const storeName = 'kv';
        const dbVersion = 1;

        let dbPromise = null;

        const openDB = () => {
            if (dbPromise) {
                return dbPromise;
            }

            dbPromise = new Promise((resolve, reject) => {
                const request = globalThis.indexedDB.open(dbName, dbVersion);

                request.onupgradeneeded = () => {
                    const db = request.result;

                    if (!db.objectStoreNames.contains(storeName)) {
                        db.createObjectStore(storeName);
                    }
                };

                request.onsuccess = () => {
                    const db = request.result;

                    db.onclose = () => {
                        dbPromise = null;
                    };

                    db.onversionchange = () => {
                        db.close();
                        dbPromise = null;
                    };

                    resolve(db);
                };

                request.onerror = () => reject(request.error);
                request.onblocked = () => reject(new Error('IndexedDB open blocked'));
            });

            dbPromise.catch(() => {
                dbPromise = null;
            });
            return dbPromise;
        };

        const get = key => openDB().then(db => new Promise((resolve, reject) => {
            const tx = db.transaction(storeName, 'readonly');
            const request = tx.objectStore(storeName).get(key);
            let value;

            request.onsuccess = () => {
                value = request.result;
            };

            tx.oncomplete = () => resolve(value);
            tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
            tx.onerror = () => reject(tx.error || new Error('IndexedDB transaction error'));
        }));

        const set = (key, value) => openDB().then(db => new Promise((resolve, reject) => {
            const tx = db.transaction(storeName, 'readwrite');
            tx.objectStore(storeName).put(value, key);

            tx.oncomplete = () => resolve(true);
            tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
            tx.onerror = () => reject(tx.error || new Error('IndexedDB transaction error'));
        }));

        return {
            get,
            set
        };
    })();

    let events = null;
    let loadingPromise = null;
    let flushTimer = null;
    let cachedVersion = null;

    const getExtensionVersion = () => {
        if (cachedVersion !== null) {
            return cachedVersion;
        }

        try {
            const manifest = browserAPI.api?.runtime?.getManifest?.();
            cachedVersion = manifest && typeof manifest.version === 'string' ? manifest.version : '';
        } catch {
            cachedVersion = '';
        }
        return cachedVersion;
    };

    const normalizeEvent = raw => {
        if (!raw || typeof raw !== 'object') {
            return null;
        }

        const ts = Number(raw.ts);

        return {
            id: typeof raw.id === 'string' ? raw.id : '',
            ts: Number.isFinite(ts) ? ts : 0,
            type: raw.type === 'bypass' ? 'bypass' : 'block',
            action: typeof raw.action === 'string' ? raw.action : null,
            url: typeof raw.url === 'string' ? raw.url : '',
            providerId: typeof raw.providerId === 'string' ? raw.providerId : null,
            verdict: typeof raw.verdict === 'string' ? raw.verdict : null,
            deviceTag: typeof raw.deviceTag === 'string' ? raw.deviceTag : '',
            siteId: typeof raw.siteId === 'string' ? raw.siteId : '',
            version: typeof raw.version === 'string' ? raw.version : '',
        };
    };

    const loadEvents = async () => {
        try {
            const stored = await idb.get(logKey);

            if (stored && typeof stored === 'object' && Array.isArray(stored.events)) {
                const restored = [];

                for (const entry of stored.events) {
                    const normalized = normalizeEvent(entry);

                    if (normalized) {
                        restored.push(normalized);
                    }
                }
                return restored.slice(-maxEvents);
            }
        } catch (error) {
            console.warn('OspreyEventLogService failed to load event log', error);
        }
        return [];
    };

    const ensureLoaded = () => {
        if (events !== null) {
            return Promise.resolve(events);
        }

        if (loadingPromise === null) {
            loadingPromise = loadEvents().then(loaded => {
                if (events === null) {
                    events = loaded;
                }

                loadingPromise = null;
                return events;
            }).catch(error => {
                loadingPromise = null;
                events = events || [];
                console.warn('OspreyEventLogService failed to initialize event log', error);
                return events;
            });
        }
        return loadingPromise;
    };

    const flushNow = async () => {
        if (flushTimer !== null) {
            clearTimeout(flushTimer);
            flushTimer = null;
        }

        const snapshot = events === null ? [] : events.slice();

        try {
            await idb.set(logKey, {version: schemaVersion, events: snapshot});
        } catch (error) {
            console.warn('OspreyEventLogService failed to persist event log', error);
        }
    };

    const scheduleFlush = (delayMs = flushDelay) => {
        if (flushTimer !== null) {
            clearTimeout(flushTimer);
        }

        flushTimer = setTimeout(() => {
            flushTimer = null;

            flushNow().catch(error => {
                console.warn('OspreyEventLogService failed to flush event log', error);
            });
        }, delayMs);
    };

    const newId = () => {
        try {
            const uuid = globalThis.crypto?.randomUUID?.();

            if (uuid) {
                return uuid;
            }
        } catch {
            // ignored
        }
        return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    };

    const append = async partial => {
        const list = await ensureLoaded();
        const identity = await policyService.getEndpointIdentity();

        const event = {
            id: newId(),
            ts: Date.now(),
            type: partial.type === 'bypass' ? 'bypass' : 'block',
            action: typeof partial.action === 'string' ? partial.action : null,
            url: typeof partial.url === 'string' ? partial.url : '',
            providerId: typeof partial.providerId === 'string' ? partial.providerId : null,
            verdict: typeof partial.verdict === 'string' ? partial.verdict : null,
            deviceTag: identity.deviceTag,
            siteId: identity.siteId,
            version: getExtensionVersion(),
        };

        list.push(event);

        if (list.length > maxEvents) {
            list.splice(0, list.length - maxEvents);
        }

        scheduleFlush();
        return event;
    };

    const recordDetection = ({url, providerId, verdict} = {}) =>
        append({type: 'block', action: null, url, providerId, verdict}).catch(error => {
            console.warn('OspreyEventLogService failed to record detection event', error);
        });

    const recordOverride = ({url, providerId, verdict, action} = {}) =>
        append({type: 'bypass', action, url, providerId, verdict}).catch(error => {
            console.warn('OspreyEventLogService failed to record override event', error);
        });

    const getEvents = async () => {
        const list = await ensureLoaded();
        return list.map(entry => ({...entry}));
    };

    const clear = async () => {
        await ensureLoaded();
        events = [];
        await flushNow();
    };

    return Object.freeze({
        recordDetection,
        recordOverride,
        getEvents,
        clear,
    });
})();
