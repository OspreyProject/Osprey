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

    const reportFlushAlarmName = 'osprey-report-flush';
    const reportFlushIntervalMinutes = 5;
    const heartbeatAlarmName = 'osprey-heartbeat';
    const heartbeatIntervalMinutes = 15;
    const reportBatchSize = 200;
    const reportMaxAttempts = 3;
    const reportRetryBaseDelayMs = 1000;
    const reportRequestTimeoutMs = 15000;
    const heartbeatProbeTimeoutMs = 5000;

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
            reported: raw.reported === true,
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
            reported: false,
        };

        list.push(event);

        if (list.length > maxEvents) {
            list.splice(0, list.length - maxEvents);
        }

        scheduleFlush();
        return event;
    };

    const recordDetection = ({url, providerId, verdict} = {}) =>
        append({
            type: 'block',
            action: null,
            url,
            providerId,
            verdict,
        }).catch(error => {
            console.warn('OspreyEventLogService failed to record detection event', error);
        });

    const recordOverride = ({url, providerId, verdict, action} = {}) =>
        append({
            type: 'bypass',
            action,
            url,
            providerId,
            verdict,
        }).catch(error => {
            console.warn('OspreyEventLogService failed to record override event', error);
        });

    const toPublicEvent = event => ({
        id: event.id,
        ts: event.ts,
        type: event.type,
        action: event.action,
        url: event.url,
        providerId: event.providerId,
        verdict: event.verdict,
        deviceTag: event.deviceTag,
        siteId: event.siteId,
        version: event.version,
    });

    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

    const postJson = async (endpoint, authToken, body) => {
        const payload = JSON.stringify(body);

        for (let attempt = 1; attempt <= reportMaxAttempts; attempt++) {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), reportRequestTimeoutMs);

            try {
                const headers = {'Content-Type': 'application/json'};

                if (authToken) {
                    headers.Authorization = `Bearer ${authToken}`;
                }

                const response = await fetch(endpoint, {
                    method: 'POST',
                    credentials: 'omit',
                    cache: 'no-store',
                    redirect: 'follow',
                    signal: controller.signal,
                    headers,
                    body: payload,
                });

                if (response.ok) {
                    return true;
                }

                if (response.status >= 400 && response.status < 500 && response.status !== 429) {
                    console.warn(`OspreyEventLogService reporting endpoint rejected request with HTTP ${response.status}`);
                    return false;
                }
            } catch (error) {
                console.warn(`OspreyEventLogService reporting request attempt ${attempt} failed`, error);
            } finally {
                clearTimeout(timer);
            }

            if (attempt < reportMaxAttempts) {
                await sleep(reportRetryBaseDelayMs * (2 ** (attempt - 1)));
            }
        }
        return false;
    };

    const flushToReporting = async () => {
        const config = await policyService.getReportingConfig();

        if (!config.endpoint) {
            return {
                ok: false,
                reason: 'no-endpoint'
            };
        }

        const list = await ensureLoaded();
        const pending = [];

        for (const entry of list) {
            if (entry.reported !== true) {
                pending.push(entry);
            }
        }

        if (pending.length === 0) {
            return {
                ok: true,
                sent: 0
            };
        }

        const identity = await policyService.getEndpointIdentity();
        const version = getExtensionVersion();
        let sent = 0;

        for (let i = 0; i < pending.length; i += reportBatchSize) {
            const batch = pending.slice(i, i + reportBatchSize);

            const body = {
                kind: 'events',
                schemaVersion,
                sentAt: Date.now(),
                deviceTag: identity.deviceTag,
                siteId: identity.siteId,
                version,
                events: batch.map(toPublicEvent),
            };

            const ok = await postJson(config.endpoint, config.authToken, body);

            if (!ok) {
                if (sent > 0) {
                    await flushNow();
                }

                return {
                    ok: false,
                    reason: 'post-failed',
                    sent
                };
            }

            for (const entry of batch) {
                entry.reported = true;
            }

            sent += batch.length;
        }

        await flushNow();

        return {
            ok: true,
            sent
        };
    };

    const probeProxyReachable = async origin => {
        if (!origin) {
            return false;
        }

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), heartbeatProbeTimeoutMs);

        try {
            await fetch(origin, {
                method: 'GET',
                credentials: 'omit',
                cache: 'no-store',
                redirect: 'follow',
                signal: controller.signal,
            });
            return true;
        } catch {
            return false;
        } finally {
            clearTimeout(timer);
        }
    };

    const sendHeartbeat = async () => {
        const config = await policyService.getReportingConfig();

        if (!config.endpoint) {
            return {
                ok: false,
                reason: 'no-endpoint'
            };
        }

        const identity = await policyService.getEndpointIdentity();

        const proxyOrigin = typeof policyService.getProxyOrigin === 'function'
            ? await policyService.getProxyOrigin()
            : '';

        const proxyReachable = await probeProxyReachable(proxyOrigin);

        const body = {
            kind: 'heartbeat',
            schemaVersion,
            sentAt: Date.now(),
            installed: true,
            enabled: true,
            version: getExtensionVersion(),
            deviceTag: identity.deviceTag,
            siteId: identity.siteId,
            proxyOrigin,
            proxyReachable,
        };

        const ok = await postJson(config.endpoint, config.authToken, body);

        return ok ? {
            ok: true
        } : {
            ok: false,
            reason: 'post-failed'
        };
    };

    const getEvents = async () => {
        const list = await ensureLoaded();
        return list.map(toPublicEvent);
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
        flushToReporting,
        sendHeartbeat,
        reportFlushAlarmName,
        reportFlushIntervalMinutes,
        heartbeatAlarmName,
        heartbeatIntervalMinutes,
    });
})();
