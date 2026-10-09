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
    const maxEventAgeMs = 30 * 24 * 60 * 60 * 1000;
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
    let persistFailures = 0;
    const maxPersistRetries = 5;
    const persistRetryDelayMs = 5000;

    // Events recorded while the stored log could not be read; merged in once it can, so the stored log is
    // never overwritten by a partial in-memory one.
    let pendingEvents = [];
    let flushTimer = null;
    let cachedVersion = null;
    let reportingPromise = null;
    let heartbeatPromise = null;

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
            type: raw.localOnly === true && typeof raw.type === 'string' ? raw.type :
                raw.type === 'bypass' ? 'bypass' : 'block',
            action: typeof raw.action === 'string' ? raw.action : null,
            url: typeof raw.url === 'string' ? raw.url : '',
            providerId: typeof raw.providerId === 'string' ? raw.providerId : null,
            verdict: typeof raw.verdict === 'string' ? raw.verdict : null,
            kind: typeof raw.kind === 'string' ? raw.kind : null,
            target: typeof raw.target === 'string' ? raw.target : null,
            detail: typeof raw.detail === 'string' ? raw.detail : null,
            localOnly: raw.localOnly === true,
            deviceTag: typeof raw.deviceTag === 'string' ? raw.deviceTag : '',
            siteId: typeof raw.siteId === 'string' ? raw.siteId : '',
            version: typeof raw.version === 'string' ? raw.version : '',
            reported: raw.reported === true,
        };
    };

    const pruneExpired = list => {
        const cutoff = Date.now() - maxEventAgeMs;
        let removed = 0;

        for (let i = list.length - 1; i >= 0; i--) {
            if (list[i].ts < cutoff) {
                list.splice(i, 1);
                removed++;
            }
        }
        return removed;
    };

    // Rejects when the stored log cannot be read: an empty list there would later overwrite the real log.
    const loadEvents = async () => {
        const stored = await idb.get(logKey);

        if (stored && typeof stored === 'object' && Array.isArray(stored.events)) {
            const restored = [];

            for (const entry of stored.events) {
                const normalized = normalizeEvent(entry);

                if (normalized) {
                    restored.push(normalized);
                }
            }

            const cutoff = Date.now() - maxEventAgeMs;
            const fresh = [];

            for (const entry of restored) {
                if (entry.ts >= cutoff) {
                    fresh.push(entry);
                }
            }
            return fresh.slice(-maxEvents);
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

                    if (pendingEvents.length > 0) {
                        events.push(...pendingEvents);
                        events.splice(0, Math.max(0, events.length - maxEvents));
                        pendingEvents = [];
                        scheduleFlush();
                    }
                }

                loadingPromise = null;
                return events;
            }).catch(error => {
                loadingPromise = null;
                console.warn('OspreyEventLogService failed to load event log; will retry', error);
                throw error;
            });
        }
        return loadingPromise;
    };

    const flushNow = async () => {
        if (flushTimer !== null) {
            clearTimeout(flushTimer);
            flushTimer = null;
        }

        if (events === null) {
            return;
        }

        const snapshot = events.slice();

        try {
            await idb.set(logKey, {version: schemaVersion, events: snapshot});
            persistFailures = 0;
        } catch (error) {
            console.warn('OspreyEventLogService failed to persist event log', error);

            // Unpersisted changes (new events, reported flags) are retried soon, a few times, before waiting for the
            // next change.
            if (++persistFailures <= maxPersistRetries) {
                scheduleFlush(persistRetryDelayMs * persistFailures);
            }
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

        try {
            const bytes = new Uint8Array(16);
            globalThis.crypto.getRandomValues(bytes);
            let hex = '';

            for (const byte of bytes) {
                hex += byte.toString(16).padStart(2, '0');
            }
            return `${Date.now()}-${hex}`;
        } catch {
            return `${Date.now()}-${Math.random().toString(36).slice(2)}`;
        }
    };

    /**
     * Strips the query string (apart from the few resource-identifying parameters the lookup
     * normalizer retains) and fragment before a URL is logged or reported. Queries routinely carry
     * session tokens, reset codes, and email addresses that must not leave the device.
     */
    const reportableUrl = url => {
        if (typeof url !== 'string' || url.length === 0) {
            return '';
        }

        const normalized = globalThis.OspreyUrlService?.normalizeLookupUrl?.(url);

        if (typeof normalized === 'string' && normalized) {
            return normalized;
        }

        try {
            const parsed = new URL(url);
            parsed.search = '';
            parsed.hash = '';
            parsed.username = '';
            parsed.password = '';
            return parsed.href;
        } catch {
            return '';
        }
    };

    const append = async partial => {
        const identity = await policyService.getEndpointIdentity();

        const event = {
            id: newId(),
            ts: Date.now(),
            type: partial.localOnly === true ? partial.type : partial.type === 'bypass' ? 'bypass' : 'block',
            action: typeof partial.action === 'string' ? partial.action : null,
            url: reportableUrl(partial.url),
            providerId: typeof partial.providerId === 'string' ? partial.providerId : null,
            verdict: typeof partial.verdict === 'string' ? partial.verdict : null,
            kind: typeof partial.kind === 'string' ? partial.kind : null,
            target: typeof partial.target === 'string' ? partial.target : null,
            detail: typeof partial.detail === 'string' ? partial.detail : null,
            localOnly: partial.localOnly === true,
            deviceTag: identity.deviceTag,
            siteId: identity.siteId,
            version: getExtensionVersion(),
            reported: false,
        };

        let list;

        try {
            list = await ensureLoaded();
        } catch {
            pendingEvents.push(event);
            pendingEvents.splice(0, Math.max(0, pendingEvents.length - maxEvents));
            return event;
        }

        pruneExpired(list);
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

    const recordLocal = (type, {url, kind, target, detail} = {}) =>
        append({type, url, kind, target, detail, localOnly: true}).catch(error => {
            console.warn('OspreyEventLogService failed to record local event', error);
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
        ...(event.localOnly ? {
            kind: event.kind,
            target: event.target,
            detail: event.detail,
        } : {}),
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

    const reportPending = async () => {
        const config = await policyService.getReportingConfig();

        if (!config.endpoint) {
            return {
                ok: false,
                reason: 'no-endpoint'
            };
        }

        const list = await ensureLoaded();

        if (pruneExpired(list) > 0) {
            scheduleFlush();
        }

        const pending = [];

        for (const entry of list) {
            if (entry.reported !== true && entry.localOnly !== true) {
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

            // Persist each batch's flags right away, so a killed worker can only resend the batch in flight.
            await flushNow();
        }

        await flushNow();

        return {
            ok: true,
            sent
        };
    };

    const flushToReporting = () => {
        if (!reportingPromise) {
            reportingPromise = reportPending().finally(() => {
                reportingPromise = null;
            });
        }
        return reportingPromise;
    };

    const probeProxyReachable = async origin => {
        if (!origin) {
            return false;
        }

        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), heartbeatProbeTimeoutMs);

        try {
            // no-cors: the extension holds no host permission for self-hosted proxies, and the probe
            // only needs to know the origin answered, not to read the response.
            await fetch(origin, {
                method: 'GET',
                mode: 'no-cors',
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

    const postHeartbeat = async () => {
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
        const runtime = await globalThis.OspreyProviderRuntimeFactory.createRuntime({fresh: true});
        const enabled = runtime.effectiveState.app.disableAllProviders !== true &&
            runtime.providers.some(provider => provider.state.enabled);

        const body = {
            kind: 'heartbeat',
            schemaVersion,
            sentAt: Date.now(),
            installed: true,
            enabled,
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

    const sendHeartbeat = () => {
        if (!heartbeatPromise) {
            heartbeatPromise = postHeartbeat().finally(() => {
                heartbeatPromise = null;
            });
        }
        return heartbeatPromise;
    };

    const getEvents = async () => {
        let list;

        try {
            list = await ensureLoaded();
        } catch {
            // The stored log is unreadable right now; show what has been recorded since.
            return pendingEvents.map(toPublicEvent);
        }
        if (pruneExpired(list) > 0) {
            scheduleFlush();
        }
        return list.map(toPublicEvent);
    };

    return Object.freeze({
        recordDetection,
        recordOverride,
        recordLocal,
        getEvents,
        flushToReporting,
        sendHeartbeat,
        reportFlushAlarmName,
        reportFlushIntervalMinutes,
        heartbeatAlarmName,
        heartbeatIntervalMinutes,
    });
})();
