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

globalThis.OspreyPolicyService = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const catalogValidator = globalThis.OspreyCatalogValidator;

    const remoteConfigStorageKey = 'osprey_remote_config';
    const remoteConfigAlarmName = 'osprey-remote-config-refresh';
    const remoteConfigRefreshMinutes = 60;
    const remoteConfigFetchTimeoutMS = 15000;
    const remoteConfigMaxBytes = 512 * 1024;
    const defaultProxyOrigin = 'https://api.osprey.ac';
    const controlOnlyPolicyKeys = new Set(['ManagedConfigUrl', 'ManagedConfigPublicKey']);

    // A credential set by the admin must only ever be sent to a destination the admin also set.
    const credentialBindings = Object.freeze([
        {secret: 'ReportingAuthToken', destination: 'ReportingEndpoint'},
        {secret: 'ProxyApiKey', destination: 'ProxyBaseUrl'},
    ]);
    const remoteOnlyPolicyKeys = new Set(['CommercialDisabledProviders']);
    const unsafeKeys = new Set(['__proto__', 'constructor', 'prototype']);

    let cachedManagedPolicies = null;
    let cachedManagedPoliciesPromise = null;
    let cachedRemoteConfig = null;
    let cachedRemoteConfigPromise = null;
    let cachedEffectivePolicies = null;
    let cachedManagedListConfig = null;
    let lastSeededCustomKey = null;
    let managedRevision = 0;
    let lastGoodManagedPolicies = null;
    const effectiveCategoriesStorageKey = 'osprey_effective_categories';
    let effectiveCategoriesBaseline = null;

    const identityMap = value => value;
    const trimStringMap = value => String(value == null ? '' : value).trim();

    const normalizeStringList = value => {
        if (!Array.isArray(value)) {
            return [];
        }

        const out = [];

        for (const element of value) {
            if (typeof element === 'string') {
                const trimmed = element.trim();

                if (trimmed) {
                    out.push(trimmed);
                }
            }
        }
        return out;
    };

    const enumMap = allowed => value => allowed.includes(value) ? value : undefined;

    const appPolicyMappings = [
        {
            policyKey: 'ManagedNotificationProtection',
            type: 'string',
            stateKey: 'notificationProtection',
            mapValue: enumMap(['', 'on']),
        },
        {
            policyKey: 'ManagedDomainIntelMode',
            type: 'string',
            stateKey: 'domainIntelMode',
            mapValue: enumMap(['', 'warn', 'block']),
        },
        {
            policyKey: 'HideWarningProceedButton',
            type: 'boolean',
            stateKey: 'hideWarningProceedButton',
            mapValue: identityMap,
        },
        {
            policyKey: 'HideWarningReportButton',
            type: 'boolean',
            stateKey: 'hideWarningReportButton',
            mapValue: identityMap,
        },
        {
            policyKey: 'CacheExpirationSeconds',
            type: 'number',
            stateKey: 'cacheExpirationSeconds',
            mapValue: value => Number.isInteger(value) && value >= 60 && value <= 2592000 ? value : undefined,
        },
        {
            policyKey: 'LockUserAllowlist',
            type: 'boolean',
            stateKey: 'lockUserAllowlist',
            mapValue: identityMap,
        },
        {
            policyKey: 'LockProviderSettings',
            type: 'boolean',
            stateKey: 'lockProviderSettings',
            mapValue: identityMap,
        },
        {
            policyKey: 'HideProviderControls',
            type: 'boolean',
            stateKey: 'hideProviderControls',
            mapValue: identityMap,
        },
        {
            policyKey: 'DisableSettingsReset',
            type: 'boolean',
            stateKey: 'disableSettingsReset',
            mapValue: identityMap,
        },
        {
            policyKey: 'ProxyBaseUrl',
            type: 'string',
            stateKey: 'proxyBaseUrl',
            mapValue: trimStringMap,
        },
        {
            policyKey: 'DeviceTag',
            type: 'string',
            stateKey: 'deviceTag',
            mapValue: trimStringMap,
        },
        {
            policyKey: 'SiteId',
            type: 'string',
            stateKey: 'siteId',
            mapValue: trimStringMap,
        },
        {
            policyKey: 'DisableUserAllowlist',
            type: 'boolean',
            stateKey: 'disableUserAllowlist',
            mapValue: identityMap,
        },
        {
            policyKey: 'BrandLogoUrl',
            type: 'string',
            stateKey: 'brandLogoUrl',
            mapValue: trimStringMap,
        },
        {
            policyKey: 'BrandName',
            type: 'string',
            stateKey: 'brandName',
            mapValue: trimStringMap,
        },
        {
            policyKey: 'SupportUrl',
            type: 'string',
            stateKey: 'supportUrl',
            mapValue: trimStringMap,
        },
        {
            policyKey: 'SupportEmail',
            type: 'string',
            stateKey: 'supportEmail',
            mapValue: trimStringMap,
        },
        {
            policyKey: 'CustomWarningMessage',
            type: 'string',
            stateKey: 'customWarningMessage',
            mapValue: trimStringMap,
        },
    ];

    const ensureProviderState = (providers, definition) => {
        let state = Object.hasOwn(providers, definition.id) ? providers[definition.id] : undefined;

        if (state === undefined) {
            state = {enabled: definition.enabledByDefault, apiKey: ''};
            providers[definition.id] = state;
        }
        return state;
    };

    const fastCloneApp = app => ({...app});

    const fastCloneProviders = providers => {
        const cloned = {};
        const keys = Object.keys(providers);

        for (const element of keys) {
            const k = element;
            cloned[k] = {...providers[k]};
        }
        return cloned;
    };

    const applyAppPolicies = (app, policies, appManagedKeys) => {
        for (const element of appPolicyMappings) {
            const mapping = element;
            const policyVal = policies[mapping.policyKey];

            if (typeof policyVal === mapping.type) {
                const mapped = mapping.mapValue(policyVal);

                if (mapped === undefined) {
                    console.warn(`OspreyPolicyService ignoring invalid ${mapping.policyKey}`);
                    continue;
                }

                app[mapping.stateKey] = mapped;

                if (appManagedKeys !== undefined) {
                    appManagedKeys.add(mapping.stateKey);
                }
            }
        }

        if (Array.isArray(policies.ManagedProtectedDomains)) {
            app.protectedDomains = normalizeStringList(policies.ManagedProtectedDomains);

            if (appManagedKeys !== undefined) {
                appManagedKeys.add('protectedDomains');
            }
        }

        const managedAllowlist = normalizeStringList(policies.ManagedAllowlist);

        if (managedAllowlist.length > 0) {
            app.managedAllowlist = managedAllowlist;

            if (appManagedKeys !== undefined) {
                appManagedKeys.add('managedAllowlist');
            }
        }

        const managedBlocklist = normalizeStringList(policies.ManagedBlocklist);

        if (managedBlocklist.length > 0) {
            app.managedBlocklist = managedBlocklist;

            if (appManagedKeys !== undefined) {
                appManagedKeys.add('managedBlocklist');
            }
        }
    };

    const applyManagedProviderSettings = (providers, policies, providerManagedIds) => {
        const settings = policies.ManagedProviderSettings;

        if (!settings || typeof settings !== 'object') {
            return;
        }

        for (const rawId of Object.keys(settings)) {
            const override = settings[rawId];

            if (!override || typeof override !== 'object') {
                continue;
            }

            const definition = providerCatalog.getDefinition(rawId);

            if (!definition) {
                continue;
            }

            const providerState = ensureProviderState(providers, definition);
            let managed = false;

            if (typeof override.enabled === 'boolean') {
                providerState.enabled = override.enabled;
                managed = true;
            }

            if (typeof override.bypassBlockingThreshold === 'boolean') {
                providerState.bypassBlockingThreshold = override.bypassBlockingThreshold;
                managed = true;
            }

            const timeout = Number(override.requestTimeoutMs);

            if (Number.isFinite(timeout) && timeout >= 1000 && timeout <= 60000) {
                providerState.requestTimeoutMs = timeout;
                managed = true;
            }

            if (override.blockCategories && typeof override.blockCategories === 'object') {
                const nextCategories = {};
                const existing = providerState.blockCategories;

                if (existing && typeof existing === 'object') {
                    for (const key of Object.keys(existing)) {
                        nextCategories[key] = existing[key];
                    }
                }

                for (const key of Object.keys(override.blockCategories)) {
                    if (typeof override.blockCategories[key] === 'boolean') {
                        nextCategories[key] = override.blockCategories[key];
                    }
                }

                providerState.blockCategories = nextCategories;
                managed = true;
            }

            if (managed) {
                providerManagedIds.add(definition.id);
            }
        }
    };

    const getManagedPolicies = async ({fresh = false} = {}) => {
        if (!fresh && cachedManagedPolicies !== null) {
            return cachedManagedPolicies;
        }

        if (!fresh && cachedManagedPoliciesPromise !== null) {
            return cachedManagedPoliciesPromise;
        }

        const managedStorage = browserAPI.api?.storage?.managed;

        if (managedStorage?.get === undefined) {
            cachedManagedPolicies = Object.freeze({});
            return cachedManagedPolicies;
        }

        const revision = managedRevision;
        cachedManagedPoliciesPromise = (async () => {
            try {
                const result = await browserAPI.storageGet('managed', null);

                if (revision !== managedRevision) {
                    return getManagedPolicies({fresh: true});
                }

                cachedManagedPolicies = Object.freeze(result || {});
                lastGoodManagedPolicies = cachedManagedPolicies;
            } catch (error) {
                if (error && typeof error.message === 'string' && error.message.includes('Managed storage manifest not found')) {
                    cachedManagedPolicies = Object.freeze({});
                } else {
                    // A transient read error must not stop URL checking. Use the last policies read
                    // in this worker if there are any, without caching the fallback, so the next
                    // call retries the read.
                    console.warn('OspreyPolicyService failed to read managed policies; retrying on next use', error);
                    return lastGoodManagedPolicies || Object.freeze({});
                }
            } finally {
                cachedManagedPoliciesPromise = null;
            }
            return cachedManagedPolicies;
        })();
        return cachedManagedPoliciesPromise;
    };

    const isPlainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

    const getStaticDefinitions = () => providerCatalog.getBuiltins();

    const sanitizeCustomProviders = list => {
        if (!Array.isArray(list)) {
            return [];
        }

        const out = [];

        for (const entry of list) {
            if (!isPlainObject(entry)) {
                continue;
            }

            const clean = {};

            for (const key of Object.keys(entry)) {
                if (unsafeKeys.has(key)) {
                    continue;
                }

                clean[key] = entry[key];
            }

            out.push(clean);
        }
        return out;
    };

    const sanitizeRemoteDocument = document => {
        const policies = {};
        let customProviders = [];

        if (isPlainObject(document)) {
            const rawPolicies = isPlainObject(document.policies) ? document.policies : document;

            for (const key of Object.keys(rawPolicies)) {
                if (unsafeKeys.has(key) || controlOnlyPolicyKeys.has(key)) {
                    continue;
                }

                if (key === 'policies' || key === 'customProviders' || key === 'version' ||
                    key === 'audience' || key === 'sequence' || key === 'issuedAt') {
                    continue;
                }

                policies[key] = rawPolicies[key];
            }

            if (Array.isArray(document.customProviders)) {
                customProviders = sanitizeCustomProviders(document.customProviders);
            }
        }
        return {policies, customProviders};
    };

    const emptyRemoteConfig = () => ({policies: {}, customProviders: []});

    const verifyRemoteDocument = async (envelope, managed) => {
        if (!isPlainObject(envelope) || typeof envelope.payload !== 'string' ||
            typeof envelope.signature !== 'string' || typeof managed.ManagedConfigPublicKey !== 'string') {
            throw new Error('remote config is missing its signature or managed public key');
        }

        const keyData = JSON.parse(managed.ManagedConfigPublicKey);

        if (keyData.kty !== 'EC' || keyData.crv !== 'P-256' || typeof keyData.x !== 'string' ||
            typeof keyData.y !== 'string' || keyData.d !== undefined) {
            throw new Error('remote config public key must be a P-256 public JWK');
        }

        const key = await crypto.subtle.importKey('jwk', keyData, {
            name: 'ECDSA',
            namedCurve: 'P-256'
        }, false, ['verify']);
        const signature = Uint8Array.from(atob(envelope.signature), char => char.charCodeAt(0));
        const bytes = new TextEncoder().encode(envelope.payload);

        if (!await crypto.subtle.verify({name: 'ECDSA', hash: 'SHA-256'}, key, signature, bytes)) {
            throw new Error('remote config signature verification failed');
        }

        const document = JSON.parse(envelope.payload);

        if (!isPlainObject(document)) {
            throw new Error('remote config payload must be an object');
        }
        // The signed payload names the exact config URL it was issued for and carries a
        // monotonically increasing sequence, so a document cannot be replayed at another client's
        // URL and an older document cannot be served to roll policy back.
        const configUrl = resolveConfigUrl(managed);
        let audience = '';

        try {
            audience = new URL(String(document.audience)).href;
        } catch {
            audience = '';
        }

        if (!configUrl || audience !== configUrl) {
            throw new Error('remote config audience does not match ManagedConfigUrl');
        }

        if (!Number.isSafeInteger(document.sequence) || document.sequence < 0) {
            throw new Error('remote config payload must carry a non-negative integer sequence');
        }
        return document;
    };

    const readStoredRemoteConfig = async managed => {
        const stored = await browserAPI.storageGet('local', remoteConfigStorageKey);
        const envelope = stored?.[remoteConfigStorageKey];

        if (!envelope) {
            return emptyRemoteConfig();
        }

        try {
            return sanitizeRemoteDocument(await verifyRemoteDocument(envelope, managed));
        } catch (error) {
            console.warn('OspreyPolicyService rejected unverified stored remote config', error);
            return emptyRemoteConfig();
        }
    };

    const getRemoteConfig = async ({fresh = false} = {}) => {
        if (!fresh && cachedRemoteConfig !== null) {
            return cachedRemoteConfig;
        }

        if (!fresh && cachedRemoteConfigPromise !== null) {
            return cachedRemoteConfigPromise;
        }

        const revision = managedRevision;
        const promise = (async () => {
            try {
                const managed = await getManagedPolicies({fresh});
                const stored = resolveConfigUrl(managed) && managed.ManagedConfigPublicKey ?
                    await readStoredRemoteConfig(managed) : emptyRemoteConfig();

                if (revision !== managedRevision) {
                    return getRemoteConfig({fresh: true});
                }

                cachedRemoteConfig = Object.freeze({
                    policies: Object.freeze({...stored.policies}),
                    customProviders: Object.freeze(stored.customProviders.slice()),
                });
                return cachedRemoteConfig;
            } finally {
                if (cachedRemoteConfigPromise === promise) {
                    cachedRemoteConfigPromise = null;
                }
            }
        })();
        cachedRemoteConfigPromise = promise;
        return promise;
    };

    const seedCustomProviders = async () => {
        if (!providerCatalog || typeof providerCatalog.setCustomDefinitions !== 'function') {
            return;
        }

        const remote = await getRemoteConfig();
        const raw = Array.isArray(remote.customProviders) ? remote.customProviders : [];
        const seedKey = JSON.stringify(raw);

        if (seedKey === lastSeededCustomKey) {
            return;
        }

        let toRegister = [];

        if (raw.length > 0 && catalogValidator && typeof catalogValidator.validateCustom === 'function') {
            const {valid, errors} = catalogValidator.validateCustom(raw, getStaticDefinitions());

            if (errors.length > 0) {
                console.warn('OspreyPolicyService rejected invalid custom providers from remote config', errors);
            }

            toRegister = valid;
        }

        providerCatalog.setCustomDefinitions(toRegister);
        lastSeededCustomKey = seedKey;
    };

    const assignInto = (target, source) => {
        if (!isPlainObject(source)) {
            return;
        }

        for (const key of Object.keys(source)) {
            if (unsafeKeys.has(key)) {
                continue;
            }

            target[key] = source[key];
        }
    };

    const buildEffectivePolicies = (managed, remotePolicies) => {
        const merged = {};

        assignInto(merged, remotePolicies);
        assignInto(merged, managed);

        for (const key of controlOnlyPolicyKeys) {
            if (isPlainObject(managed) && Object.hasOwn(managed, key)) {
                merged[key] = managed[key];
            } else {
                delete merged[key];
            }
        }

        for (const {secret, destination} of credentialBindings) {
            if (isPlainObject(managed) && Object.hasOwn(managed, secret) && !Object.hasOwn(managed, destination)) {
                delete merged[destination];
            }
        }

        for (const key of remoteOnlyPolicyKeys) {
            if (isPlainObject(remotePolicies) && Object.hasOwn(remotePolicies, key)) {
                merged[key] = remotePolicies[key];
            } else {
                delete merged[key];
            }
        }
        return Object.freeze(merged);
    };

    const getPolicies = async ({fresh = false} = {}) => {
        if (!fresh && cachedEffectivePolicies !== null) {
            return cachedEffectivePolicies;
        }

        const revision = managedRevision;
        const [managed, remote] = await Promise.all([
            getManagedPolicies({fresh}),
            getRemoteConfig({fresh}),
        ]);

        if (revision !== managedRevision) {
            return getPolicies({fresh: true});
        }

        cachedEffectivePolicies = buildEffectivePolicies(managed, remote.policies);
        return cachedEffectivePolicies;
    };

    const isAllowedTransport = parsed => parsed.protocol === 'https:';

    const resolveConfigUrl = managed => {
        const raw = managed && typeof managed.ManagedConfigUrl === 'string' ? managed.ManagedConfigUrl.trim() : '';

        if (!raw) {
            return '';
        }

        let parsed;

        try {
            parsed = new URL(raw);
        } catch {
            console.warn('OspreyPolicyService ignoring malformed ManagedConfigUrl');
            return '';
        }

        if (!isAllowedTransport(parsed)) {
            console.warn('OspreyPolicyService ignoring ManagedConfigUrl without an approved transport');
            return '';
        }
        return parsed.href;
    };

    const readBodyCapped = async (response, maxBytes) => {
        const body = response.body;

        if (!body || typeof body.getReader !== 'function') {
            const text = await response.text();

            if (text.length > maxBytes) {
                throw new Error(`config document exceeds ${maxBytes} bytes`);
            }
            return text;
        }

        const reader = body.getReader();
        const decoder = new TextDecoder();
        let received = 0;
        let text = '';

        for (; ;) {
            const {done, value} = await reader.read();

            if (done) {
                break;
            }

            received += value.byteLength;

            if (received > maxBytes) {
                await reader.cancel().catch(() => undefined);
                throw new Error(`config document exceeds ${maxBytes} bytes`);
            }

            text += decoder.decode(value, {stream: true});
        }
        return text + decoder.decode();
    };

    const fetchConfigDocument = async url => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), remoteConfigFetchTimeoutMS);

        try {
            const response = await fetch(url, {
                method: 'GET',
                credentials: 'omit',
                cache: 'no-store',
                redirect: 'follow',
                signal: controller.signal,
                headers: {
                    Accept: 'application/json'
                },
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            let finalUrl = null;

            try {
                finalUrl = new URL(response.url);
            } catch {
                finalUrl = null;
            }

            if (finalUrl === null || !isAllowedTransport(finalUrl)) {
                throw new Error('config fetch was redirected off an approved transport');
            }

            const declaredLength = Number(response.headers.get('content-length'));

            if (Number.isFinite(declaredLength) && declaredLength > remoteConfigMaxBytes) {
                throw new Error(`config document exceeds ${remoteConfigMaxBytes} bytes`);
            }

            const text = await readBodyCapped(response, remoteConfigMaxBytes);
            return JSON.parse(text);
        } finally {
            clearTimeout(timer);
        }
    };

    const persistRemoteConfig = async payload => {
        try {
            await browserAPI.storageSet('local', {[remoteConfigStorageKey]: payload});
            return true;
        } catch (error) {
            console.warn('OspreyPolicyService failed to persist remote config', error);
            return false;
        }
    };

    const refreshRemoteConfig = async () => {
        const revision = managedRevision;
        const managed = await getManagedPolicies({fresh: true});
        const url = resolveConfigUrl(managed);

        if (!url || !managed.ManagedConfigPublicKey) {
            await browserAPI.storageRemove('local', remoteConfigStorageKey);
            invalidateRemote();
            await seedCustomProviders();
            return {ok: false, reason: 'no-url'};
        }

        let document;
        let envelope;

        try {
            envelope = await fetchConfigDocument(url);
            document = await verifyRemoteDocument(envelope, managed);
        } catch (error) {
            console.warn('OspreyPolicyService remote config fetch or verification failed; keeping last-known-good', error);
            return {ok: false, reason: 'fetch-failed'};
        }

        const currentManaged = await getManagedPolicies({fresh: true});

        if (revision !== managedRevision || resolveConfigUrl(currentManaged) !== url ||
            currentManaged.ManagedConfigPublicKey !== managed.ManagedConfigPublicKey) {
            return {ok: false, reason: 'policy-changed'};
        }

        let storedSequence = -1;

        try {
            const stored = await browserAPI.storageGet('local', remoteConfigStorageKey);

            if (stored?.[remoteConfigStorageKey]) {
                storedSequence = (await verifyRemoteDocument(stored[remoteConfigStorageKey], managed)).sequence;
            }
        } catch {
            storedSequence = -1;
        }

        if (document.sequence < storedSequence) {
            console.warn(`OspreyPolicyService rejected remote config sequence ${document.sequence}; `
                + `last accepted is ${storedSequence}`);
            return {ok: false, reason: 'rollback'};
        }

        const sanitized = sanitizeRemoteDocument(document);

        let customProviders = [];

        if (sanitized.customProviders.length > 0 && catalogValidator && typeof catalogValidator.validateCustom === 'function') {
            const {valid, errors} = catalogValidator.validateCustom(sanitized.customProviders, getStaticDefinitions());

            if (errors.length > 0) {
                console.warn('OspreyPolicyService dropped invalid custom providers from remote config', errors);
            }

            customProviders = valid;
        }

        if (!await persistRemoteConfig(envelope)) {
            return {ok: false, reason: 'persist-failed'};
        }

        if (revision !== managedRevision) {
            return refreshRemoteConfig();
        }

        cachedRemoteConfig = Object.freeze({
            policies: Object.freeze({...sanitized.policies}),
            customProviders: Object.freeze(customProviders.slice()),
        });

        cachedEffectivePolicies = null;
        cachedManagedListConfig = null;
        lastSeededCustomKey = null;

        await seedCustomProviders();

        return {
            ok: true,
            customProviderCount: customProviders.length,
        };
    };

    const initRemoteConfig = async () => {
        await getRemoteConfig({fresh: true});
        await seedCustomProviders();
    };

    const loadEffectiveCategoriesBaseline = async () => {
        if (effectiveCategoriesBaseline === null) {
            try {
                const stored = await browserAPI.storageGet('local', effectiveCategoriesStorageKey);
                const value = stored?.[effectiveCategoriesStorageKey];
                effectiveCategoriesBaseline = isPlainObject(value) ? value : {};
            } catch (error) {
                console.warn('OspreyPolicyService failed to read the effective category baseline', error);
                return null;
            }
        }
        return effectiveCategoriesBaseline;
    };

    /**
     * Clears a provider's verdict cache when its effective block categories change, so verdicts
     * cached under the old categories stop applying. Runs only where the cache service exists (the
     * background); extension pages build runtimes too but own no cache. The baseline is persisted,
     * so a service-worker restart does not look like a change.
     */
    const syncEffectiveCategories = async providers => {
        const cacheService = globalThis.OspreyCacheService;

        if (typeof cacheService?.clearProviderCache !== 'function') {
            return;
        }

        const baseline = await loadEffectiveCategoriesBaseline();

        if (baseline === null) {
            return;
        }

        const firstRun = Object.keys(baseline).length === 0;
        const next = {};
        let changed = false;

        for (const [id, provider] of Object.entries(providers)) {
            const current = {...(provider.blockCategories || {})};
            const previous = isPlainObject(baseline[id]) ? baseline[id] : null;
            next[id] = current;

            if (previous === null) {
                changed = true;
                continue;
            }

            const keys = new Set([...Object.keys(previous), ...Object.keys(current)]);

            if ([...keys].some(key => previous[key] !== current[key])) {
                changed = true;

                if (!firstRun) {
                    await cacheService.clearProviderCache(id);
                }
            }
        }

        if (changed || Object.keys(baseline).length !== Object.keys(next).length) {
            effectiveCategoriesBaseline = next;

            try {
                await browserAPI.storageSet('local', {[effectiveCategoriesStorageKey]: next});
            } catch (error) {
                console.warn('OspreyPolicyService failed to persist the effective category baseline', error);
            }
        }
    };

    const applyToState = async state => {
        const policies = await getPolicies();
        const locked = policies.LockProviderSettings === true;
        const source = locked ? globalThis.OspreyProviderStateStore.getDefaultState() : state;
        const effectiveApp = fastCloneApp(source.app);
        const effectiveProviders = fastCloneProviders(source.providers);

        // API keys are credentials, not settings: a lock replaces user-writable settings with
        // defaults but keeps locally entered keys so keyed providers keep working.
        if (locked) {
            for (const id of Object.keys(effectiveProviders)) {
                const apiKey = state.providers?.[id]?.apiKey;

                if (typeof apiKey === 'string' && apiKey) {
                    effectiveProviders[id].apiKey = apiKey;
                }
            }
        }

        const effective = {
            ...state,
            app: effectiveApp,
            providers: effectiveProviders,
        };

        const appManagedKeys = new Set();
        const providerManagedIds = new Set();

        applyAppPolicies(effective.app, policies, appManagedKeys);

        applyManagedProviderSettings(effective.providers, policies, providerManagedIds);

        await syncEffectiveCategories(effective.providers);

        if (effective.app.disableAllProviders) {
            const providerIds = Object.keys(effective.providers);

            for (const providerId of providerIds) {
                effective.providers[providerId].enabled = false;
            }
        }

        const commercialDisabledIds = new Set();
        const commercialDisabledList = normalizeStringList(policies.CommercialDisabledProviders);

        for (const providerId of commercialDisabledList) {
            const definition = providerCatalog.getDefinition(providerId);

            if (!definition) {
                continue;
            }

            ensureProviderState(effective.providers, definition).enabled = false;
            providerManagedIds.add(definition.id);
            commercialDisabledIds.add(definition.id);
        }

        return Object.freeze({
            policies,
            effectiveState: effective,
            appManagedKeys,
            providerManagedIds,
            commercialDisabledIds,
        });
    };

    const applyToAppState = async state => {
        const policies = await getPolicies();
        const source = policies.LockProviderSettings === true ?
            globalThis.OspreyProviderStateStore.getDefaultState() : state;
        const effectiveApp = fastCloneApp(source.app);
        const appManagedKeys = new Set();

        applyAppPolicies(effectiveApp, policies, appManagedKeys);

        return Object.freeze({
            policies,
            effectiveApp,
            appManagedKeys,
        });
    };

    const invalidate = () => {
        cachedManagedPolicies = null;
        cachedManagedPoliciesPromise = null;
        cachedEffectivePolicies = null;
        cachedManagedListConfig = null;
    };

    const invalidateRemote = () => {
        cachedRemoteConfig = null;
        cachedRemoteConfigPromise = null;
        cachedEffectivePolicies = null;
        cachedManagedListConfig = null;
    };

    const getManagedListConfig = async () => {
        const policies = await getPolicies();

        if (cachedManagedListConfig !== null && cachedManagedListConfig.source === policies) {
            return cachedManagedListConfig;
        }

        const config = Object.freeze({
            source: policies,
            allowlist: normalizeStringList(policies.ManagedAllowlist),
            blocklist: normalizeStringList(policies.ManagedBlocklist),
            disableUserAllowlist: policies.DisableUserAllowlist === true,
        });

        cachedManagedListConfig = config;
        return config;
    };

    const getEndpointIdentity = async () => {
        const policies = await getPolicies();

        return {
            deviceTag: trimStringMap(policies.DeviceTag),
            siteId: trimStringMap(policies.SiteId),
        };
    };

    const resolveHttpUrl = raw => {
        const trimmed = String(raw == null ? '' : raw).trim();

        if (!trimmed) {
            return '';
        }

        let parsed;

        try {
            parsed = new URL(trimmed);
        } catch {
            return '';
        }

        if (!isAllowedTransport(parsed)) {
            return '';
        }
        return parsed.href;
    };

    const getReportingConfig = async () => {
        const policies = await getPolicies();

        return {
            endpoint: resolveHttpUrl(policies.ReportingEndpoint),
            authToken: trimStringMap(policies.ReportingAuthToken),
        };
    };

    const getProxyOrigin = async () => {
        const policies = await getPolicies();
        const raw = trimStringMap(policies.ProxyBaseUrl);

        if (!raw) {
            return defaultProxyOrigin;
        }

        let parsed;

        try {
            parsed = new URL(raw);
        } catch {
            return defaultProxyOrigin;
        }

        if (!isAllowedTransport(parsed)) {
            return defaultProxyOrigin;
        }
        return parsed.origin;
    };

    const storageApi = browserAPI.api?.storage;

    if (storageApi?.onChanged?.addListener !== undefined) {
        storageApi.onChanged.addListener((changes, area) => {
            if (area === 'managed') {
                managedRevision++;
                invalidate();
                invalidateRemote();
                refreshRemoteConfig().catch(error => {
                    console.error('OspreyPolicyService failed to refresh remote config after policy change', error);
                });
            } else if (area === 'local' && changes?.[remoteConfigStorageKey]) {
                invalidateRemote();
                seedCustomProviders().catch(error => {
                    console.warn('OspreyPolicyService failed to seed custom providers after remote config change', error);
                });
            }
        });
    }

    const getEffectiveAppLocks = async () => {
        const policies = await getPolicies();

        return {
            lockProviderSettings: policies.LockProviderSettings === true,
            disableSettingsReset: policies.DisableSettingsReset === true,
        };
    };

    const getActionRestrictions = async () => {
        const policies = await getPolicies();

        return {
            lockUserAllowlist: policies.LockUserAllowlist === true,
            disableUserAllowlist: policies.DisableUserAllowlist === true,
            hideWarningProceedButton: policies.HideWarningProceedButton === true,
        };
    };

    const isUninstallSurveyDisabled = async () => {
        const policies = await getPolicies();
        return policies.DisableUninstallSurvey === true;
    };

    const isWelcomePageDisabled = async () => {
        const policies = await getPolicies();
        return policies.DisableWelcomePage === true;
    };

    return Object.freeze({
        applyToState,
        applyToAppState,
        getEffectiveAppLocks,
        getActionRestrictions,
        isUninstallSurveyDisabled,
        isWelcomePageDisabled,
        getManagedListConfig,
        getEndpointIdentity,
        getReportingConfig,
        getProxyOrigin,
        isAllowedTransport,
        refreshRemoteConfig,
        initRemoteConfig,
        ensureCustomProviders: seedCustomProviders,
        remoteConfigStorageKey,
        remoteConfigAlarmName,
        remoteConfigRefreshMinutes,
    });
})();
