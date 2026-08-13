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
    const controlOnlyPolicyKeys = new Set(['ManagedConfigUrl']);
    const unsafeKeys = new Set(['__proto__', 'constructor', 'prototype']);

    let cachedManagedPolicies = null;
    let cachedManagedPoliciesPromise = null;
    let cachedRemoteConfig = null;
    let cachedRemoteConfigPromise = null;
    let cachedEffectivePolicies = null;
    let cachedManagedListConfig = null;
    let lastSeededCustomKey = null;

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

    const appPolicyMappings = [
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
            mapValue: identityMap,
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
            policyKey: 'DisableThirdPartyProviders',
            type: 'boolean',
            stateKey: 'disableThirdPartyProviders',
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

    const toPascalCase = value => String(value || '')
        .split(/[-_]+/)
        .filter(Boolean)
        .map(part => part.charAt(0).toUpperCase() + part.slice(1))
        .join('');

    const apiKeyKeyCache = Object.create(null);

    const getApiKeyPolicyKey = definition => {
        const id = definition.id;
        const cached = apiKeyKeyCache[id];

        if (cached !== undefined) {
            return cached;
        }

        const generated = typeof definition.apiKeyPolicyKey === 'string' && definition.apiKeyPolicyKey ?
            definition.apiKeyPolicyKey :
            `${toPascalCase(definition.sharedApiKeyGroup || id)}ApiKey`;

        apiKeyKeyCache[id] = generated;
        return generated;
    };

    const ensureProviderState = (providers, definition) => {
        let state = providers[definition.id];

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
                app[mapping.stateKey] = mapping.mapValue(policyVal);

                if (appManagedKeys !== undefined) {
                    appManagedKeys.add(mapping.stateKey);
                }
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

    const applyProviderPolicies = (providers, policies, providerManagedIds, providerManagedApiKeyIds, disableThirdPartyProviders) => {
        const directIntegrations = providerCatalog.getDirectIntegrations();

        for (const element of directIntegrations) {
            const definition = element;
            const providerState = ensureProviderState(providers, definition);
            const apiKeyPolicyKey = getApiKeyPolicyKey(definition);

            if (disableThirdPartyProviders) {
                providerState.enabled = false;
                providerManagedIds.add(definition.id);
            }

            const policyApiVal = policies[apiKeyPolicyKey];

            if (typeof policyApiVal === 'string') {
                providerState.apiKey = policyApiVal;
                const sharedMembers = providerCatalog.getSharedGroupMembersById(definition.id);

                if (sharedMembers !== undefined && sharedMembers.length > 0) {
                    for (const sharedId of sharedMembers) {
                        const memberId = sharedId;
                        let def = providerCatalog.getDefinition(memberId);

                        if (def === undefined) {
                            def = {id: memberId, enabledByDefault: false};
                        }

                        ensureProviderState(providers, def).apiKey = policyApiVal;
                        providerManagedApiKeyIds.add(memberId);
                    }
                } else {
                    providerManagedApiKeyIds.add(definition.id);
                }
            }
        }

        applyManagedProviderSettings(providers, policies, providerManagedIds);
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

        cachedManagedPoliciesPromise = (async () => {
            try {
                const result = await browserAPI.storageGet('managed', null);
                cachedManagedPolicies = Object.freeze(result || {});
            } catch (error) {
                if (error && typeof error.message === 'string' && !error.message.includes('Managed storage manifest not found')) {
                    console.warn('OspreyPolicyService failed to read managed policies', error);
                }

                cachedManagedPolicies = Object.freeze({});
            }

            cachedManagedPoliciesPromise = null;
            return cachedManagedPolicies;
        })();
        return cachedManagedPoliciesPromise;
    };

    const isPlainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);

    const getStaticDefinitions = () => providerCatalog.getBuiltins().concat(providerCatalog.getDirectIntegrations());

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

                if (key === 'policies' || key === 'customProviders' || key === 'version') {
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

    const readStoredRemoteConfig = async () => {
        try {
            const stored = await browserAPI.storageGet('local', remoteConfigStorageKey);
            const document = stored ? stored[remoteConfigStorageKey] : null;

            if (isPlainObject(document)) {
                return {
                    policies: isPlainObject(document.policies) ? document.policies : {},
                    customProviders: Array.isArray(document.customProviders) ? document.customProviders : [],
                };
            }
        } catch (error) {
            console.warn('OspreyPolicyService failed to read stored remote config', error);
        }
        return {policies: {}, customProviders: []};
    };

    const getRemoteConfig = async ({fresh = false} = {}) => {
        if (!fresh && cachedRemoteConfig !== null) {
            return cachedRemoteConfig;
        }

        if (!fresh && cachedRemoteConfigPromise !== null) {
            return cachedRemoteConfigPromise;
        }

        cachedRemoteConfigPromise = (async () => {
            const stored = await readStoredRemoteConfig();

            cachedRemoteConfig = Object.freeze({
                policies: Object.freeze({...stored.policies}),
                customProviders: Object.freeze(stored.customProviders.slice()),
            });

            cachedRemoteConfigPromise = null;
            return cachedRemoteConfig;
        })();
        return cachedRemoteConfigPromise;
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
        return Object.freeze(merged);
    };

    const getPolicies = async ({fresh = false} = {}) => {
        if (!fresh && cachedEffectivePolicies !== null) {
            return cachedEffectivePolicies;
        }

        const [managed, remote] = await Promise.all([
            getManagedPolicies({fresh}),
            getRemoteConfig({fresh}),
        ]);

        cachedEffectivePolicies = buildEffectivePolicies(managed, remote.policies);
        return cachedEffectivePolicies;
    };

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

        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            console.warn('OspreyPolicyService ignoring non-http(s) ManagedConfigUrl');
            return '';
        }
        return parsed.href;
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
                headers: {Accept: 'application/json'},
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const text = await response.text();

            if (text.length > remoteConfigMaxBytes) {
                throw new Error(`config document exceeds ${remoteConfigMaxBytes} bytes`);
            }
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
        const managed = await getManagedPolicies();
        const url = resolveConfigUrl(managed);

        if (!url) {
            return {ok: false, reason: 'no-url'};
        }

        let document;

        try {
            document = await fetchConfigDocument(url);
        } catch (error) {
            console.warn('OspreyPolicyService remote config fetch failed; keeping last-known-good', error);
            return {ok: false, reason: 'fetch-failed'};
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

        const payload = {
            policies: sanitized.policies,
            customProviders,
            updatedAt: Date.now(),
        };

        await persistRemoteConfig(payload);

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

    const applyToState = async state => {
        const policies = await getPolicies();
        const effectiveApp = fastCloneApp(state.app);
        const effectiveProviders = fastCloneProviders(state.providers);

        const effective = {
            ...state,
            app: effectiveApp,
            providers: effectiveProviders,
        };

        const appManagedKeys = new Set();
        const providerManagedIds = new Set();
        const providerManagedApiKeyIds = new Set();

        applyAppPolicies(effective.app, policies, appManagedKeys);

        applyProviderPolicies(
            effective.providers,
            policies,
            providerManagedIds,
            providerManagedApiKeyIds,
            effective.app.disableThirdPartyProviders,
        );

        if (effective.app.disableAllProviders) {
            const providerIds = Object.keys(effective.providers);

            for (const providerId of providerIds) {
                effective.providers[providerId].enabled = false;
            }
        }

        return Object.freeze({
            policies,
            effectiveState: effective,
            appManagedKeys,
            providerManagedIds,
            providerManagedApiKeyIds,
        });
    };

    const applyToAppState = async state => {
        const policies = await getPolicies();
        const effectiveApp = fastCloneApp(state.app);
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

        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
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

        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
            return defaultProxyOrigin;
        }
        return parsed.origin;
    };

    const storageApi = browserAPI.api?.storage;

    if (storageApi?.onChanged?.addListener !== undefined) {
        storageApi.onChanged.addListener((changes, area) => {
            if (area === 'managed') {
                invalidate();
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

    return Object.freeze({
        applyToState,
        applyToAppState,
        getEffectiveAppLocks,
        getManagedListConfig,
        getEndpointIdentity,
        getReportingConfig,
        getProxyOrigin,
        refreshRemoteConfig,
        initRemoteConfig,
        remoteConfigStorageKey,
        remoteConfigAlarmName,
        remoteConfigRefreshMinutes,
    });
})();
