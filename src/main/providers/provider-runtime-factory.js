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

globalThis.OspreyProviderRuntimeFactory = (() => {
    const policyService = globalThis.OspreyPolicyService;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerGroups = globalThis.OspreyProviderGroups;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const protectionResult = globalThis.OspreyProtectionResult;

    const malicious = protectionResult.resultTypes.MALICIOUS;
    const phishing = protectionResult.resultTypes.PHISHING;
    const suspicious = protectionResult.resultTypes.SUSPICIOUS;
    const newlyRegistered = protectionResult.resultTypes.NEWLY_REGISTERED;
    const dynamicDns = protectionResult.resultTypes.DYNAMIC_DNS;

    const emptyCategoryState = Object.freeze(Object.create(null));
    const managedBlocklistID = 'managed-blocklist';

    const resolveProxyBaseOverride = raw => {
        if (typeof raw !== 'string') {
            return '';
        }

        const trimmed = raw.trim();

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
        return parsed.origin;
    };

    const resolveRequestTimeoutMs = rawState => {
        if (rawState === undefined) {
            return 0;
        }

        const value = Number(rawState.requestTimeoutMs);
        return Number.isFinite(value) && value > 0 ? value : 0;
    };

    const resolveBlockCategoryState = (definition, rawState) => {
        const declared = Array.isArray(definition.blockCategories) ? definition.blockCategories : null;

        if (!declared || declared.length === 0) {
            return emptyCategoryState;
        }

        const stored = rawState && typeof rawState.blockCategories === 'object' && rawState.blockCategories ?
            rawState.blockCategories :
            null;

        const out = Object.create(null);

        for (const element of declared) {
            const key = element.key;
            const storedValue = stored ? stored[key] : undefined;
            out[key] = typeof storedValue === 'boolean' ? storedValue : Boolean(element.defaultEnabled);
        }
        return Object.freeze(out);
    };

    let cachedRuntime = null;
    let loadingRuntime = null;
    let cachedAppRuntime = null;
    let loadingAppRuntime = null;

    const buildRuntime = async () => {
        const persistedState = await providerStateStore.getState();
        const policyResult = await policyService.applyToState(persistedState);

        const {
            effectiveState,
            policies,
            appManagedKeys,
            providerManagedIds,
            providerManagedApiKeyIds,
            commercialDisabledIds,
        } = policyResult;

        const proxyBaseOverride = resolveProxyBaseOverride(policies.ProxyBaseUrl);
        const proxyApiKey = proxyBaseOverride && typeof policies.ProxyApiKey === 'string' ? policies.ProxyApiKey.trim() : '';

        const definitions = providerCatalog.getAllDefinitions();
        const definitionsLength = definitions.length;

        const providersById = new Map();
        const providers = Array.from({length: definitionsLength});

        const blockingProviderIdsByResult = {
            [phishing]: new Set(),
            [malicious]: new Set(),
            [suspicious]: new Set(),
            [newlyRegistered]: new Set(),
            [dynamicDns]: new Set(),
        };

        for (let i = 0; i < definitionsLength; i++) {
            const definition = definitions[i];
            const rawState = effectiveState.providers?.[definition.id];

            const enabled = rawState === undefined ? definition.enabledByDefault : Boolean(rawState.enabled);
            const apiKey = rawState === undefined ? '' : String(rawState.apiKey || '');

            const bypassBlockingThreshold = rawState !== undefined && typeof rawState.bypassBlockingThreshold === 'boolean' ?
                rawState.bypassBlockingThreshold :
                Boolean(definition.bypassBlockingThreshold);

            const blockCategoryState = resolveBlockCategoryState(definition, rawState);
            const requestTimeoutMs = resolveRequestTimeoutMs(rawState);

            const effectiveProxyBaseUrl = definition.kind === 'proxy_builtin' && proxyBaseOverride && !providerCatalog.isCustomProvider(definition.id)
                ? proxyBaseOverride
                : definition.proxyBaseUrl;

            const effectiveProxyApiKey = definition.kind === 'proxy_builtin' && proxyApiKey && !providerCatalog.isCustomProvider(definition.id)
                ? proxyApiKey
                : '';

            const provider = Object.freeze({
                ...definition,
                proxyBaseUrl: effectiveProxyBaseUrl,
                proxyApiKey: effectiveProxyApiKey,
                bypassBlockingThreshold,
                blockCategoryState,
                state: Object.freeze({enabled, apiKey, bypassBlockingThreshold, blockCategoryState, requestTimeoutMs}),
                managed: providerManagedIds.has(definition.id),
            });

            providers[i] = provider;
            providersById.set(provider.id, provider);

            if (enabled) {
                if (providerCatalog.supportsBlockingResult(provider, phishing)) {
                    blockingProviderIdsByResult[phishing].add(provider.id);
                }

                if (providerCatalog.supportsBlockingResult(provider, malicious)) {
                    blockingProviderIdsByResult[malicious].add(provider.id);
                }

                if (providerCatalog.supportsBlockingResult(provider, suspicious)) {
                    blockingProviderIdsByResult[suspicious].add(provider.id);
                }

                if (providerCatalog.supportsBlockingResult(provider, newlyRegistered)) {
                    blockingProviderIdsByResult[newlyRegistered].add(provider.id);
                }

                if (providerCatalog.supportsBlockingResult(provider, dynamicDns)) {
                    blockingProviderIdsByResult[dynamicDns].add(provider.id);
                }
            }
        }

        const managedBlocklist = Array.isArray(policies.ManagedBlocklist) ?
            policies.ManagedBlocklist.filter(entry => typeof entry === 'string' && entry.trim()) :
            [];

        if (managedBlocklist.length > 0) {
            const managedProvider = Object.freeze({
                id: managedBlocklistID,
                kind: 'managed_local',
                displayName: 'Managed Blocklist',
                group: 'security_filters',
                icon: '',
                aliases: [],
                enabledByDefault: true,
                bypassBlockingThreshold: true,
                blockCategories: [],
                blockCategoryState: emptyCategoryState,
                lookupTarget: 'url',
                tags: ['managed'],
                report: {type: 'none'},
                managed: true,
                state: Object.freeze({
                    enabled: true,
                    apiKey: '',
                    bypassBlockingThreshold: true,
                    blockCategoryState: emptyCategoryState,
                    requestTimeoutMs: 0,
                }),
            });

            providers.push(managedProvider);
            providersById.set(managedBlocklistID, managedProvider);
            blockingProviderIdsByResult[malicious].add(managedBlocklistID);
        }

        providers.sort((a, b) => {
            const orderA = providerGroups[a.group]?.order ?? 999;
            const orderB = providerGroups[b.group]?.order ?? 999;
            return orderA - orderB || a.displayName.localeCompare(b.displayName);
        });

        return Object.freeze({
            persistedState,
            effectiveState,
            policies,
            appManagedKeys,
            providerManagedIds,
            providerManagedApiKeyIds,
            commercialDisabledIds,
            providers,
            providersById,
            blockingProviderIdsByResult: Object.freeze(blockingProviderIdsByResult),
        });
    };

    const buildAppRuntime = async () => {
        const persistedState = await providerStateStore.getState();
        const policyResult = await policyService.applyToAppState(persistedState);

        return Object.freeze({
            persistedState,
            effectiveState: Object.freeze({
                app: policyResult.effectiveApp,
            }),
            policies: policyResult.policies,
            appManagedKeys: policyResult.appManagedKeys,
        });
    };

    const createRuntime = async ({fresh = false} = {}) => {
        if (!fresh && cachedRuntime) {
            return cachedRuntime;
        }

        if (!fresh && loadingRuntime) {
            return loadingRuntime;
        }

        const loadPromise = buildRuntime();
        loadingRuntime = loadPromise;

        try {
            cachedRuntime = await loadPromise;
            return cachedRuntime;
        } finally {
            if (loadingRuntime === loadPromise) {
                loadingRuntime = null;
            }
        }
    };

    const createAppRuntime = async ({fresh = false} = {}) => {
        if (!fresh && cachedAppRuntime) {
            return cachedAppRuntime;
        }

        if (!fresh && loadingAppRuntime) {
            return loadingAppRuntime;
        }

        const loadPromise = buildAppRuntime();
        loadingAppRuntime = loadPromise;

        try {
            cachedAppRuntime = await loadPromise;
            return cachedAppRuntime;
        } finally {
            if (loadingAppRuntime === loadPromise) {
                loadingAppRuntime = null;
            }
        }
    };

    const invalidate = () => {
        cachedRuntime = null;
        cachedAppRuntime = null;
    };

    const remoteConfigStorageKey = 'osprey_remote_config';

    globalThis.OspreyBrowserAPI.api?.storage?.onChanged?.addListener((changes, area) => {
        const localRelevant = area === 'local' && (changes?.[providerStateStore.stateKey] || changes?.[remoteConfigStorageKey]);

        if (localRelevant || area === 'managed') {
            invalidate();
        }
    });

    return Object.freeze({
        createRuntime,
        createAppRuntime,
    });
})();
