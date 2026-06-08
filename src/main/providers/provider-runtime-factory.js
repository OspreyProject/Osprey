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

globalThis.OspreyProviderRuntimeFactory = (() => {
    const policyService = globalThis.OspreyPolicyService;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerGroups = globalThis.OspreyProviderGroups;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const protectionResult = globalThis.OspreyProtectionResult;

    const malicious = protectionResult.resultTypes.MALICIOUS;
    const phishing = protectionResult.resultTypes.PHISHING;
    const adultContent = protectionResult.resultTypes.ADULT_CONTENT;

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
        } = policyResult;

        const definitions = providerCatalog.getAllDefinitions();
        const definitionsLength = definitions.length;

        const providersById = new Map();
        const providers = Array.from({length: definitionsLength});

        const blockingProviderIdsByResult = {
            [malicious]: new Set(),
            [phishing]: new Set(),
            [adultContent]: new Set(),
        };

        for (let i = 0; i < definitionsLength; i++) {
            const definition = definitions[i];
            const rawState = effectiveState.providers?.[definition.id];

            const enabled = rawState === undefined ? definition.enabledByDefault : Boolean(rawState.enabled);
            const apiKey = rawState === undefined ? '' : String(rawState.apiKey || '');

            const provider = Object.freeze({
                ...definition,
                state: Object.freeze({enabled, apiKey}),
                managed: providerManagedIds.has(definition.id),
            });

            providers[i] = provider;
            providersById.set(provider.id, provider);

            if (enabled) {
                if (providerCatalog.supportsBlockingResult(provider, malicious)) {
                    blockingProviderIdsByResult[malicious].add(provider.id);
                }

                if (providerCatalog.supportsBlockingResult(provider, phishing)) {
                    blockingProviderIdsByResult[phishing].add(provider.id);
                }

                if (providerCatalog.supportsBlockingResult(provider, adultContent)) {
                    blockingProviderIdsByResult[adultContent].add(provider.id);
                }
            }
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

    globalThis.OspreyBrowserAPI.api?.storage?.onChanged?.addListener((changes, area) => {
        if (area === 'local' && changes?.[providerStateStore.stateKey] || area === 'managed') {
            invalidate();
        }
    });

    return Object.freeze({
        createRuntime,
        createAppRuntime,
    });
})();
