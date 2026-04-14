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

globalThis.OspreyProviderRuntimeFactory = (() => {
    // Global variables
    const policyService = globalThis.OspreyPolicyService;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerGroups = globalThis.OspreyProviderGroups;
    const providerStateStore = globalThis.OspreyProviderStateStore;

    let cachedRuntime = null;
    let loadingRuntime = null;

    const buildRuntime = async () => {
        const persistedState = await providerStateStore.getState();
        const policyResult = await policyService.applyToState(persistedState);
        const {effectiveState, policies, appManagedKeys, providerManagedIds, providerManagedApiKeyIds} = policyResult;
        const definitions = providerCatalog.getAllDefinitions(effectiveState);

        const providers = definitions.map(definition => {
            const providerState = effectiveState.providers?.[definition.id] ?? {
                enabled: definition.enabledByDefault,
                apiKey: ''
            };

            const state = Object.freeze({
                enabled: Boolean(providerState.enabled),
                apiKey: String(providerState.apiKey || ''),
            });

            return Object.freeze({
                ...definition,
                state,
                managed: providerManagedIds.has(definition.id),
            });
        }).sort((a, b) =>
            (providerGroups[a.group]?.order ?? 999) - (providerGroups[b.group]?.order ?? 999) ||
            a.displayName.localeCompare(b.displayName)
        );

        return Object.freeze({
            persistedState,
            effectiveState,
            policies,
            appManagedKeys,
            providerManagedIds,
            providerManagedApiKeyIds,
            providers,
        });
    };


    const createRuntime = async ({fresh = false} = {}) => {
        if (!fresh && cachedRuntime) {
            return cachedRuntime;
        }

        if (fresh || !loadingRuntime) {
            loadingRuntime = buildRuntime().then(runtime => {
                cachedRuntime = runtime;
                loadingRuntime = null;
                return runtime;
            }).catch(error => {
                loadingRuntime = null;
                throw error;
            });
        }

        return loadingRuntime;
    };

    const invalidate = () => {
        cachedRuntime = null;
        loadingRuntime = null;
    };

    globalThis.OspreyBrowserAPI.api?.storage?.onChanged?.addListener((changes, area) => {
        if (area === 'local' && changes?.[providerStateStore.stateKey] || area === 'managed') {
            invalidate();
        }
    });

    // Public API
    return Object.freeze({
        createRuntime,
        invalidate,
    });
})();
