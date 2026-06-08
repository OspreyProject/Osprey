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

globalThis.OspreyPolicyService = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const providerCatalog = globalThis.OspreyProviderCatalog;

    let cachedPolicies = null;
    let cachedPoliciesPromise = null;

    const identityMap = value => value;
    const negateMap = value => !value;

    const appPolicyMappings = [
        {
            policyKey: 'DisableContextMenu',
            type: 'boolean',
            stateKey: 'contextMenuEnabled',
            mapValue: negateMap
        },
        {
            policyKey: 'HideContinueButtons',
            type: 'boolean',
            stateKey: 'hideContinueButtons',
            mapValue: identityMap
        },
        {
            policyKey: 'HideReportButton',
            type: 'boolean',
            stateKey: 'hideReportButton',
            mapValue: identityMap
        },
        {
            policyKey: 'CacheExpirationSeconds',
            type: 'number',
            stateKey: 'cacheExpirationSeconds',
            mapValue: identityMap
        },
        {
            policyKey: 'DisableClearAllowedWebsites',
            type: 'boolean',
            stateKey: 'disableClearAllowedWebsites',
            mapValue: identityMap
        },
        {
            policyKey: 'LockProtectionOptions',
            type: 'boolean',
            stateKey: 'lockSettings',
            mapValue: identityMap
        },
        {
            policyKey: 'HideProtectionOptions',
            type: 'boolean',
            stateKey: 'hidePopupPanel',
            mapValue: identityMap
        },
        {
            policyKey: 'DisableResetButtons',
            type: 'boolean',
            stateKey: 'disableResetButtons',
            mapValue: identityMap
        },
        {
            policyKey: 'DisableThirdPartyIntegrations',
            type: 'boolean',
            stateKey: 'disableThirdPartyIntegrations',
            mapValue: identityMap
        },
    ];

    const apiKeyKeyCache = Object.create(null);

    const getApiKeyPolicyKey = id => {
        let cached = apiKeyKeyCache[id];

        if (cached !== undefined) {
            return cached;
        }

        const generated = `${id.charAt(0).toUpperCase()}${id.slice(1)}ApiKey`;
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
    };

    const applyProviderPolicies = (providers, policies, providerManagedIds, providerManagedApiKeyIds, disableThirdPartyIntegrations) => {
        const builtins = providerCatalog.getBuiltins();

        for (const element of builtins) {
            const definition = element;
            const policyKey = definition.policyKey;

            if (policyKey !== undefined && typeof policies[policyKey] === 'boolean') {
                ensureProviderState(providers, definition).enabled = policies[policyKey];
                providerManagedIds.add(definition.id);
            }
        }

        const directIntegrations = providerCatalog.getDirectIntegrations();

        for (const element of directIntegrations) {
            const definition = element;
            const providerState = ensureProviderState(providers, definition);
            const apiKeyPolicyKey = getApiKeyPolicyKey(definition.id);

            if (disableThirdPartyIntegrations) {
                providerState.enabled = false;
                providerManagedIds.add(definition.id);
            }

            const policyApiVal = policies[apiKeyPolicyKey];

            if (typeof policyApiVal === 'string') {
                providerState.apiKey = policyApiVal;
                const sharedMembers = providerCatalog.getSharedGroupMembersById(definition.id);

                if (sharedMembers !== undefined && sharedMembers.length > 0) {
                    for (const element of sharedMembers) {
                        const memberId = element;
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
    };

    const getPolicies = async ({fresh = false} = {}) => {
        if (!fresh && cachedPolicies !== null) {
            return cachedPolicies;
        }

        if (!fresh && cachedPoliciesPromise !== null) {
            return cachedPoliciesPromise;
        }

        const managedStorage = browserAPI.api?.storage?.managed;

        if (managedStorage?.get === undefined) {
            cachedPolicies = Object.freeze({});
            return cachedPolicies;
        }

        cachedPoliciesPromise = (async () => {
            try {
                const result = await browserAPI.storageGet('managed', null);
                cachedPolicies = Object.freeze(result || {});
            } catch (error) {
                console.warn('OspreyPolicyService failed to read managed policies', error);
                cachedPolicies = Object.freeze({});
            }

            cachedPoliciesPromise = null;
            return cachedPolicies;
        })();
        return cachedPoliciesPromise;
    };

    const applyToState = async state => {
        const policies = await getPolicies();
        const effectiveApp = fastCloneApp(state.app);
        const effectiveProviders = fastCloneProviders(state.providers);

        const effective = {
            ...state,
            app: effectiveApp,
            providers: effectiveProviders
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
            effective.app.disableThirdPartyIntegrations
        );

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
        cachedPolicies = null;
        cachedPoliciesPromise = null;
    };

    const storageApi = browserAPI.api?.storage;

    if (storageApi?.onChanged?.addListener !== undefined) {
        storageApi.onChanged.addListener((changes, area) => {
            if (area === 'managed') {
                invalidate();
            }
        });
    }

    return Object.freeze({
        applyToState,
        applyToAppState,
    });
})();
