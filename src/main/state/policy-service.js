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
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;
    const providerCatalog = globalThis.OspreyProviderCatalog;

    let cachedPolicies = null;

    const appPolicyMappings = [
        ['DisableContextMenu', 'boolean', 'contextMenuEnabled', value => !value],
        ['HideContinueButtons', 'boolean', 'hideContinueButtons'],
        ['HideReportButton', 'boolean', 'hideReportButton'],
        ['IgnoreFrameNavigation', 'boolean', 'ignoreFrameNavigation'],
        ['CacheExpirationSeconds', 'number', 'cacheExpirationSeconds'],
        ['DisableClearAllowedWebsites', 'boolean', 'disableClearAllowedWebsites'],
        ['LockProtectionOptions', 'boolean', 'lockSettings'],
        ['HideProtectionOptions', 'boolean', 'hidePopupPanel'],
        ['DisableResetButtons', 'boolean', 'disableResetButtons'],
        ['DisableCustomProviders', 'boolean', 'disableCustomProviders'],
        ['DisableThirdPartyIntegrations', 'boolean', 'disableThirdPartyIntegrations'],
    ];

    const ensureProviderState = (providers, definition) => providers[definition.id] || (
        providers[definition.id] = {enabled: definition.enabledByDefault, apiKey: ''}
    );

    const getApiKeyPolicyKey = id => `${id.charAt(0).toUpperCase()}${id.slice(1)}ApiKey`;

    const getSharedApiKeyGroupMembers = providerId => {
        const definition = providerCatalog.getDefinition(providerId);
        const groupId = String(definition?.sharedApiKeyGroup || '');

        return groupId ? providerCatalog.getSharedApiKeyGroupMembers(groupId) : [];
    };


    const getPolicies = async ({fresh = false} = {}) => {
        if (!fresh && cachedPolicies) {
            return {...cachedPolicies};
        }

        if (!browserAPI.api?.storage?.managed?.get) {
            cachedPolicies = {};
            return {};
        }

        try {
            cachedPolicies = await browserAPI.storageGet('managed', null) || {};
        } catch (error) {
            console.warn('OspreyPolicyService failed to read managed policies', error);
            cachedPolicies = {};
        }
        return {...cachedPolicies};
    };

    const applyToState = async state => {
        const policies = await getPolicies();
        const effective = structuredClone(state);
        const appManagedKeys = new Set();
        const providerManagedIds = new Set();
        const providerManagedApiKeyIds = new Set();

        const setManaged = (key, value) => {
            effective.app[key] = value;
            appManagedKeys.add(key);
        };

        for (const [policyKey, type, stateKey, mapValue = value => value] of appPolicyMappings) {
            if (typeof policies[policyKey] === type) {
                setManaged(stateKey, mapValue(policies[policyKey]));
            }
        }

        for (const definition of providerCatalog.getBuiltins()) {
            if (definition.policyKey && typeof policies[definition.policyKey] === 'boolean') {
                ensureProviderState(effective.providers, definition).enabled = policies[definition.policyKey];
                providerManagedIds.add(definition.id);
            }
        }

        for (const definition of providerCatalog.getDirectIntegrations()) {
            const providerState = ensureProviderState(effective.providers, definition);
            const apiKeyPolicyKey = getApiKeyPolicyKey(definition.id);

            if (effective.app.disableThirdPartyIntegrations) {
                providerState.enabled = false;
                providerManagedIds.add(definition.id);
            }

            if (typeof policies[apiKeyPolicyKey] === 'string') {
                providerState.apiKey = policies[apiKeyPolicyKey];

                const sharedMembers = getSharedApiKeyGroupMembers(definition.id);

                if (sharedMembers.length > 0) {
                    for (const memberId of sharedMembers) {
                        ensureProviderState(effective.providers, providerCatalog.getDefinition(memberId) || {id: memberId, enabledByDefault: false}).apiKey = policies[apiKeyPolicyKey];
                        providerManagedApiKeyIds.add(memberId);
                    }
                } else {
                    providerManagedApiKeyIds.add(definition.id);
                }
            }
        }

        if (effective.app.disableCustomProviders) {
            for (const definition of providerCatalog.getAllDefinitions(effective)) {
                if (definition.kind !== 'direct_custom' || !effective.providers[definition.id]) {
                    continue;
                }

                effective.providers[definition.id].enabled = false;
                providerManagedIds.add(definition.id);
            }

            effective.customProviders = {};
        }

        return Object.freeze({
            policies,
            effectiveState: effective,
            appManagedKeys,
            providerManagedIds,
            providerManagedApiKeyIds,
        });
    };

    const invalidate = () => {
        cachedPolicies = null;
    };

    browserAPI.api?.storage?.onChanged?.addListener((changes, area) => {
        if (area === 'managed') {
            invalidate();
        }
    });

    // Public API
    return Object.freeze({
        applyToState,
        invalidate,
    });
})();
