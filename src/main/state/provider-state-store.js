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

globalThis.OspreyProviderStateStore = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const providerCatalog = globalThis.OspreyProviderCatalog;

    const stateKey = 'osprey_state';
    const legacyKey = 'Settings';

    let cachedState = null;
    let loadingPromise = null;
    let writeLock = Promise.resolve();

    const unsafeProviderKeys = new Set(['__proto__', 'prototype', 'constructor']);
    const isUnsafeProviderId = providerId => typeof providerId !== 'string' || unsafeProviderKeys.has(providerId);
    const emptyCategoryState = Object.freeze(Object.create(null));

    const normalizeBlockCategories = (definition, src) => {
        const declared = Array.isArray(definition.blockCategories) ? definition.blockCategories : null;

        if (!declared || declared.length === 0) {
            return emptyCategoryState;
        }

        const stored = src && typeof src.blockCategories === 'object' && src.blockCategories ? src.blockCategories : null;
        const out = Object.create(null);

        for (const element of declared) {
            const key = element.key;
            const storedValue = stored ? stored[key] : undefined;
            out[key] = typeof storedValue === 'boolean' ? storedValue : Boolean(element.defaultEnabled);
        }
        return Object.freeze(out);
    };

    const cloneState = state => {
        if (!state) {
            return null;
        }

        const cloned = {
            version: state.version,
            app: {...state.app},
            providers: Object.create(null),
        };

        const pKeys = Object.keys(state.providers);

        for (const element of pKeys) {
            const k = element;
            cloned.providers[k] = {...state.providers[k]};
        }
        return cloned;
    };

    const normalizeState = input => {
        const state = input && typeof input === 'object' ? input : {};
        const app = state.app && typeof state.app === 'object' ? state.app : {};

        const base = {
            version: 2,
            app: {
                hideWarningProceedButton: typeof app.hideWarningProceedButton === 'boolean' ? app.hideWarningProceedButton : typeof app.hideContinueButtons === 'boolean' ? app.hideContinueButtons : false,
                hideWarningReportButton: typeof app.hideWarningReportButton === 'boolean' ? app.hideWarningReportButton : typeof app.hideReportButton === 'boolean' ? app.hideReportButton : false,
                lockProviderSettings: typeof app.lockProviderSettings === 'boolean' ? app.lockProviderSettings : typeof app.lockSettings === 'boolean' ? app.lockSettings : typeof app.lockProtectionOptions === 'boolean' ? app.lockProtectionOptions : false,
                hideProviderControls: typeof app.hideProviderControls === 'boolean' ? app.hideProviderControls : typeof app.hidePopupPanel === 'boolean' ? app.hidePopupPanel : typeof app.hideProtectionOptions === 'boolean' ? app.hideProtectionOptions : false,
                lockUserAllowlist: typeof app.lockUserAllowlist === 'boolean' ? app.lockUserAllowlist : typeof app.disableClearAllowedWebsites === 'boolean' ? app.disableClearAllowedWebsites : false,
                disableSettingsReset: typeof app.disableSettingsReset === 'boolean' ? app.disableSettingsReset : typeof app.disableResetButtons === 'boolean' ? app.disableResetButtons : false,
                disableThirdPartyProviders: typeof app.disableThirdPartyProviders === 'boolean' ? app.disableThirdPartyProviders : typeof app.disableThirdPartyIntegrations === 'boolean' ? app.disableThirdPartyIntegrations : false,
                disableAllProviders: typeof app.disableAllProviders === 'boolean' ? app.disableAllProviders : false,
                cacheExpirationSeconds: 604800,
                proxyBaseUrl: typeof app.proxyBaseUrl === 'string' ? app.proxyBaseUrl : '',
                deviceTag: typeof app.deviceTag === 'string' ? app.deviceTag : '',
                siteId: typeof app.siteId === 'string' ? app.siteId : '',
                disableUserAllowlist: typeof app.disableUserAllowlist === 'boolean' ? app.disableUserAllowlist : false,
                managedAllowlist: Array.isArray(app.managedAllowlist) ? app.managedAllowlist.filter(entry => typeof entry === 'string') : [],
                managedBlocklist: Array.isArray(app.managedBlocklist) ? app.managedBlocklist.filter(entry => typeof entry === 'string') : [],
            },
            providers: Object.create(null),
        };

        const exp = Number(app.cacheExpirationSeconds);

        if (Number.isFinite(exp) && exp >= 60 && exp <= 2592000) {
            base.app.cacheExpirationSeconds = exp;
        }

        const providersInput = state.providers && typeof state.providers === 'object' ? state.providers : {};
        const defs = providerCatalog.getAllDefinitions();

        for (const element of defs) {
            const id = element.id;
            const src = providersInput[id];

            base.providers[id] = {
                enabled: src && typeof src.enabled === 'boolean' ? src.enabled : Boolean(element.enabledByDefault),
                apiKey: src && typeof src.apiKey === 'string' ? src.apiKey : '',

                bypassBlockingThreshold: src && typeof src.bypassBlockingThreshold === 'boolean' ?
                    src.bypassBlockingThreshold :
                    Boolean(element.bypassBlockingThreshold),

                blockCategories: normalizeBlockCategories(element, src),

                requestTimeoutMs: src && Number.isFinite(Number(src.requestTimeoutMs)) && Number(src.requestTimeoutMs) > 0 ?
                    Number(src.requestTimeoutMs) :
                    0,
            };

            Object.freeze(base.providers[id]);
        }

        Object.freeze(base.app);
        Object.freeze(base.providers);
        return Object.freeze(base);
    };

    const migrateLegacyState = legacySettings => {
        const source = legacySettings && typeof legacySettings === 'object' ? legacySettings : {};

        const draft = {
            app: {
                hideWarningProceedButton: source.hideWarningProceedButton ?? source.hideContinueButtons,
                hideWarningReportButton: source.hideWarningReportButton ?? source.hideReportButton,
                lockProviderSettings: source.lockProviderSettings ?? source.lockSettings ?? source.lockProtectionOptions,
                hideProviderControls: source.hideProviderControls ?? source.hidePopupPanel ?? source.hideProtectionOptions,
                lockUserAllowlist: source.lockUserAllowlist ?? source.disableClearAllowedWebsites,
                disableSettingsReset: source.disableSettingsReset ?? source.disableResetButtons,
                disableThirdPartyProviders: source.disableThirdPartyProviders ?? source.disableThirdPartyIntegrations,
                disableAllProviders: source.disableAllProviders,
                cacheExpirationSeconds: source.cacheExpirationSeconds,
            },
            providers: {},
        };

        const defs = providerCatalog.getAllDefinitions();

        for (const element of defs) {
            const def = element;
            const aliasKey = def.aliases && def.aliases.length > 0 ? def.aliases[0] : def.id;

            draft.providers[def.id] = {
                enabled: source[aliasKey + 'Enabled'],
                apiKey: source[aliasKey + 'ApiKey'],
            };
        }
        return normalizeState(draft);
    };

    const readStoredState = async () => {
        try {
            const stored = await browserAPI.storageGet('local', stateKey);

            if (stored?.[stateKey]) {
                return normalizeState(stored[stateKey]);
            }
        } catch {
            // ignored
        }

        try {
            const legacy = await browserAPI.storageGet('local', [legacyKey]);
            const migrated = migrateLegacyState(legacy?.[legacyKey]);

            browserAPI.storageSet('local', {[stateKey]: migrated}).catch(error => {
                console.error('OspreyProviderStateStore failed to persist migrated legacy state', error);
            });
            return migrated;
        } catch (error) {
            console.error('OspreyProviderStateStore failed to load legacy state', error);
            return normalizeState({});
        }
    };

    const getState = ({fresh = false} = {}) => {
        if (!fresh) {
            if (cachedState) {
                return Promise.resolve(cachedState);
            }

            if (loadingPromise) {
                return loadingPromise;
            }
        }

        const promise = readStoredState().then(state => {
            cachedState = state;

            if (loadingPromise === promise) {
                loadingPromise = null;
            }
            return cachedState;
        }).catch(error => {
            if (loadingPromise === promise) {
                loadingPromise = null;
            }
            throw error;
        });

        loadingPromise = promise;
        return promise;
    };

    const enqueueWrite = taskFn => {
        const taskPromise = writeLock.then(taskFn);

        writeLock = taskPromise.catch(() => {
            // ignored
        });
        return taskPromise;
    };

    const updateState = updater => enqueueWrite(async () => {
        const current = await getState();
        const draft = cloneState(current);
        const result = typeof updater === 'function' ? await updater(draft) : undefined;
        const modifiedDraft = result || draft;

        const normalized = normalizeState(modifiedDraft);
        cachedState = normalized;

        await browserAPI.storageSet('local', {[stateKey]: normalized});
        return normalized;
    });

    const getPolicyLocks = () =>
        globalThis.OspreyPolicyService?.getEffectiveAppLocks?.() ?? Promise.resolve({});

    const setProviderEnabled = (providerId, enabled) => updateState(async state => {
        const locks = await getPolicyLocks();

        if (isUnsafeProviderId(providerId) || state.app.lockProviderSettings || locks.lockProviderSettings) {
            return;
        }

        const provider = state.providers[providerId] || (state.providers[providerId] = {
            enabled: false,
            apiKey: '',
        });

        provider.enabled = Boolean(enabled);
    });

    const setDisableAllProviders = disabled => updateState(async state => {
        const locks = await getPolicyLocks();

        if (state.app.lockProviderSettings || locks.lockProviderSettings) {
            return;
        }

        state.app = {...state.app, disableAllProviders: Boolean(disabled)};
    });

    const setProviderApiKey = (providerId, apiKey) => updateState(async state => {
        const locks = await getPolicyLocks();

        if (isUnsafeProviderId(providerId) || state.app.lockProviderSettings || locks.lockProviderSettings) {
            return;
        }

        const normalizedApiKey = String(apiKey ?? '');
        const sharedMembers = providerCatalog.getSharedGroupMembersById(providerId);

        if (sharedMembers && sharedMembers.length > 0) {
            for (const element of sharedMembers) {
                const memberId = element;

                const provider = state.providers[memberId] || (state.providers[memberId] = {
                    enabled: false,
                    apiKey: '',
                });

                provider.apiKey = normalizedApiKey;
            }
        } else {
            const provider = state.providers[providerId] || (state.providers[providerId] = {
                enabled: false,
                apiKey: '',
            });

            provider.apiKey = normalizedApiKey;
        }
    });

    const setBypassBlockingThreshold = (providerId, bypass) => updateState(async state => {
        const locks = await getPolicyLocks();

        if (isUnsafeProviderId(providerId) || state.app.lockProviderSettings || locks.lockProviderSettings) {
            return;
        }

        const provider = state.providers[providerId] || (state.providers[providerId] = {
            enabled: false,
            apiKey: '',
        });

        provider.bypassBlockingThreshold = Boolean(bypass);
    });

    const setBlockCategory = (providerId, categoryKey, enabled) => updateState(async state => {
        const locks = await getPolicyLocks();

        if (isUnsafeProviderId(providerId) || state.app.lockProviderSettings || locks.lockProviderSettings) {
            return;
        }

        const definition = providerCatalog.getDefinition(providerId);
        const declared = definition && Array.isArray(definition.blockCategories) ? definition.blockCategories : null;

        if (!declared?.some(category => category.key === categoryKey)) {
            return;
        }

        const provider = state.providers[providerId] || (state.providers[providerId] = {
            enabled: false,
            apiKey: '',
        });

        const current = provider.blockCategories && typeof provider.blockCategories === 'object' ?
            provider.blockCategories :
            null;

        const next = Object.create(null);

        if (current) {
            for (const key of Object.keys(current)) {
                next[key] = current[key];
            }
        }

        next[categoryKey] = Boolean(enabled);
        provider.blockCategories = next;
    });

    const resetDefaultProviders = () => updateState(async state => {
        const locks = await getPolicyLocks();

        if (state.app.disableSettingsReset || locks.disableSettingsReset) {
            return;
        }

        const defs = providerCatalog.getAllDefinitions();

        for (const element of defs) {
            const def = element;

            const provider = state.providers[def.id] || (state.providers[def.id] = {
                enabled: false,
                apiKey: ''
            });

            provider.enabled = Boolean(def.enabledByDefault);
            provider.bypassBlockingThreshold = Boolean(def.bypassBlockingThreshold);
            provider.blockCategories = Object.create(null);
        }
    });

    const resetAll = () => updateState(async state => {
        const locks = await getPolicyLocks();

        if (state.app.disableSettingsReset || locks.disableSettingsReset) {
            return;
        }
        return {};
    });

    const importState = rawState => updateState(async state => {
        const locks = await getPolicyLocks();

        if (state.app.lockProviderSettings || locks.lockProviderSettings) {
            return;
        }
        return rawState && typeof rawState === 'object' ? rawState : {};
    });

    const countEnabledProviders = state => {
        if (!state?.providers) {
            return 0;
        }

        let count = 0;
        const keys = Object.keys(state.providers);

        for (const element of keys) {
            if (state.providers[element].enabled) {
                count++;
            }
        }
        return count;
    };

    const countTotalProviders = () => providerCatalog.getAllDefinitions().length;

    const invalidateCache = () => {
        cachedState = null;
        loadingPromise = null;
    };

    const remoteConfigStorageKey = 'osprey_remote_config';

    if (browserAPI.api?.storage?.onChanged?.addListener) {
        browserAPI.api.storage.onChanged.addListener((changes, area) => {
            if (area === 'local' && (changes?.[stateKey] || changes?.[remoteConfigStorageKey])) {
                invalidateCache();
            }
        });
    }

    return Object.freeze({
        stateKey,
        getState,
        setProviderEnabled,
        setDisableAllProviders,
        setProviderApiKey,
        setBypassBlockingThreshold,
        setBlockCategory,
        resetDefaultProviders,
        resetAll,
        importState,
        countEnabledProviders,
        countTotalProviders,
    });
})();
