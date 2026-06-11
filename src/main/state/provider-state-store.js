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
                contextMenuEnabled: typeof app.contextMenuEnabled === 'boolean' ? app.contextMenuEnabled : true,
                hideContinueButtons: typeof app.hideContinueButtons === 'boolean' ? app.hideContinueButtons : false,
                hideReportButton: typeof app.hideReportButton === 'boolean' ? app.hideReportButton : false,
                lockSettings: typeof app.lockSettings === 'boolean' ? app.lockSettings : typeof app.lockProtectionOptions === 'boolean' ? app.lockProtectionOptions : false,
                hidePopupPanel: typeof app.hidePopupPanel === 'boolean' ? app.hidePopupPanel : typeof app.hideProtectionOptions === 'boolean' ? app.hideProtectionOptions : false,
                disableClearAllowedWebsites: typeof app.disableClearAllowedWebsites === 'boolean' ? app.disableClearAllowedWebsites : false,
                disableResetButtons: typeof app.disableResetButtons === 'boolean' ? app.disableResetButtons : false,
                disableThirdPartyIntegrations: typeof app.disableThirdPartyIntegrations === 'boolean' ? app.disableThirdPartyIntegrations : false,
                cacheExpirationSeconds: 604800,
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
                contextMenuEnabled: source.contextMenuEnabled,
                hideContinueButtons: source.hideContinueButtons,
                hideReportButton: source.hideReportButton,
                lockSettings: source.lockSettings ?? source.lockProtectionOptions,
                hidePopupPanel: source.hidePopupPanel ?? source.hideProtectionOptions,
                disableClearAllowedWebsites: source.disableClearAllowedWebsites,
                disableResetButtons: source.disableResetButtons,
                disableThirdPartyIntegrations: source.disableThirdPartyIntegrations,
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

        if (isUnsafeProviderId(providerId) || state.app.lockSettings || locks.lockSettings) {
            return;
        }

        const provider = state.providers[providerId] || (state.providers[providerId] = {
            enabled: false,
            apiKey: '',
        });

        provider.enabled = Boolean(enabled);
    });

    const setProviderApiKey = (providerId, apiKey) => updateState(async state => {
        const locks = await getPolicyLocks();

        if (isUnsafeProviderId(providerId) || state.app.lockSettings || locks.lockSettings) {
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

    const resetDefaultProviders = () => updateState(async state => {
        const locks = await getPolicyLocks();

        if (state.app.disableResetButtons || locks.disableResetButtons) {
            return;
        }

        const defs = providerCatalog.getAllDefinitions();

        for (const element of defs) {
            const def = element;
            const p = state.providers[def.id] || (state.providers[def.id] = {enabled: false, apiKey: ''});
            p.enabled = Boolean(def.enabledByDefault);
        }
    });

    const resetAll = () => updateState(async state => {
        const locks = await getPolicyLocks();

        if (state.app.disableResetButtons || locks.disableResetButtons) {
            return;
        }
        return {};
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

    if (browserAPI.api?.storage?.onChanged?.addListener) {
        browserAPI.api.storage.onChanged.addListener((changes, area) => {
            if (area === 'local' && changes?.[stateKey]) {
                invalidateCache();
            }
        });
    }

    return Object.freeze({
        stateKey,
        getState,
        setProviderEnabled,
        setProviderApiKey,
        resetDefaultProviders,
        resetAll,
        countEnabledProviders,
        countTotalProviders,
    });
})();
