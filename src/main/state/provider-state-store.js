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

globalThis.OspreyProviderStateStore = (() => {
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;
    const providerCatalog = globalThis.OspreyProviderCatalog;

    const stateKey = 'osprey_state';
    const legacyKey = 'Settings';

    let cachedState = null;
    let loadingPromise = null;

    const asObject = value => value && typeof value === 'object' ? value : {};
    const coerceBoolean = (value, fallback) => typeof value === 'boolean' ? value : fallback;
    const coerceString = (value, fallback = '') => typeof value === 'string' ? value : fallback;
    const clone = value => structuredClone(value);

    const coerceNumber = (value, fallback, min = null, max = null) => {
        const num = Number(value);

        if (!Number.isFinite(num) || min !== null && num < min || max !== null && num > max) {
            return fallback;
        }
        return num;
    };

    const ensureProviderState = (state, providerId, enabled = false, apiKey = '') =>
        state.providers[providerId] || (state.providers[providerId] = {enabled, apiKey});

    const applyProviderState = (target, source, providerId, enabledFallback, apiKeyFallback = '') => {
        const providerState = {
            enabled: coerceBoolean(source?.enabled, enabledFallback),
            apiKey: coerceString(source?.apiKey, apiKeyFallback),
        };

        target.providers[providerId] = providerState;
        return providerState;
    };

    const getSharedApiKeyGroupMembers = providerId => {
        const definition = providerCatalog.getDefinition(providerId);
        const groupId = String(definition?.sharedApiKeyGroup || '');
        return groupId ? providerCatalog.getSharedApiKeyGroupMembers(groupId) : [];
    };

    const buildDefaultProviders = () => {
        const providers = Object.create(null);

        for (const {id, enabledByDefault} of providerCatalog.getAllDefinitions()) {
            providers[id] = {enabled: Boolean(enabledByDefault)};
        }
        return providers;
    };

    const defaultState = () => ({
        version: 2,

        app: {
            contextMenuEnabled: true,
            ignoreFrameNavigation: true,
            hideContinueButtons: false,
            hideReportButton: false,
            lockSettings: false,
            hidePopupPanel: false,
            disableClearAllowedWebsites: false,
            disableResetButtons: false,
            disableThirdPartyIntegrations: false,
            cacheExpirationSeconds: 604800,
        },

        providers: buildDefaultProviders(),
    });

    const boolAppKeys = [
        'contextMenuEnabled',
        'ignoreFrameNavigation',
        'hideContinueButtons',
        'hideReportButton',
        'lockSettings',
        'hidePopupPanel',
        'disableClearAllowedWebsites',
        'disableResetButtons',
        'disableThirdPartyIntegrations',
    ];

    const appAliases = {
        lockSettings: 'lockProtectionOptions',
        hidePopupPanel: 'hideProtectionOptions',
    };

    const applyAppSettings = (target, source) => {
        const app = asObject(source);

        for (const key of boolAppKeys) {
            const alias = appAliases[key];
            let value;

            if (Object.hasOwn(app, key)) {
                value = app[key];
            } else if (alias) {
                value = app[alias];
            } else {
                value = undefined;
            }

            target[key] = coerceBoolean(value, target[key]);
        }

        target.cacheExpirationSeconds = coerceNumber(
            app.cacheExpirationSeconds,
            target.cacheExpirationSeconds,
            60,
            2592000
        );
    };

    const normalizeState = input => {
        const base = defaultState();
        const state = asObject(input);

        applyAppSettings(base.app, state.app);

        for (const {id, enabledByDefault} of providerCatalog.getAllDefinitions()) {
            applyProviderState(base, state.providers?.[id] || {}, id, enabledByDefault);
        }
        return base;
    };

    const legacyFieldKeyFor = (definition, suffix) => `${definition.aliases?.[0] || definition.id}${suffix}`;

    const migrateLegacyState = (legacySettings) => {
        const migrated = defaultState();
        const source = asObject(legacySettings);

        applyAppSettings(migrated.app, source);

        for (const definition of providerCatalog.getAllDefinitions()) {
            applyProviderState(migrated, {
                enabled: source[legacyFieldKeyFor(definition, 'Enabled')],
                apiKey: source[legacyFieldKeyFor(definition, 'ApiKey')],
            }, definition.id, definition.enabledByDefault);
        }
        return migrated;
    };

    const readStoredState = async () => {
        const stored = await browserAPI.storageGet('local', stateKey).catch(() => ({}));
        const next = stored?.[stateKey];

        if (next) {
            return normalizeState(next);
        }

        const legacy = await browserAPI.storageGet('local', [legacyKey]).catch(() => ({}));
        const migrated = migrateLegacyState(legacy?.[legacyKey]);

        await browserAPI.storageSet('local', {[stateKey]: migrated}).catch(() => {
            console.error('OspreyProviderStateStore failed to persist migrated legacy state');
        });
        return migrated;
    };

    const getState = async ({fresh = false} = {}) => {
        if (!fresh) {
            if (cachedState) {
                return clone(cachedState);
            }

            if (loadingPromise) {
                return clone(await loadingPromise);
            }
        }

        loadingPromise = readStoredState().then(state => {
            cachedState = normalizeState(state);
            loadingPromise = null;
            return cachedState;
        }).catch(error => {
            loadingPromise = null;
            console.error('OspreyProviderStateStore failed to load state', error);
            throw error;
        });
        return clone(await loadingPromise);
    };

    const setState = async nextState => {
        const normalized = normalizeState(nextState);
        cachedState = normalized;

        await browserAPI.storageSet('local', {[stateKey]: normalized});
        return clone(normalized);
    };

    const updateState = async updater => {
        const draft = clone(await getState());
        return setState(typeof updater === 'function' ? updater(draft) || draft : draft);
    };

    const setAppSettings = patch => updateState(state => {
        for (const key of Object.keys(state.app)) {
            if (Object.hasOwn(patch || {}, key)) {
                state.app[key] = patch[key];
            }
        }
        return state;
    });

    const withUnlockedState = (state, action) => {
        if (!state.app.lockSettings) {
            action(state);
        }
        return state;
    };

    const setProviderEnabled = (providerId, enabled) => updateState(state => withUnlockedState(state, current => {
        ensureProviderState(current, providerId).enabled = Boolean(enabled);
    }));

    const setProviderApiKey = (providerId, apiKey) => updateState(state => withUnlockedState(state, current => {
        const normalizedApiKey = String(apiKey ?? '');
        const sharedMembers = getSharedApiKeyGroupMembers(providerId);

        if (sharedMembers.length > 0) {
            for (const memberId of sharedMembers) {
                ensureProviderState(current, memberId).apiKey = normalizedApiKey;
            }
            return;
        }

        ensureProviderState(current, providerId).apiKey = normalizedApiKey;
    }));

    const resetDefaultProviders = () => updateState(state => {
        if (state.app.disableResetButtons) {
            return state;
        }

        for (const definition of providerCatalog.getAllDefinitions()) {
            const providerState = ensureProviderState(state, definition.id, definition.enabledByDefault, '');

            providerState.enabled = definition.enabledByDefault;

            if (definition.kind !== 'direct_static') {
                providerState.apiKey = providerState.apiKey || '';
            }
        }
        return state;
    });

    const resetAll = async () => {
        const current = await getState();

        if (current.app.disableResetButtons) {
            return clone(current);
        }
        return setState(defaultState());
    };

    const countEnabledProviders = state => providerCatalog.getAllDefinitions().reduce(
        (count, definition) => count + (state?.providers?.[definition.id]?.enabled ? 1 : 0), 0
    );

    const countTotalProviders = () => providerCatalog.getAllDefinitions().length;

    const invalidateCache = () => {
        cachedState = null;
        loadingPromise = null;
    };

    browserAPI.api?.storage?.onChanged?.addListener((changes, area) => {
        if (area === 'local' && changes?.[stateKey]) {
            invalidateCache();
        }
    });

    // Public API
    return Object.freeze({
        stateKey,
        getState,
        setState,
        updateState,
        setAppSettings,
        setProviderEnabled,
        setProviderApiKey,
        resetDefaultProviders,
        resetAll,
        countEnabledProviders,
        countTotalProviders,
        invalidateCache,
        normalizeState,
        buildDefaultState: defaultState,
    });
})();
