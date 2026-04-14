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
    const customProviderNormalizer = globalThis.OspreyCustomProviderNormalizer;
    const providerCatalog = globalThis.OspreyProviderCatalog;

    const stateKey = 'osprey_state';
    const legacyKey = 'Settings';
    const legacyCustomProvidersKey = 'customProviders';

    let cachedState = null;
    let loadingPromise = null;

    const asObject = value => value && typeof value === 'object' ? value : {};
    const asArray = value => Array.isArray(value) ? value : [];
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

    const getDefinitionStates = stateOrCustomProviders => {
        const candidate = stateOrCustomProviders && typeof stateOrCustomProviders === 'object'
            ? stateOrCustomProviders
            : {};

        return providerCatalog.getAllDefinitions(
            Object.hasOwn(candidate, 'customProviders') || Object.hasOwn(candidate, 'providers') || Object.hasOwn(candidate, 'app')
                ? candidate
                : {customProviders: candidate}
        );
    };

    const forEachCustomProvider = (customProviders, callback) => {
        const items = Array.isArray(customProviders) ? customProviders : Object.values(asObject(customProviders));

        for (const raw of items) {
            const definition = customProviderNormalizer.normalize(raw);

            if (definition) {
                callback(definition, raw);
            }
        }
    };

    const buildDefaultProviders = () => {
        const providers = Object.create(null);

        for (const {id, enabledByDefault} of getDefinitionStates({})) {
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
            disableCustomProviders: false,
            disableThirdPartyIntegrations: false,
            cacheExpirationSeconds: 604800,
        },

        providers: buildDefaultProviders(),
        customProviders: {},
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
        'disableCustomProviders',
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

    const addCustomProviders = (base, customProviders, providerStates, apiKeySelector) => {
        forEachCustomProvider(customProviders, (definition, raw) => {
            base.customProviders[definition.id] = definition;
            const customState = providerStates?.[definition.id] || {};

            applyProviderState(base, {
                enabled: customState.enabled,
                apiKey: apiKeySelector(raw, customState),
            }, definition.id, false);
        });
    };

    const normalizeState = input => {
        const base = defaultState();
        const state = asObject(input);

        applyAppSettings(base.app, state.app);

        for (const {id, enabledByDefault} of getDefinitionStates({})) {
            applyProviderState(base, state.providers?.[id] || {}, id, enabledByDefault);
        }

        addCustomProviders(base, state.customProviders, state.providers, (raw, customState) => customState.apiKey || raw.apiKey);
        return base;
    };

    // -------------------------------------------------------------------------
    // Legacy migration (v1 → v2)
    // -------------------------------------------------------------------------

    const legacyFieldKeyFor = (definition, suffix) => `${definition.aliases?.[0] || definition.id}${suffix}`;

    const migrateLegacyState = (legacySettings, legacyCustomProviders) => {
        const migrated = defaultState();
        const source = asObject(legacySettings);

        applyAppSettings(migrated.app, source);

        for (const definition of getDefinitionStates({})) {
            applyProviderState(migrated, {
                enabled: source[legacyFieldKeyFor(definition, 'Enabled')],
                apiKey: source[legacyFieldKeyFor(definition, 'ApiKey')],
            }, definition.id, definition.enabledByDefault);
        }

        forEachCustomProvider(asArray(legacyCustomProviders), (definition, raw) => {
            migrated.customProviders[definition.id] = definition;

            applyProviderState(migrated, {
                enabled: source[`${raw.id}Enabled`],
                apiKey: raw.apiKey,
            }, definition.id, false);
        });
        return migrated;
    };

    // -------------------------------------------------------------------------
    // Storage I/O
    // -------------------------------------------------------------------------

    const readStoredState = async () => {
        const stored = await browserAPI.storageGet('local', stateKey).catch(() => ({}));
        const next = stored?.[stateKey];

        if (next) {
            return normalizeState(next);
        }

        const legacy = await browserAPI.storageGet('local', [legacyKey, legacyCustomProvidersKey]).catch(() => ({}));
        const migrated = migrateLegacyState(legacy?.[legacyKey], legacy?.[legacyCustomProvidersKey]);

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

    const setCustomProviders = (customProviders, additionalProviderStates = {}) => updateState(state => {
        if (state.app.lockSettings || state.app.disableCustomProviders) {
            return state;
        }

        const next = Object.create(null);

        forEachCustomProvider(asArray(customProviders), (definition, raw) => {
            customProviderNormalizer.validate(definition);
            next[definition.id] = definition;

            const providerState = ensureProviderState(state, definition.id);

            if (typeof raw?.apiKey === 'string') {
                providerState.apiKey = raw.apiKey;
            }
        });

        for (const existingId of Object.keys(state.customProviders || {})) {
            if (!Object.hasOwn(next, existingId)) {
                delete state.providers[existingId];
            }
        }

        for (const [id, providerState] of Object.entries(additionalProviderStates)) {
            if (state.providers[id] && typeof providerState?.enabled === 'boolean') {
                state.providers[id].enabled = providerState.enabled;
            }
        }

        state.customProviders = next;
        return state;
    });

    const resetDefaultProviders = () => updateState(state => {
        if (state.app.disableResetButtons) {
            return state;
        }

        for (const definition of getDefinitionStates({})) {
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

    const countEnabledProviders = state => getDefinitionStates(state).reduce(
        (count, definition) => count + (state?.providers?.[definition.id]?.enabled ? 1 : 0), 0
    );

    const countTotalProviders = state => getDefinitionStates(state).length;

    const invalidateCache = () => {
        cachedState = null;
        loadingPromise = null;
    };

    browserAPI.api?.storage?.onChanged?.addListener((changes, area) => {
        if (area === 'local' && changes?.[stateKey]) {
            invalidateCache();
        }
    });

    const generateCustomProviderId = () => customProviderNormalizer.generateId();
    const normalizeCustomDefinition = value => customProviderNormalizer.normalize(value);
    const validateCustomDefinition = value => customProviderNormalizer.validate(value);

    // Public API
    return Object.freeze({
        stateKey,
        getState,
        setState,
        updateState,
        setAppSettings,
        setProviderEnabled,
        setProviderApiKey,
        setCustomProviders,
        resetDefaultProviders,
        resetAll,
        countEnabledProviders,
        countTotalProviders,
        invalidateCache,
        normalizeState,
        buildDefaultState: defaultState,
        generateCustomProviderId,
        normalizeCustomDefinition,
        validateCustomDefinition,
    });
})();
