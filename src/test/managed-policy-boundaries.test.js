/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
'use strict';

const assert = require('node:assert/strict');
const {webcrypto} = require('node:crypto');
const {readFileSync} = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const main = path.join(__dirname, '..', 'main');
const load = (context, file) => vm.runInContext(
    readFileSync(path.join(main, file), 'utf8'), context, {filename: file},
);

const createPolicy = (managed = {}) => {
    const local = {};
    const listeners = [];
    const browser = {
        api: {
            storage: {
                managed: {
                    get() {
                    }
                }, onChanged: {addListener: fn => listeners.push(fn)}
            }
        },
        storageGet: async (area, key) => {
            const source = area === 'managed' ? managed : local;
            if (key === null) return {...source};
            return {[key]: source[key]};
        },
        storageSet: async (_, entries) => Object.assign(local, entries),
        storageRemove: async (_, key) => {
            delete local[key];
        },
    };
    const definitions = [
        {id: 'default-on', enabledByDefault: true, bypassBlockingThreshold: false},
        {id: 'default-off', enabledByDefault: false, bypassBlockingThreshold: false},
    ];
    const catalog = {
        getAllDefinitions: () => definitions,
        getBuiltins: () => definitions,
        getDefinition: id => definitions.find(def => def.id === id),
        setCustomDefinitions() {
        },
    };
    const context = vm.createContext({
        URL, TextEncoder, crypto: webcrypto, atob, AbortController,
        setTimeout, clearTimeout, console: {
            warn() {
            }, error() {
            }
        },
        OspreyBrowserAPI: browser,
        OspreyProviderCatalog: catalog,
        OspreyCatalogValidator: {validateCustom: () => ({valid: [], errors: []})},
    });
    const cacheClears = [];
    context.OspreyCacheService = {
        clearProviderCache: async id => {
            cacheClears.push(id);
        },
    };
    load(context, 'state/provider-state-store.js');
    load(context, 'state/policy-service.js');
    const changeManaged = next => {
        for (const key of Object.keys(managed)) delete managed[key];
        Object.assign(managed, next);
        for (const listener of listeners) listener({}, 'managed');
    };
    return {context, local, managed, changeManaged, cacheClears, policy: context.OspreyPolicyService};
};

test('absent protected-domain policy leaves user state unmanaged, but an empty list is managed', async () => {
    const fixture = createPolicy();
    const state = fixture.context.OspreyProviderStateStore.getDefaultState();
    const custom = {...state, app: {...state.app, protectedDomains: ['example.com']}};
    const unconfigured = await fixture.policy.applyToState(custom);
    assert.deepEqual(unconfigured.effectiveState.app.protectedDomains, ['example.com']);
    assert.equal(unconfigured.appManagedKeys.has('protectedDomains'), false);

    fixture.changeManaged({ManagedProtectedDomains: []});
    const configured = await fixture.policy.applyToState(custom);
    assert.deepEqual(Array.from(configured.effectiveState.app.protectedDomains), []);
    assert.equal(configured.appManagedKeys.has('protectedDomains'), true);
});

test('provider verdict cache clears on effective category transitions, not repeated rebuilds', async () => {
    const fixture = createPolicy({
        ManagedProviderSettings: {
            'default-on': {
                blockCategories: {malicious: false},
            }
        }
    });
    const state = fixture.context.OspreyProviderStateStore.getDefaultState();
    const custom = {
        ...state, providers: {
            ...state.providers,
            'default-on': {...state.providers['default-on'], blockCategories: {malicious: true}}
        }
    };

    // The first build only records a baseline; repeated rebuilds with the same effective
    // categories never clear.
    await fixture.policy.applyToState(custom);
    await fixture.policy.applyToState(custom);
    assert.deepEqual(fixture.cacheClears, []);

    fixture.changeManaged({ManagedProviderSettings: {'default-on': {blockCategories: {malicious: true}}}});
    await fixture.policy.applyToState(custom);
    assert.deepEqual(fixture.cacheClears, ['default-on']);

    fixture.changeManaged({ManagedProviderSettings: {'default-on': {blockCategories: {malicious: false}}}});
    await fixture.policy.applyToState(custom);
    fixture.changeManaged({});
    await fixture.policy.applyToState(custom);
    assert.equal(fixture.cacheClears.length, 3);
});

test('provider lock uses catalog defaults and managed overrides, never stored switches', async () => {
    const {policy, context} = createPolicy({
        LockProviderSettings: true,
        ManagedProviderSettings: {'default-off': {enabled: true}},
    });
    const state = context.OspreyProviderStateStore.getDefaultState();
    const poisoned = {
        ...state,
        app: {...state.app, disableAllProviders: true},
        providers: {
            'default-on': {...state.providers['default-on'], enabled: false},
            'default-off': {...state.providers['default-off'], enabled: false},
        },
    };
    const result = await policy.applyToState(poisoned);
    assert.equal(result.effectiveState.app.disableAllProviders, false);
    assert.equal(result.effectiveState.providers['default-on'].enabled, true);
    assert.equal(result.effectiveState.providers['default-off'].enabled, true);
    assert.equal((await policy.applyToAppState(poisoned)).effectiveApp.disableAllProviders, false);
});

test('signed remote config is reverified on load and removed on offboarding', async () => {
    const keys = await webcrypto.subtle.generateKey(
        {name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify'],
    );
    const publicKey = JSON.stringify(await webcrypto.subtle.exportKey('jwk', keys.publicKey));
    const managed = {ManagedConfigUrl: 'https://config.example/policy', ManagedConfigPublicKey: publicKey};
    const fixture = createPolicy(managed);
    const payload = JSON.stringify({audience: 'https://config.example/policy', sequence: 1, policies: {ProxyBaseUrl: 'https://proxy.example', LockUserAllowlist: true}});
    const signature = Buffer.from(await webcrypto.subtle.sign(
        {name: 'ECDSA', hash: 'SHA-256'}, keys.privateKey, new TextEncoder().encode(payload),
    )).toString('base64');
    const envelope = {payload, signature};
    fixture.context.fetch = async () => ({
        ok: true, url: managed.ManagedConfigUrl, headers: {get: () => null},
        body: null, text: async () => JSON.stringify(envelope),
    });

    assert.equal((await fixture.policy.refreshRemoteConfig()).ok, true);
    assert.equal((await fixture.policy.getProxyOrigin()), 'https://proxy.example');
    assert.equal((await fixture.policy.getActionRestrictions()).lockUserAllowlist, true);

    fixture.local.osprey_remote_config = {...envelope, payload: JSON.stringify({audience: 'https://config.example/policy', sequence: 1, policies: {LockUserAllowlist: false}})};
    fixture.changeManaged({...managed});
    assert.equal((await fixture.policy.getActionRestrictions()).lockUserAllowlist, false);
    assert.equal((await fixture.policy.getProxyOrigin()), 'https://api.osprey.ac');

    fixture.local.osprey_remote_config = envelope;
    fixture.changeManaged({});
    assert.equal((await fixture.policy.getProxyOrigin()), 'https://api.osprey.ac');
    assert.equal((await fixture.policy.refreshRemoteConfig()).reason, 'no-url');
    assert.equal(fixture.local.osprey_remote_config, undefined);
});

test('offboarding during a stored-config read cannot reinstate remote policy', async () => {
    const keys = await webcrypto.subtle.generateKey(
        {name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify'],
    );
    const fixture = createPolicy({
        ManagedConfigUrl: 'https://config.example/policy',
        ManagedConfigPublicKey: JSON.stringify(await webcrypto.subtle.exportKey('jwk', keys.publicKey)),
    });
    const payload = JSON.stringify({audience: 'https://config.example/policy', sequence: 1, policies: {LockUserAllowlist: true}});
    fixture.local.osprey_remote_config = {
        payload,
        signature: Buffer.from(await webcrypto.subtle.sign(
            {name: 'ECDSA', hash: 'SHA-256'}, keys.privateKey, new TextEncoder().encode(payload),
        )).toString('base64'),
    };
    const originalGet = fixture.context.OspreyBrowserAPI.storageGet;
    let releaseRead;
    let startedRead;
    const started = new Promise(resolve => {
        startedRead = resolve;
    });
    fixture.context.OspreyBrowserAPI.storageGet = (area, key) => {
        if (area === 'local' && key === 'osprey_remote_config') {
            startedRead();
            return new Promise(resolve => {
                releaseRead = () => originalGet(area, key).then(resolve);
            });
        }
        return originalGet(area, key);
    };

    const pending = fixture.policy.getActionRestrictions();
    await started;
    fixture.changeManaged({});
    fixture.context.OspreyBrowserAPI.storageGet = originalGet;
    releaseRead();
    assert.equal((await pending).lockUserAllowlist, false);
});

test('remote config refuses unsigned documents, HTTP hosts and HTTP redirects', async () => {
    const fixture = createPolicy({
        ManagedConfigUrl: 'http://config.local/policy',
        ManagedConfigPublicKey: '{}',
    });
    let fetches = 0;
    fixture.context.fetch = async () => {
        fetches++;
        throw new Error('unexpected fetch');
    };
    assert.equal((await fixture.policy.refreshRemoteConfig()).reason, 'no-url');
    assert.equal(fetches, 0);

    fixture.changeManaged({ManagedConfigUrl: 'https://config.example/policy', ManagedConfigPublicKey: '{}'});
    fixture.context.fetch = async () => {
        fetches++;
        return {
            ok: true, url: 'http://192.168.1.1/config', headers: {get: () => null},
            body: null, text: async () => '{}'
        };
    };
    assert.equal((await fixture.policy.refreshRemoteConfig()).reason, 'fetch-failed');
    assert.equal(fixture.local.osprey_remote_config, undefined);
    assert.equal(fixture.policy.isAllowedTransport(new URL('http://router.local/')), false);
});

test('remote config refuses unsigned and tampered HTTPS responses', async () => {
    const keys = await webcrypto.subtle.generateKey(
        {name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify'],
    );
    const fixture = createPolicy({
        ManagedConfigUrl: 'https://config.example/policy',
        ManagedConfigPublicKey: JSON.stringify(await webcrypto.subtle.exportKey('jwk', keys.publicKey)),
    });
    let envelope = {policies: {LockUserAllowlist: true}};
    fixture.context.fetch = async () => ({
        ok: true, url: 'https://config.example/policy', headers: {get: () => null},
        body: null, text: async () => JSON.stringify(envelope),
    });
    assert.equal((await fixture.policy.refreshRemoteConfig()).reason, 'fetch-failed');

    const payload = JSON.stringify({audience: 'https://config.example/policy', sequence: 1, policies: {LockUserAllowlist: false}});
    envelope = {
        payload: JSON.stringify({audience: 'https://config.example/policy', sequence: 1, policies: {LockUserAllowlist: true}}),
        signature: Buffer.from(await webcrypto.subtle.sign(
            {name: 'ECDSA', hash: 'SHA-256'}, keys.privateKey, new TextEncoder().encode(payload),
        )).toString('base64'),
    };
    assert.equal((await fixture.policy.refreshRemoteConfig()).reason, 'fetch-failed');
    assert.equal((await fixture.policy.getActionRestrictions()).lockUserAllowlist, false);
    assert.equal(fixture.local.osprey_remote_config, undefined);
});

test('cache mutation methods reject locked user allowlist before touching storage', async () => {
    const context = vm.createContext({
        console: {
            warn() {
            }
        },
        setInterval: () => {
        },
        OspreyPolicyService: {
            getActionRestrictions: async () => ({
                lockUserAllowlist: true, disableUserAllowlist: false,
            })
        },
        OspreyBrowserAPI: {},
        OspreyUrlService: {},
        OspreyProtectionResult: {resultTypes: {}},
    });
    load(context, 'state/cache-service.js');
    const cache = context.OspreyCacheService;

    for (const result of await Promise.all([
        cache.allowPattern('*.bad.example'),
        cache.addGlobalHost('bad.example'),
        cache.removeGlobalPattern('*.bad.example'),
        cache.removeProviderAllowed('provider', 'bad.example'),
        cache.clearAll(),
        cache.markAllowed('provider', 'bad.example', 60, true),
    ])) {
        assert.equal(result.ok, false);
        assert.equal(result.reason, 'managed');
    }
});

test('locked allowlist and hidden proceed reject direct background service calls', async () => {
    const restrictions = {
        lockUserAllowlist: true, disableUserAllowlist: false, hideWarningProceedButton: true,
    };
    const context = vm.createContext({
        URL, console: {
            warn() {
            }
        },
        OspreyPolicyService: {getActionRestrictions: async () => restrictions},
        OspreyBrowserAPI: {safeRuntimeURL: path => `chrome-extension://test/${path}`},
        OspreyBadgeService: {},
        OspreyCacheService: {getManagedListDecision: async () => ({allowed: false, blocked: false})},
        OspreyEventLogService: {},
        OspreyMessageBus: {Messages: {}},
        OspreyProviderEngine: {},
        OspreyProviderRuntimeFactory: {},
        OspreyResultAggregationService: {
            ensureHydrated: async () => {
            },
            getBlockedContext: () => ({
                url: 'https://bad.example/', origins: ['provider'],
            }),
        },
    });
    load(context, 'platform/url-service.js');
    load(context, 'background/blocking-service.js');
    const blocking = context.OspreyBlockingService;
    assert.equal((await blocking.allowWebsite(1, 'https://bad.example/')).ok, false);
    assert.equal((await blocking.continueToWebsite(1, 'https://bad.example/', 'provider')).ok, false);
    restrictions.hideWarningProceedButton = false;
    restrictions.disableUserAllowlist = true;
    assert.equal((await blocking.allowWebsite(1, 'https://bad.example/')).ok, false);
});
