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

const createPolicy = (managed = {}, {local = {}, withCache = true} = {}) => {
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
    if (withCache) {
        context.OspreyCacheService = {
            clearProviderCache: async id => {
                cacheClears.push(id);
            },
        };
    }
    load(context, 'state/provider-state-store.js');
    load(context, 'state/policy-service.js');
    const changeManaged = next => {
        for (const key of Object.keys(managed)) delete managed[key];
        Object.assign(managed, next);
        for (const listener of listeners) listener({}, 'managed');
    };
    return {context, local, managed, changeManaged, cacheClears, policy: context.OspreyPolicyService};
};


const sign = async (keys, document) => {
    const payload = JSON.stringify(document);
    const signature = Buffer.from(await webcrypto.subtle.sign(
        {name: 'ECDSA', hash: 'SHA-256'}, keys.privateKey, new TextEncoder().encode(payload),
    )).toString('base64');
    return {payload, signature};
};

const signedFixture = async () => {
    const keys = await webcrypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify']);
    const managed = {
        ManagedConfigUrl: 'https://config.example/policy',
        ManagedConfigPublicKey: JSON.stringify(await webcrypto.subtle.exportKey('jwk', keys.publicKey)),
    };
    const fixture = createPolicy(managed);
    let served = null;
    fixture.context.fetch = async () => ({
        ok: true, url: managed.ManagedConfigUrl, headers: {get: () => null},
        body: null, text: async () => JSON.stringify(served),
    });
    return {keys, fixture, serve: envelope => {
        served = envelope;
    }};
};

test('extension pages without a cache service build runtimes even when categories differ', async () => {
    const fixture = createPolicy({
        LockProviderSettings: true,
        ManagedProviderSettings: {'default-on': {blockCategories: {malicious: false}}},
    }, {withCache: false});
    const state = fixture.context.OspreyProviderStateStore.getDefaultState();
    const custom = {
        ...state, providers: {
            ...state.providers,
            'default-on': {...state.providers['default-on'], blockCategories: {malicious: true}},
        },
    };
    const result = await fixture.policy.applyToState(custom);
    assert.equal(result.effectiveState.providers['default-on'].blockCategories.malicious, false);
    assert.equal(fixture.local.osprey_effective_categories, undefined);
});

test('category baseline survives a worker restart, so a restart never clears provider caches', async () => {
    const managed = {ManagedProviderSettings: {'default-on': {blockCategories: {malicious: false}}}};
    const first = createPolicy({...managed});
    const state = first.context.OspreyProviderStateStore.getDefaultState();
    await first.policy.applyToState(state);
    assert.ok(first.local.osprey_effective_categories);

    const restarted = createPolicy({...managed}, {local: first.local});
    await restarted.policy.applyToState(state);
    assert.deepEqual(restarted.cacheClears, []);

    restarted.changeManaged({ManagedProviderSettings: {'default-on': {blockCategories: {malicious: true}}}});
    await restarted.policy.applyToState(state);
    assert.deepEqual(restarted.cacheClears, ['default-on']);
});

test('provider lock keeps locally entered API keys while discarding other user settings', async () => {
    const fixture = createPolicy({LockProviderSettings: true});
    const state = fixture.context.OspreyProviderStateStore.getDefaultState();
    const custom = {
        ...state, providers: {
            ...state.providers,
            'default-on': {...state.providers['default-on'], enabled: false, apiKey: 'user-key'},
        },
    };
    const result = await fixture.policy.applyToState(custom);
    assert.equal(result.effectiveState.providers['default-on'].enabled, true);
    assert.equal(result.effectiveState.providers['default-on'].apiKey, 'user-key');
});

test('remote config must name its own URL as audience', async () => {
    const {keys, fixture, serve} = await signedFixture();
    serve(await sign(keys, {audience: 'https://config.example/other-client', sequence: 1, policies: {}}));
    assert.equal((await fixture.policy.refreshRemoteConfig()).reason, 'fetch-failed');
    serve(await sign(keys, {sequence: 1, policies: {}}));
    assert.equal((await fixture.policy.refreshRemoteConfig()).reason, 'fetch-failed');
    serve(await sign(keys, {audience: 'https://config.example/policy', policies: {}}));
    assert.equal((await fixture.policy.refreshRemoteConfig()).reason, 'fetch-failed');
    assert.equal(fixture.local.osprey_remote_config, undefined);
});

test('remote config rejects a lower sequence but accepts the same or a higher one', async () => {
    const {keys, fixture, serve} = await signedFixture();
    const audience = 'https://config.example/policy';
    serve(await sign(keys, {audience, sequence: 5, policies: {LockUserAllowlist: true}}));
    assert.equal((await fixture.policy.refreshRemoteConfig()).ok, true);

    serve(await sign(keys, {audience, sequence: 4, policies: {LockUserAllowlist: false}}));
    assert.equal((await fixture.policy.refreshRemoteConfig()).reason, 'rollback');
    assert.equal((await fixture.policy.getActionRestrictions()).lockUserAllowlist, true);

    serve(await sign(keys, {audience, sequence: 5, policies: {LockUserAllowlist: true}}));
    assert.equal((await fixture.policy.refreshRemoteConfig()).ok, true);
    serve(await sign(keys, {audience, sequence: 6, policies: {LockUserAllowlist: false}}));
    assert.equal((await fixture.policy.refreshRemoteConfig()).ok, true);
    assert.equal((await fixture.policy.getActionRestrictions()).lockUserAllowlist, false);
});

test('a failed state read scans with defaults but never lets a write overwrite stored settings', async () => {
    const fixture = createPolicy();
    const store = fixture.context.OspreyProviderStateStore;
    const browser = fixture.context.OspreyBrowserAPI;
    const realGet = browser.storageGet;
    browser.storageGet = async (area, key) => {
        if (area === 'local' && key === 'osprey_state') {
            throw new Error('storage unavailable');
        }
        return realGet(area, key);
    };
    const state = await store.getState();
    assert.equal(state.providers['default-on'].enabled, true);
    await assert.rejects(store.setProviderEnabled('default-on', false), /storage unavailable/);
    assert.equal(fixture.local.osprey_state, undefined);

    browser.storageGet = realGet;
    fixture.local.osprey_state = {app: {}, providers: {'default-on': {enabled: false}}};
    assert.equal((await store.getState()).providers['default-on'].enabled, false);
});

test('reported and logged URLs drop query strings and credentials', async () => {
    const context = vm.createContext({
        URL, console: {warn() {}, error() {}}, setTimeout: () => 0, clearTimeout() {},
        crypto: webcrypto,
        OspreyBrowserAPI: {api: {runtime: {getManifest: () => ({version: '9.9.9'})}}},
        OspreyPolicyService: {getEndpointIdentity: async () => ({deviceTag: '', siteId: ''})},
    });
    load(context, 'platform/url-service.js');
    load(context, 'state/event-log-service.js');
    const log = context.OspreyEventLogService;
    await log.recordDetection({
        url: 'https://user:pw@phish.example/login?session=secret&email=a%40b.c#frag',
        providerId: 'provider', verdict: 'phishing',
    });
    await log.recordDetection({url: 'https://drive.google.com/uc?export=download&id=abc&token=x'});
    const events = await log.getEvents();
    assert.equal(events[0].url, 'https://phish.example/login');
    assert.equal(events[1].url, 'https://drive.google.com/uc?export=download&id=abc');
});
