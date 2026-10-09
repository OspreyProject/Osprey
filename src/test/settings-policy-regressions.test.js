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

const createFixture = (managed = {}, customDefinitions = []) => {
    const local = {};
    const listeners = [];
    const definitions = [{id: 'phishunt-io', enabledByDefault: true, bypassBlockingThreshold: false}];
    const catalog = {
        getAllDefinitions: () => definitions.concat(customDefinitions),
        getBuiltins: () => definitions,
        getDefinition: id => definitions.concat(customDefinitions).find(def => def.id === id) || null,
        setCustomDefinitions: next => {
            customDefinitions = next;
        },
    };
    const context = vm.createContext({
        URL, TextEncoder, crypto: webcrypto, atob, AbortController, setTimeout, clearTimeout,
        console: {
            warn() {
            }, error() {
            }
        },
        OspreyBrowserAPI: {
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
                return key === null ? {...source} : {[key]: source[key]};
            },
            storageSet: async (_, entries) => Object.assign(local, entries),
            storageRemove: async (_, key) => {
                delete local[key];
            },
        },
        OspreyProviderCatalog: catalog,
        OspreyCatalogValidator: {validateCustom: next => ({valid: next, errors: []})},
        OspreyCacheService: {
            clearProviderCache: async () => {
            }
        },
    });
    load(context, 'state/provider-state-store.js');
    load(context, 'state/policy-service.js');
    return {
        context, local, managed, catalog, store: context.OspreyProviderStateStore,
        policy: context.OspreyPolicyService
    };
};

test('managed schema declares domain intel and notification protection with supported types', () => {
    const properties = JSON.parse(readFileSync(path.join(main, 'policies.json'), 'utf8')).properties;
    assert.deepEqual(properties.ManagedDomainIntelMode.enum, ['', 'warn', 'block']);
    assert.deepEqual(properties.ManagedNotificationProtection.enum, ['', 'on']);
    assert.equal(properties.ManagedProtectedDomains.type, 'array');
    assert.equal(properties.ManagedProtectedDomains.items.type, 'string');
});

test('managed domain intel and notification policies reach effective app state', async () => {
    const fixture = createFixture({
        ManagedDomainIntelMode: 'block',
        ManagedNotificationProtection: 'on',
        ManagedProtectedDomains: ['example.com'],
    });
    const state = await fixture.store.getState();
    const result = await fixture.policy.applyToAppState(state);
    assert.equal(result.effectiveApp.domainIntelMode, 'block');
    assert.equal(result.effectiveApp.notificationProtection, 'on');
    assert.deepEqual(Array.from(result.effectiveApp.protectedDomains), ['example.com']);
});

test('out-of-range remote cache policy does not override cache lifetime', async () => {
    const keys = await webcrypto.subtle.generateKey(
        {name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify'],
    );
    const managed = {
        ManagedConfigUrl: 'https://config.example/policy',
        ManagedConfigPublicKey: JSON.stringify(await webcrypto.subtle.exportKey('jwk', keys.publicKey)),
    };
    for (const value of [0, -1, 2592001, 1e99, 60.5, 60, 2592000]) {
        const fixture = createFixture(managed);
        const payload = JSON.stringify({audience: 'https://config.example/policy', sequence: 1, policies: {CacheExpirationSeconds: value}});
        fixture.local.osprey_remote_config = {
            payload,
            signature: Buffer.from(await webcrypto.subtle.sign(
                {name: 'ECDSA', hash: 'SHA-256'}, keys.privateKey, new TextEncoder().encode(payload),
            )).toString('base64'),
        };
        const result = await fixture.policy.applyToAppState(await fixture.store.getState());
        assert.equal(result.effectiveApp.cacheExpirationSeconds,
            Number.isInteger(value) && value >= 60 && value <= 2592000 ? value : 604800);
    }
});

test('reset and import respect provider and reset locks without changing stored state', async () => {
    const fixture = createFixture();
    const original = await fixture.store.getState();
    const imported = {app: {...original.app}, providers: {'phishunt-io': {enabled: false}}};
    for (const lock of ['lockProviderSettings', 'disableSettingsReset']) {
        fixture.local.osprey_state = {...original, app: {...original.app, [lock]: true}};
        const locked = await fixture.store.getState({fresh: true});
        await assert.rejects(fixture.store.resetDefaultProviders(), /locked/);
        await assert.rejects(fixture.store.resetAll(), /locked/);
        await assert.rejects(fixture.store.importState(imported), /locked/);
        assert.equal(fixture.local.osprey_state.app[lock], true);
        assert.equal(locked.providers['phishunt-io'].enabled, true);
    }
});

test('import discards legacy lock flags and keeps keys omitted by a new export', async () => {
    const fixture = createFixture();
    await fixture.store.setProviderApiKey('phishunt-io', 'existing-key');
    const original = await fixture.store.getState();
    await fixture.store.importState({
        app: {
            ...original.app, lockProviderSettings: true, disableSettingsReset: true,
            lockUserAllowlist: true
        },
        providers: {'phishunt-io': {enabled: false}},
    });
    const state = await fixture.store.getState({fresh: true});
    assert.equal(state.app.lockProviderSettings, false);
    assert.equal(state.app.disableSettingsReset, false);
    assert.equal(state.app.lockUserAllowlist, false);
    assert.equal(state.providers['phishunt-io'].enabled, false);
    assert.equal(state.providers['phishunt-io'].apiKey, 'existing-key');
});

test('settings export omits lock flags and plaintext provider API keys', async () => {
    const fixture = createFixture();
    await fixture.store.setProviderApiKey('phishunt-io', 'secret-key');
    let exportedBlob;
    const elements = [];
    const context = vm.createContext({
        Blob, Date, JSON, console, LangUtil: {TOAST_SETTINGS_EXPORTED: 'exported'},
        OspreyProviderStateStore: fixture.store,
        OspreyToast: {
            show() {
            }
        },
        OspreyFormHelpers: {
            createElement: tag => {
                const element = {
                    tag, style: {}, handlers: {},
                    addEventListener(event, fn) {
                        this.handlers[event] = fn;
                    },
                    append() {
                    }, remove() {
                    }, click() {
                    },
                };
                elements.push(element);
                return element;
            }
        },
        URL: {
            createObjectURL: blob => {
                exportedBlob = blob;
                return 'blob:test';
            },
            revokeObjectURL() {
            }
        },
        document: {
            body: {
                appendChild() {
                }
            }
        },
        setTimeout() {
        },
    });
    load(context, 'pages/settings/ui/import-export-page.js');
    context.OspreyImportExportPage.buildControls();
    await elements.find(element => element.tag === 'button').handlers.click();
    const exported = JSON.parse(await exportedBlob.text());
    for (const flag of ['lockProviderSettings', 'disableSettingsReset', 'lockUserAllowlist']) {
        assert.equal(Object.hasOwn(exported.state.app, flag), false);
    }
    assert.equal(Object.hasOwn(exported.state.providers['phishunt-io'], 'apiKey'), false);
    assert.equal((await exportedBlob.text()).includes('secret-key'), false);
});

test('emergency migrations change the named provider setting even under a provider lock', async () => {
    const fixture = createFixture({LockProviderSettings: true});
    fixture.local.osprey_state = {
        app: {}, providers: {
            'phishunt-io': {enabled: true, bypassBlockingThreshold: true},
        }
    };
    await fixture.store.applyEmergencySetting('phishunt-io', 'bypassBlockingThreshold', false);
    assert.equal(fixture.local.osprey_state.providers['phishunt-io'].bypassBlockingThreshold, false);
    await fixture.store.applyEmergencySetting('phishunt-io', 'enabled', false);
    assert.equal(fixture.local.osprey_state.providers['phishunt-io'].enabled, false);
    await assert.rejects(fixture.store.applyEmergencySetting('phishunt-io', 'apiKey', 'x'), /Unsupported/);
    await assert.rejects(fixture.store.applyEmergencySetting('phishunt-io', 'enabled', 'yes'), /Unsupported/);
});

test('custom providers are registered before state normalization and survive settings writes', async () => {
    const keys = await webcrypto.subtle.generateKey(
        {name: 'ECDSA', namedCurve: 'P-256'}, true, ['sign', 'verify'],
    );
    const fixture = createFixture({
        ManagedConfigUrl: 'https://config.example/policy',
        ManagedConfigPublicKey: JSON.stringify(await webcrypto.subtle.exportKey('jwk', keys.publicKey)),
    });
    const payload = JSON.stringify({
        audience: 'https://config.example/policy',
        sequence: 1,
        customProviders: [{
            id: 'custom-intel', enabledByDefault: true,
            displayName: 'Custom Intel', report: {type: 'url', url: 'https://example.com/report'}
        }]
    });
    fixture.local.osprey_remote_config = {
        payload,
        signature: Buffer.from(await webcrypto.subtle.sign(
            {name: 'ECDSA', hash: 'SHA-256'}, keys.privateKey, new TextEncoder().encode(payload),
        )).toString('base64'),
    };
    fixture.local.osprey_state = {
        app: {}, providers: {
            'custom-intel': {enabled: false, apiKey: 'saved'},
        }
    };
    const initial = await fixture.store.getState();
    assert.equal(fixture.catalog.getDefinition('custom-intel').displayName, 'Custom Intel');
    assert.equal(initial.providers['custom-intel'].enabled, false);
    await fixture.store.setProviderEnabled('phishunt-io', false);
    assert.equal(fixture.local.osprey_state.providers['custom-intel'].apiKey, 'saved');
    assert.equal(fixture.local.osprey_state.providers['custom-intel'].enabled, false);
});

test('a failed managed policy read is retried instead of cached as empty policy', async () => {
    const {context, policy} = createFixture({DisableUserAllowlist: true});
    const read = context.OspreyBrowserAPI.storageGet;
    let failManaged = true;
    context.OspreyBrowserAPI.storageGet = async (area, key) => {
        if (area === 'managed' && failManaged) {
            throw new Error('managed storage unavailable');
        }
        return read(area, key);
    };
    assert.equal((await policy.getActionRestrictions()).disableUserAllowlist, false);
    failManaged = false;
    assert.equal((await policy.getActionRestrictions()).disableUserAllowlist, true);
});
