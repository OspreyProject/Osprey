/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
'use strict';

const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const main = path.join(__dirname, '..', 'main');
const load = (context, file) => vm.runInContext(
    readFileSync(path.join(main, file), 'utf8'), context, {filename: file},
);
const deferred = () => {
    let resolve;
    let reject;
    const promise = new Promise((done, fail) => {
        resolve = done;
        reject = fail;
    });
    return {promise, resolve, reject};
};
const tick = () => new Promise(resolve => setImmediate(resolve));

const createEngine = ({shared = false, proxy = false} = {}) => {
    const requests = [];
    const allowed = [];
    const blocked = [];
    const results = new Map();
    let allowlisted = false;
    const context = vm.createContext({
        URL,
        AbortController,
        console: {
            info() {
            }, debug() {
            }, warn() {
            }
        },
        fetch: () => {
            const request = deferred();
            requests.push(request);
            return request.promise;
        },
        OspreyUrlService: {
            parseHttpUrl: url => new URL(url),
            isAcceptableHost: () => true,
            isInternalHostname: () => false,
            lookupValueForTarget: url => url,
        },
        OspreyProtectionResult: {
            resultTypes: {
                ALLOWED: 'allowed', FAILED: 'failed', WAITING: 'waiting',
                KNOWN_SAFE: 'known_safe', MALICIOUS: 'malicious',
            },
            blockingResults: new Set(['malicious']),
            fromProviderString: result => result || 'failed',
            create: value => value,
        },
        OspreyResponseRuleEngine: {evaluateRules: body => body.result},
        OspreyRequestBuilder: {buildRequest: (_, url) => ({url, options: {}, timeoutMs: 1000})},
        OspreyTimedSignal: {
            create: signal => ({
                signal, cleanup() {
                }
            })
        },
        OspreyCacheService: {
            getManagedListDecision: async () => ({blocked: false, allowed: allowlisted}),
            matchesGlobalPattern: async () => false,
            getBlockedEntry: async (_, key) => blocked.find(entry => entry.key === key),
            getAllowedEntry: async (_, key) => allowed.find(entry => entry.key === key),
            markAllowed: async (providerId, key) => {
                allowed.push({providerId, key});
            },
            markBlocked: async (providerId, key, result) => {
                blocked.push({providerId, key, result});
            },
            markProcessing() {
            },
            clearProcessing() {
            },
            clearProcessingByTab() {
            },
            storeOutcomes: async entries => {
                for (const entry of entries) {
                    if (entry.outcome === 'malicious') {
                        blocked.push({key: entry.lookupKey, result: entry.outcome});
                    }
                }
            },
        },
    });
    load(context, 'providers/provider-engine.js');
    const providers = (shared ? ['a', 'b'] : ['a']).map(id => ({
        id, displayName: id, kind: proxy ? 'proxy_builtin' : 'direct',
        state: {enabled: true}, ...(shared ? {sharedRequestGroup: 'group'} : {}),
    }));
    const scan = (tabId, url = 'https://evil.example/') => {
        const observed = [];
        results.set(tabId, observed);
        const promise = context.OspreyProviderEngine.scanUrl({
            tabId, url, providers, expirationSeconds: 604800,
            onResult: result => observed.push(result),
        });
        return promise;
    };
    return {
        context, requests, allowed, blocked, results, scan, setAllowlisted: value => {
            allowlisted = value;
        }
    };
};

test('proxy failures are emitted but not cached as allowed', async () => {
    const engine = createEngine({proxy: true});
    const first = engine.scan(1);
    await tick();
    engine.requests[0].resolve({ok: true, json: async () => ({result: 'failed'})});
    await first;
    assert.deepEqual(engine.results.get(1).map(result => result.result), ['failed']);
    assert.equal(engine.allowed.length, 0);

    const retry = engine.scan(2);
    await tick();
    assert.equal(engine.requests.length, 2);
    engine.requests[1].resolve({ok: true, json: async () => ({result: 'malicious'})});
    await retry;
    assert.deepEqual(engine.results.get(2).map(result => result.result), ['malicious']);
});

test('allowlist matches do not write provider verdicts and removal triggers a scan', async () => {
    const engine = createEngine();
    engine.setAllowlisted(true);
    await engine.scan(1);
    assert.deepEqual(engine.results.get(1).map(result => result.result), ['allowed']);
    assert.equal(engine.allowed.length, 0);
    assert.equal(engine.requests.length, 0);

    engine.setAllowlisted(false);
    const retry = engine.scan(2);
    await tick();
    assert.equal(engine.requests.length, 1);
    engine.requests[0].resolve({ok: true, json: async () => ({result: 'malicious'})});
    await retry;
    assert.deepEqual(engine.results.get(2).map(result => result.result), ['malicious']);
});

for (const shared of [false, true]) {
    test(`${shared ? 'shared' : 'individual'} concurrent scans replay the final block to both tabs`, async () => {
        const engine = createEngine({shared});
        const first = engine.scan(1);
        const second = engine.scan(2);
        await tick();
        assert.equal(engine.requests.length, 1);
        assert.ok(engine.results.get(2).some(result => result.result === 'waiting'));

        engine.requests[0].resolve({ok: true, json: async () => ({result: 'malicious'})});
        await Promise.all([first, second]);
        for (const tabId of [1, 2]) {
            assert.deepEqual(
                engine.results.get(tabId).filter(result => result.result === 'malicious').map(result => result.origin).sort(),
                shared ? ['a', 'b'] : ['a'],
            );
        }
    });
}

for (const shared of [false, true]) {
    test(`${shared ? 'shared' : 'individual'} waiting tabs retry after the original navigation is replaced`, async () => {
        const engine = createEngine({shared});
        const first = engine.scan(1);
        await tick();
        const second = engine.scan(2);
        await tick();
        await engine.context.OspreyProviderEngine.abortTab(1);
        engine.requests[0].reject('navigation-replaced');
        await first;
        await tick();
        assert.equal(engine.requests.length, shared ? 3 : 2);
        for (const request of engine.requests.slice(1)) {
            request.resolve({ok: true, json: async () => ({result: 'malicious'})});
        }
        await second;
        assert.deepEqual(
            engine.results.get(2).filter(result => result.result === 'malicious').map(result => result.origin).sort(),
            shared ? ['a', 'b'] : ['a'],
        );
    });
}

test('legacy allowed verdicts are invalidated and failed shared outcomes do not overwrite cached results', async () => {
    const records = new Map([
        ['osprey_cache', {version: 2, providerIds: ['a'], globalAllowPatterns: []}],
        ['osprey_cache::p::a', {
            allowed: {
                legacy: {exp: Date.now() + 604800000},
                explicit: {exp: Date.now() + 604800000, userAllowed: true},
            },
            blocked: {blocked: {exp: Date.now() + 604800000, result: 'malicious'}},
        }],
    ]);
    const db = {
        transaction: () => {
            const tx = {
                objectStore: () => ({
                    get: key => {
                        const request = {result: records.get(key)};
                        queueMicrotask(() => request.onsuccess?.());
                        return request;
                    },
                    put: (value, key) => {
                        records.set(key, value);
                    },
                    delete: key => {
                        records.delete(key);
                    },
                }),
            };
            setImmediate(() => tx.oncomplete?.());
            return tx;
        },
    };
    const context = vm.createContext({
        console,
        Date,
        Map,
        Set,
        setTimeout,
        clearTimeout,
        setInterval: () => 0,
        indexedDB: {
            open: () => {
                const request = {result: db};
                queueMicrotask(() => request.onsuccess?.());
                return request;
            },
        },
        OspreyBrowserAPI: {storageGet: async () => ({})},
        OspreyUrlService: {},
        OspreyProtectionResult: {
            resultTypes: {FAILED: 'failed'},
            blockingResults: new Set(['malicious']),
        },
        OspreyPolicyService: {getManagedListConfig: async () => null},
    });
    load(context, 'state/cache-service.js');
    const cache = context.OspreyCacheService;
    assert.equal(await cache.getAllowedEntry('a', 'legacy'), null);
    assert.equal((await cache.getAllowedEntry('a', 'explicit')).userAllowed, true);

    await cache.storeOutcomes([
        {providerId: 'a', lookupKey: 'blocked', outcome: 'failed'},
        {providerId: 'a', lookupKey: 'outage', outcome: 'failed'},
    ], 604800);
    assert.equal((await cache.getBlockedEntry('a', 'blocked')).result, 'malicious');
    assert.equal(await cache.getAllowedEntry('a', 'outage'), null);
    await new Promise(resolve => setTimeout(resolve, 550));
    assert.equal(records.get('osprey_cache').version, 3);
    assert.equal(records.get('osprey_cache::p::a').allowed.legacy, undefined);
});

const createCacheService = (records, managedListConfig = null) => {
    const db = {
        transaction: () => {
            const tx = {
                objectStore: () => ({
                    get: key => {
                        const request = {result: records.get(key)};
                        queueMicrotask(() => request.onsuccess?.());
                        return request;
                    },
                    put: (value, key) => {
                        records.set(key, value);
                    },
                    delete: key => {
                        records.delete(key);
                    },
                }),
            };
            setImmediate(() => tx.oncomplete?.());
            return tx;
        },
    };
    const context = vm.createContext({
        console, Date, Map, Set, setTimeout, clearTimeout,
        setInterval: () => 0,
        indexedDB: {
            open: () => {
                const request = {result: db};
                queueMicrotask(() => request.onsuccess?.());
                return request;
            },
        },
        OspreyBrowserAPI: {storageGet: async () => ({})},
        OspreyUrlService: {},
        OspreyProtectionResult: {resultTypes: {FAILED: 'failed'}, blockingResults: new Set(['malicious'])},
        OspreyPolicyService: {
            getManagedListConfig: async () => managedListConfig,
            getActionRestrictions: async () => ({disableUserAllowlist: false, lockUserAllowlist: false}),
        },
    });
    load(context, 'state/cache-service.js');
    return context.OspreyCacheService;
};

test('expired verdicts are ignored and disabled user allowlists hide stored exclusions', async () => {
    const future = Date.now() + 600000;
    const past = Date.now() - 1000;
    const records = () => new Map([
        ['osprey_cache', {version: 3, providerIds: ['a'], globalAllowPatterns: []}],
        ['osprey_cache::p::a', {
            allowed: {
                stale: {exp: past},
                cached: {exp: future},
                user: {exp: future, userAllowed: true},
            },
            blocked: {staleBlock: {exp: past, result: 'malicious'}},
        }],
    ]);
    const cache = createCacheService(records());
    assert.equal(await cache.getAllowedEntry('a', 'stale'), null);
    assert.equal(await cache.getBlockedEntry('a', 'staleBlock'), null);
    assert.equal((await cache.getAllowedEntry('a', 'user')).userAllowed, true);

    const policy = {allowlist: [], blocklist: [], disableUserAllowlist: true};
    const managed = createCacheService(records(), policy);
    assert.equal(await managed.getAllowedEntry('a', 'user'), null);
    assert.ok(await managed.getAllowedEntry('a', 'cached'));
});

test('capacity eviction drops cached verdicts before user exclusions', async () => {
    const cache = createCacheService(new Map());
    await cache.markAllowed('a', 'user', 600, true);

    for (let i = 0; i < 600; i++) {
        await cache.markAllowed('a', `clean-${i}`, 600);
    }

    assert.equal((await cache.getAllowedEntry('a', 'user')).userAllowed, true);
    assert.equal(await cache.getAllowedEntry('a', 'clean-0'), null);
});

test('managed list entries with a query block by path, but allow entries with one are ignored', async () => {
    const records = new Map();
    const config = {
        allowlist: ['https://ok.example/portal?x=1'],
        blocklist: ['https://phish.example/login?x=1#top'],
        disableUserAllowlist: false,
    };
    const db = {
        transaction: () => {
            const tx = {
                objectStore: () => ({
                    get: key => {
                        const request = {result: records.get(key)};
                        queueMicrotask(() => request.onsuccess?.());
                        return request;
                    },
                }),
            };
            setImmediate(() => tx.oncomplete?.());
            return tx;
        },
    };
    const context = vm.createContext({
        URL, console: {warn() {}, error() {}}, setTimeout, clearTimeout, setInterval: () => 0,
        indexedDB: {
            open: () => {
                const request = {result: db};
                queueMicrotask(() => request.onsuccess?.());
                return request;
            },
        },
        OspreyBrowserAPI: {storageGet: async () => ({})},
        OspreyProtectionResult: {resultTypes: {}},
        OspreyPolicyService: {getManagedListConfig: async () => config},
    });
    load(context, 'platform/url-service.js');
    load(context, 'state/cache-service.js');
    const cache = context.OspreyCacheService;
    assert.equal((await cache.getManagedListDecision('https://phish.example/login')).blocked, true);
    assert.equal((await cache.getManagedListDecision('https://phish.example/login?y=2')).blocked, true);
    assert.equal((await cache.getManagedListDecision('https://phish.example/home')).blocked, false);
    assert.equal((await cache.getManagedListDecision('https://ok.example/portal')).allowed, false);
});

test('failed cache writes back off instead of retrying every flush interval', async () => {
    const delays = [];
    const timers = [];
    const db = {
        transaction: (_, mode) => {
            if (mode === 'readwrite') {
                throw new Error('quota exceeded');
            }
            const tx = {
                objectStore: () => ({
                    get: () => {
                        const request = {result: undefined};
                        queueMicrotask(() => request.onsuccess?.());
                        return request;
                    },
                }),
            };
            setImmediate(() => tx.oncomplete?.());
            return tx;
        },
    };
    const context = vm.createContext({
        console: {warn() {}, error() {}}, Date, Map, Set,
        setTimeout: (fn, delay) => {
            delays.push(delay);
            timers.push(fn);
            return timers.length;
        },
        clearTimeout: () => {},
        setInterval: () => 0,
        indexedDB: {
            open: () => {
                const request = {result: db};
                queueMicrotask(() => request.onsuccess?.());
                return request;
            },
        },
        OspreyBrowserAPI: {storageGet: async () => ({})},
        OspreyUrlService: {},
        OspreyProtectionResult: {resultTypes: {}},
        OspreyPolicyService: {getManagedListConfig: async () => null},
    });
    load(context, 'state/cache-service.js');
    const cache = context.OspreyCacheService;
    await cache.markAllowed('a', 'key', 600).catch(() => {});

    for (let i = 0; i < 4; i++) {
        const before = delays.length;
        timers.at(-1)();
        await new Promise(resolve => setTimeout(resolve, 20));
        assert.ok(delays.length > before);
    }

    const retries = delays.slice(-3);
    assert.ok(retries[0] < retries[1] && retries[1] < retries[2], `delays did not grow: ${delays}`);
});
