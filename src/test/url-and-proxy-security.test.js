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

test('cache keys distinguish full queries while provider lookups omit them', () => {
    const context = vm.createContext({
        URL,
        console,
        OspreyBrowserAPI: {safeRuntimeURL: path => `chrome-extension://test/${path}`},
    });
    load(context, 'platform/url-service.js');
    load(context, 'platform/request-builder.js');

    const urls = [
        'http://evil.com/login',
        'http://evil.com:8443/login',
        'http://evil.com:8443/login?page=home',
        'http://evil.com:8443/login?page=paypal&page=bank',
    ];
    const keys = urls.map(url => context.OspreyUrlService.lookupValueForTarget(url, 'url'));
    assert.equal(new Set(keys).size, urls.length);
    assert.equal(keys[3], urls[3]);
    assert.equal(context.OspreyUrlService.normalizeUrl('http://evil.com:80/login#fragment'), urls[0]);
    assert.equal(context.OspreyUrlService.normalizeUrl('https://www.evil.com/login/?q=x#section'),
        'https://evil.com/login?q=x');
    assert.equal(context.OspreyUrlService.lookupValueForTarget(urls[3], 'hostname'), 'evil.com');

    const proxy = {
        kind: 'proxy_builtin', proxyBaseUrl: 'https://api.osprey.ac', endpoint: 'lookup',
        lookupTarget: 'url'
    };
    const direct = {
        kind: 'direct_static', lookupTarget: 'url',
        request: {urlTemplate: 'https://feed.example/lookup?url={url}'}
    };
    const proxyRequest = context.OspreyRequestBuilder.buildRequest(proxy, urls[3]);
    const directRequest = context.OspreyRequestBuilder.buildRequest(direct, urls[3]);
    assert.equal(JSON.parse(proxyRequest.options.body).url, 'http://evil.com:8443/login');
    assert.equal(proxyRequest.lookupKey, urls[3]);
    assert.equal(new URL(directRequest.url).searchParams.get('url'), 'http://evil.com:8443/login');
    assert.equal(directRequest.lookupKey, urls[3]);

    const directWithLookupValue = {
        ...direct, request: {
            urlTemplate: 'https://feed.example/lookup?value={lookupValue}',
            method: 'POST',
            headers: [{name: 'X-Lookup', value: '{url}'}],
            bodyTemplate: '{lookupValue}',
        }
    };
    const post = context.OspreyRequestBuilder.buildRequest(directWithLookupValue, urls[3]);
    assert.equal(new URL(post.url).searchParams.get('value'), 'http://evil.com:8443/login');
    assert.equal(post.options.headers['X-Lookup'], 'http://evil.com:8443/login');
    assert.equal(post.options.body, 'http://evil.com:8443/login');
    assert.equal(post.lookupKey, urls[3]);

    const googleUrl = 'https://drive.google.com/uc?export=download&id=123&token=private';
    assert.equal(context.OspreyUrlService.normalizeLookupUrl(googleUrl),
        'https://drive.google.com/uc?export=download&id=123');
    assert.equal(context.OspreyUrlService.normalizeUrl(googleUrl), googleUrl);
});

test('a cached verdict for one query cannot skip a lookup for another query', async () => {
    const allowed = new Map();
    const requests = [];
    const context = vm.createContext({
        URL,
        AbortController,
        console: {
            info() {
            }, debug() {
            }, warn() {
            }
        },
        fetch: async (url, options) => {
            requests.push({url, body: JSON.parse(options.body)});
            return {
                ok: true, json: async () => ({
                    result: requests.length === 1 ? 'allowed' : 'malicious',
                })
            };
        },
        OspreyBrowserAPI: {safeRuntimeURL: path => `chrome-extension://test/${path}`},
        OspreyProtectionResult: {
            resultTypes: {
                ALLOWED: 'allowed', FAILED: 'failed', WAITING: 'waiting',
                MALICIOUS: 'malicious',
            },
            blockingResults: new Set(['malicious']),
            fromProviderString: value => value,
            create: value => value,
        },
        OspreyTimedSignal: {
            create: signal => ({
                signal, cleanup() {
                }
            })
        },
        OspreyCacheService: {
            getManagedListDecision: async () => ({blocked: false, allowed: false}),
            matchesGlobalPattern: async () => false,
            getBlockedEntry: async () => null,
            getAllowedEntry: async (_, key) => allowed.get(key) || null,
            markAllowed: async (_, key) => {
                allowed.set(key, {exp: Date.now() + 60000});
            },
            markBlocked: async () => {
            },
            markProcessing() {
            },
            clearProcessing() {
            },
            clearProcessingByTab() {
            },
        },
    });
    load(context, 'platform/url-service.js');
    load(context, 'platform/request-builder.js');
    load(context, 'providers/provider-engine.js');

    const provider = {
        id: 'proxy', displayName: 'Proxy', kind: 'proxy_builtin', lookupTarget: 'url',
        proxyBaseUrl: 'https://api.osprey.ac', endpoint: 'lookup', state: {enabled: true},
    };
    const results = [];
    for (const url of ['https://evil.example/login?page=home', 'https://evil.example/login?page=paypal']) {
        await context.OspreyProviderEngine.scanUrl({
            tabId: 1, url, providers: [provider], expirationSeconds: 604800,
            onResult: result => results.push(result.result),
        });
    }
    assert.deepEqual(results, ['allowed', 'malicious']);
    assert.equal(requests.length, 2);
    assert.deepEqual(requests.map(request => request.body.url),
        ['https://evil.example/login', 'https://evil.example/login']);
    assert.equal(allowed.has('https://evil.example/login?page=home'), true);
    assert.equal(allowed.has('https://evil.example/login?page=paypal'), false);
});

test('proxy overrides require HTTPS even on private networks', async () => {
    let override = 'http://public-host.example:8080/path';
    const definition = {
        id: 'proxy', kind: 'proxy_builtin', group: 'feeds', displayName: 'Proxy',
        proxyBaseUrl: 'https://api.osprey.ac', enabledByDefault: true, blockCategories: [],
    };
    const context = vm.createContext({
        URL,
        console,
        OspreyBrowserAPI: {api: {}},
        OspreyProviderCatalog: {
            getAllDefinitions: () => [definition],
            isCustomProvider: () => false,
            supportsBlockingResult: () => false,
        },
        OspreyProviderGroups: {feeds: {order: 1}},
        OspreyProviderStateStore: {getState: async () => ({providers: {}})},
        OspreyProtectionResult: {
            resultTypes: {
                MALICIOUS: 'malicious', PHISHING: 'phishing', SUSPICIOUS: 'suspicious',
                NEWLY_REGISTERED: 'newly_registered', DYNAMIC_DNS: 'dynamic_dns',
            }
        },
    });
    load(context, 'state/policy-service.js');
    const isAllowedTransport = context.OspreyPolicyService.isAllowedTransport;
    context.OspreyPolicyService = {
        isAllowedTransport,
        applyToState: async state => ({
            effectiveState: state, policies: {ProxyBaseUrl: override, ProxyApiKey: 'secret'},
            appManagedKeys: new Set(), providerManagedIds: new Set(), commercialDisabledIds: new Set(),
        }),
    };
    load(context, 'providers/provider-runtime-factory.js');

    const providerFor = async () => (await context.OspreyProviderRuntimeFactory.createRuntime({fresh: true})).providers[0];
    assert.equal((await providerFor()).proxyBaseUrl, definition.proxyBaseUrl);
    assert.equal((await providerFor()).proxyApiKey, '');

    override = 'http://192.168.1.2:8080/path';
    assert.equal((await providerFor()).proxyBaseUrl, definition.proxyBaseUrl);
    assert.equal((await providerFor()).proxyApiKey, '');
    override = 'https://public-host.example:8443/path';
    assert.equal((await providerFor()).proxyBaseUrl, 'https://public-host.example:8443');
});

test('host permission stays limited to the public API so updates never re-prompt users', () => {
    const manifest = JSON.parse(readFileSync(path.join(main, 'manifest.json'), 'utf8'));
    assert.deepEqual(manifest.host_permissions, ['https://api.osprey.ac/*']);
    assert.equal(manifest.optional_host_permissions, undefined);
});

test('URLs with RFC 3986 host characters are checked, while bare host patterns stay strict', () => {
    const context = vm.createContext({
        URL,
        console: {warn() {}},
        OspreyBrowserAPI: {safeRuntimeURL: path => `chrome-extension://test/${path}`},
    });
    load(context, 'platform/url-service.js');
    const urlService = context.OspreyUrlService;
    assert.equal(urlService.parseHttpUrl('https://login$secure.evil.com/').hostname, 'login$secure.evil.com');
    assert.equal(urlService.normalizeUrl('https://login$secure.evil.com/a'), 'https://login$secure.evil.com/a');
    assert.equal(urlService.isNavigableHost('login$secure.evil.com'), true);
    assert.equal(urlService.isAcceptableHost('login$secure.evil.com'), false);
    assert.equal(urlService.parseHttpUrl('https://a{b.evil.com/'), null);
});
