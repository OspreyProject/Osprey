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
    const promise = new Promise(done => {
        resolve = done;
    });
    return {promise, resolve};
};
const tick = () => new Promise(resolve => setImmediate(resolve));

test('clearing during initial snapshot load removes persisted provider shards', async () => {
    const shardKey = 'osprey_cache::p::provider';
    const records = new Map([
        ['osprey_cache', {version: 3, providerIds: ['provider'], globalAllowPatterns: ['*.example.com']}],
        [shardKey, {allowed: {site: {exp: Date.now() + 60000, userAllowed: true}}, blocked: {}}],
    ]);
    const shardRequested = deferred();
    const releaseShard = deferred();
    const db = {
        objectStoreNames: {contains: () => true},
        transaction: () => {
            const tx = {
                objectStore: () => ({
                    get: key => {
                        const request = {result: records.get(key)};
                        const complete = () => {
                            request.onsuccess();
                            tx.oncomplete();
                        };
                        if (key === shardKey) {
                            shardRequested.resolve();
                            releaseShard.promise.then(complete);
                        } else {
                            queueMicrotask(complete);
                        }
                        return request;
                    },
                    put: (value, key) => {
                        records.set(key, value);
                        queueMicrotask(() => tx.oncomplete());
                    },
                    delete: key => {
                        records.delete(key);
                        queueMicrotask(() => tx.oncomplete());
                    },
                })
            };
            return tx;
        },
    };
    const context = vm.createContext({
        console, setTimeout, clearTimeout, setInterval: () => {
        },
        indexedDB: {
            open: () => {
                const request = {};
                queueMicrotask(() => {
                    request.result = db;
                    request.onsuccess();
                });
                return request;
            }
        },
        OspreyBrowserAPI: {},
        OspreyUrlService: {},
        OspreyProtectionResult: {blockingResults: new Set()},
        OspreyPolicyService: {getActionRestrictions: async () => ({})},
    });
    load(context, 'state/cache-service.js');
    await shardRequested.promise;
    const cache = context.OspreyCacheService;
    const clearing = cache.clearAll();
    releaseShard.resolve();
    assert.equal((await clearing).ok, true);
    await new Promise(resolve => setTimeout(resolve, 20));
    assert.deepEqual(Array.from(records.get('osprey_cache').providerIds), []);
    assert.equal(records.has(shardKey), false);
    assert.equal(await cache.getAllowedEntry('provider', 'site'), null);
});

test('managed allowlist hosts match exactly; managed blocklist hosts always cover subdomains', async () => {
    const config = {
        allowlist: ['sharepoint.com', '*.corp.example.com', 'https://apps.example.com/portal'],
        blocklist: ['bad.example.com', '*.malware.example'],
    };
    const context = vm.createContext({
        URL, console, setInterval: () => {
        },
        OspreyPolicyService: {getManagedListConfig: async () => config},
        OspreyBrowserAPI: {safeRuntimeURL: p => `chrome-extension://test/${p}`},
        OspreyProtectionResult: {resultTypes: {}},
    });
    load(context, 'platform/url-service.js');
    load(context, 'state/cache-service.js');
    const decide = context.OspreyCacheService.getManagedListDecision;

    assert.equal((await decide('https://sharepoint.com/')).allowed, true);
    assert.equal((await decide('https://attacker.sharepoint.com/')).allowed, false);
    assert.equal((await decide('https://corp.example.com/')).allowed, true);
    assert.equal((await decide('https://a.corp.example.com/')).allowed, true);
    assert.equal((await decide('https://apps.example.com/portal/login')).allowed, true);
    assert.equal((await decide('https://other.apps.example.com/portal/login')).allowed, false);
    assert.equal((await decide('https://bad.example.com/')).blocked, true);
    assert.equal((await decide('https://tenant.bad.example.com/')).blocked, true);
    assert.equal((await decide('https://notbad.example.com/')).blocked, false);
    assert.equal((await decide('https://sub.malware.example/')).blocked, true);
});

test('API keys persist for direct providers and all shared-request group members', async () => {
    const local = {};
    const definitions = [
        {id: 'direct', enabledByDefault: true},
        {id: 'group-a', sharedRequestGroup: 'shared', enabledByDefault: true},
        {id: 'group-b', sharedRequestGroup: 'shared', enabledByDefault: true},
    ];
    const context = vm.createContext({
        console,
        OspreyBrowserAPI: {
            storageGet: async (_, key) => ({[key]: local[key]}),
            storageSet: async (_, value) => Object.assign(local, value),
        },
        OspreyProviderCatalog: {
            getAllDefinitions: () => definitions,
            getDefinition: id => definitions.find(def => def.id === id) || null,
        },
    });
    load(context, 'state/provider-state-store.js');
    const store = context.OspreyProviderStateStore;
    await store.setProviderApiKey('direct', 'direct-key');
    await store.setProviderApiKey('group-a', 'group-key');
    const state = await store.getState({fresh: true});
    assert.equal(state.providers.direct.apiKey, 'direct-key');
    assert.equal(state.providers['group-a'].apiKey, 'group-key');
    assert.equal(state.providers['group-b'].apiKey, 'group-key');
});

const blockingFixture = ({managedAllowed = false, hideProceed = false} = {}) => {
    const navigated = [];
    const logged = [];
    const scans = [];
    const notificationUrls = [];
    const resetHosts = [];
    const allowedEntries = new Set();
    const contextByTab = new Map();
    const context = vm.createContext({
        URL, console, setTimeout, clearTimeout,
        OspreyBrowserAPI: {
            safeRuntimeURL: p => `chrome-extension://test/${p}`,
            tabsUpdate: async (_, value) => {
                navigated.push(value.url);
            },
        },
        OspreyBadgeService: {
            clear() {
            }, syncWithContext() {
            }
        },
        OspreyCacheService: {
            getManagedListDecision: async () => ({allowed: managedAllowed, blocked: false}),
            matchesGlobalPattern: async () => false,
            getAllowedEntry: async (providerId, lookupKey) => allowedEntries.has(`${providerId}::${lookupKey}`) ? {} : null,
            markAllowed: async (providerId, lookupKey) => {
                allowedEntries.add(`${providerId}::${lookupKey}`);
            },
            clearBlockedForProviderLookup: async () => {
            },
        },
        OspreyEventLogService: {
            recordOverride: event => logged.push(event),
            recordLocal: (type, event) => logged.push({type, ...event}),
        },
        OspreyNotificationService: {
            blockForUrl: async url => {
                notificationUrls.push(url);
            },
            resetForHost: async host => {
                resetHosts.push(host);
                return {ok: true};
            },
        },
        OspreyMessageBus: {Messages: {}},
        OspreyPolicyService: {getActionRestrictions: async () => ({hideWarningProceedButton: hideProceed})},
        OspreyProviderEngine: {
            abortTab: async () => {
            }, scanUrl: async request => {
                scans.push(request);
            }
        },
        OspreyProviderRuntimeFactory: {
            createRuntime: async () => ({
                providers: [{id: 'provider', lookupTarget: 'url', state: {enabled: true}}],
                effectiveState: {
                    app: {
                        domainIntelMode: 'block', protectedDomains: ['ups.com'],
                        notificationProtection: 'on', cacheExpirationSeconds: 60
                    }
                },
                blockingProviderIdsByResult: {},
            })
        },
        OspreyResultAggregationService: {
            ensureHydrated: async () => {
            },
            getBlockedContext: tabId => contextByTab.get(tabId),
            removeOrigin: (tabId, origin) => {
                const current = contextByTab.get(tabId);
                const remaining = current.origins.filter(id => id !== origin);
                if (!remaining.length) {
                    contextByTab.delete(tabId);
                    return null;
                }
                const next = {...current, origins: remaining, primaryOrigin: remaining[0]};
                contextByTab.set(tabId, next);
                return next;
            },
            persist: async () => {
            },
            retire: tabId => contextByTab.delete(tabId),
            clear: tabId => contextByTab.delete(tabId),
            recordBlockingResult: (tabId, url, origin, result) => contextByTab.set(tabId,
                {url, origins: [origin], primaryOrigin: origin, primaryResult: result}),
            getFrameZeroUrl: () => '',
            isRetired: () => false,
            isRedirected: () => false,
            markRedirected() {
            },
            beginNavigation() {
            },
            setFrameZeroUrl() {
            },
        },
        OspreyProtectionResult: {create: value => ({...value, isBlocking: true})},
    });
    load(context, 'platform/url-service.js');
    load(context, 'platform/domain-intel.js');
    load(context, 'background/blocking-service.js');
    return {
        context, contextByTab, navigated, logged, scans, notificationUrls, resetHosts,
        service: context.OspreyBlockingService
    };
};

test('domain intel warn records findings and an analysis failure still scans providers', async () => {
    const fixture = blockingFixture();
    fixture.context.OspreyProviderRuntimeFactory.createRuntime = async () => ({
        providers: [{id: 'provider', state: {enabled: true}}],
        effectiveState: {app: {domainIntelMode: 'warn', protectedDomains: ['examplebank.com']}},
    });
    await fixture.service.handleNavigation({tabId: 10, url: 'https://examplebark.com/'});
    assert.equal(fixture.logged[0].type, 'domain_intel');
    assert.equal(fixture.logged[0].kind, 'protected_lookalike');
    assert.equal(fixture.scans.length, 1);

    fixture.context.OspreyDomainIntel = {
        analyze: () => {
            throw new RangeError('invalid code point');
        }
    };
    await fixture.service.handleNavigation({tabId: 11, url: 'https://another.example/'});
    assert.equal(fixture.scans.length, 2);
    fixture.context.OspreyProviderRuntimeFactory.createRuntime = async () => ({
        providers: [{id: 'provider', state: {enabled: true}}],
        effectiveState: {app: {domainIntelMode: 'block', protectedDomains: ['examplebank.com']}},
    });
    await fixture.service.handleNavigation({tabId: 13, url: 'https://third.example/'});
    assert.equal(fixture.scans.length, 3);
});

test('notification blocking uses the original origin and allowing resets that exact host', async () => {
    const fixture = blockingFixture();
    fixture.context.OspreyProviderRuntimeFactory.createRuntime = async () => ({
        providers: [{id: 'provider', state: {enabled: true}}],
        effectiveState: {app: {domainIntelMode: '', notificationProtection: 'on'}},
        blockingProviderIdsByResult: {malicious: new Set(['provider'])},
        providersById: new Map([['provider', {}]]),
    });
    const url = 'https://www.example.com:8443/attack';
    await fixture.service.handleNavigation({tabId: 12, url});
    await fixture.scans[0].onResult({isBlocking: true, origin: 'provider', result: 'malicious'});
    assert.deepEqual(fixture.notificationUrls, [url]);
    fixture.context.OspreyCacheService.allowPattern = async () => ({ok: true});
    fixture.context.OspreyCacheService.clearBlockedForLookup = async () => {
    };
    await fixture.service.allowWebsite(12, url);
    assert.deepEqual(fixture.resetHosts, ['www.example.com']);
    // A failed notification reset is best-effort: the allowlist entry is already saved, so the
    // action still succeeds and navigates instead of reporting a failure for an allowed site.
    fixture.context.OspreyNotificationService.resetForHost = async () => ({ok: false});
    const count = fixture.navigated.length;
    assert.equal((await fixture.service.allowWebsite(12, url)).ok, true);
    assert.equal(fixture.navigated.length, count + 1);
    fixture.context.OspreyNotificationService.resetForHost = async () => {
        throw new Error('contentSettings unavailable');
    };
    assert.equal((await fixture.service.allowWebsite(12, url)).ok, true);
});

test('notification service records unsupported browsers and resets only tracked origins', async () => {
    const recorded = [];
    const settings = [];
    let registry = {};
    const context = vm.createContext({
        URL, console,
        OspreyBrowserAPI: {
            storage: {
                local: {
                    get: (_, callback) => callback({osprey_notification_origins: registry}),
                    set: (data, callback) => {
                        registry = data.osprey_notification_origins;
                        callback();
                    },
                }
            }
        },
        OspreyEventLogService: {
            recordLocal: async type => {
                recorded.push(type);
            }
        },
    });
    load(context, 'state/notification-service.js');
    const service = context.OspreyNotificationService;
    assert.equal((await service.blockForUrl('https://www.example.com:8443/path')).reason, 'unsupported');
    assert.deepEqual(recorded, ['notification_protection_unavailable']);
    context.chrome = {
        contentSettings: {
            notifications: {
                set: (entry, callback) => {
                    settings.push(entry);
                    callback();
                },
            }
        }
    };
    await service.blockForUrl('https://www.example.com:8443/path');
    assert.equal(settings[0].primaryPattern, 'https://www.example.com:8443/*');
    await service.resetForHost('example.com');
    assert.equal(settings.length, 1);
    await service.resetForHost('www.example.com');
    assert.equal(settings[1].setting, 'ask');
    assert.equal(settings[1].primaryPattern, settings[0].primaryPattern);
});

test('local domain findings persist without being sent to the reporting endpoint', async () => {
    const saved = new Map();
    const indexedDB = {
        open: () => {
            const request = {};
            const db = {
                objectStoreNames: {contains: () => false},
                createObjectStore() {
                },
                transaction: () => {
                    const tx = {
                        objectStore: () => ({
                            get: key => {
                                const operation = {result: saved.get(key)};
                                queueMicrotask(() => {
                                    operation.onsuccess();
                                    tx.oncomplete();
                                });
                                return operation;
                            },
                            put: (value, key) => {
                                saved.set(key, value);
                                queueMicrotask(() => tx.oncomplete());
                            },
                        }),
                    };
                    return tx;
                },
            };
            queueMicrotask(() => {
                request.result = db;
                request.onupgradeneeded();
                request.onsuccess();
            });
            return request;
        }
    };
    const sent = [];
    const context = vm.createContext({
        indexedDB, console, crypto: require('node:crypto').webcrypto,
        AbortController, setTimeout, clearTimeout,
        fetch: async (_, options) => {
            sent.push(JSON.parse(options.body));
            return {ok: true};
        },
        OspreyBrowserAPI: {api: {runtime: {getManifest: () => ({version: 'test'})}}},
        OspreyPolicyService: {
            getEndpointIdentity: async () => ({deviceTag: '', siteId: ''}),
            getReportingConfig: async () => ({endpoint: 'https://report.example/', authToken: ''}),
        },
    });
    load(context, 'state/event-log-service.js');
    const log = context.OspreyEventLogService;
    await log.recordLocal('domain_intel', {
        url: 'https://example.test/', kind: 'protected_lookalike',
        target: 'example.com', detail: 'homograph'
    });
    assert.equal((await log.getEvents())[0].kind, 'protected_lookalike');
    await log.recordDetection({url: 'https://blocked.test/', providerId: 'provider', verdict: 'malicious'});
    assert.equal((await log.flushToReporting()).sent, 1);
    assert.equal(sent[0].events.length, 1);
    assert.equal(sent[0].events[0].type, 'block');
    assert.equal((await log.getEvents())[0].type, 'domain_intel');
});

test('short protected-domain typos remain signals, while longer lookalikes block and can be continued', async () => {
    const fixture = blockingFixture();
    const {context, contextByTab, navigated, service} = fixture;
    assert.equal(context.OspreyDomainIntel.analyze('ubs.com', ['ups.com']).detail, 'edit_distance');
    assert.equal(context.OspreyDomainIntel.analyze('ample.com', ['apple.com']).detail, 'edit_distance');
    await service.handleNavigation({tabId: 1, url: 'https://ubs.com/'});
    assert.equal(navigated.length, 0);
    assert.equal(contextByTab.has(1), false);

    const runtime = context.OspreyProviderRuntimeFactory.createRuntime;
    context.OspreyProviderRuntimeFactory.createRuntime = async () => {
        const result = await runtime();
        result.effectiveState.app.protectedDomains = ['examplebank.com'];
        return result;
    };
    await service.handleNavigation({tabId: 2, url: 'https://examplebark.com/'});
    assert.ok(navigated[0].includes('warning-page.html'));
    assert.deepEqual(Array.from(contextByTab.get(2).origins), ['osprey']);
    assert.equal((await service.continueToWebsite(2, 'https://examplebark.com/', 'osprey')).navigated, true);
    assert.equal(navigated[1], 'https://examplebark.com/');

    // Continuing past the warning is remembered, so the same lookalike is not blocked again.
    await service.handleNavigation({tabId: 3, url: 'https://examplebark.com/'});
    assert.equal(navigated.length, 2);
});

test('administrator approval resumes a blocked URL even when Continue is hidden, without writing an exclusion', async () => {
    const fixture = blockingFixture({managedAllowed: true, hideProceed: true});
    fixture.contextByTab.set(3, {
        url: 'https://approved.example/', origins: ['provider'],
        primaryOrigin: 'provider', primaryResult: 'malicious',
    });
    const result = await fixture.service.continueToWebsite(3, 'https://approved.example/', 'provider');
    assert.equal(result.navigated, true);
    assert.deepEqual(fixture.navigated, ['https://approved.example/']);
    assert.deepEqual(fixture.logged.map(event => event.type), ['admin_approval']);
    assert.equal((await fixture.service.continueToWebsite(3, 'https://different.example/', 'provider')).ok, false);
    assert.equal(fixture.navigated.length, 1);
});

test('administrator approval clears every provider block without recording a user override', async () => {
    const fixture = blockingFixture({managedAllowed: true, hideProceed: true});
    fixture.contextByTab.set(9, {
        url: 'https://approved.example/', origins: ['provider', 'second-provider'],
        primaryOrigin: 'provider', primaryResult: 'malicious',
    });
    const result = await fixture.service.continueToWebsite(9, 'https://approved.example/', 'provider');
    assert.equal(result.navigated, true);
    assert.equal(result.context, null);
    assert.equal(fixture.contextByTab.has(9), false);
    assert.deepEqual(fixture.logged.map(event => event.type), ['admin_approval']);
});

test('warning support link omits sensitive fields and approval watch resumes through the managed path', async () => {
    const blockedUrl = 'https://blocked.example/private?token=private-value';
    const createElement = () => {
        const attributes = new Map();
        const listeners = new Map();
        return {
            children: [], textContent: '', title: '', hidden: false, disabled: false,
            classList: {
                contains: () => false, toggle() {
                }, add() {
                }, remove() {
                }
            },
            setAttribute: (name, value) => attributes.set(name, value),
            getAttribute: name => attributes.get(name) ?? null,
            hasAttribute: name => attributes.has(name),
            removeAttribute: name => attributes.delete(name),
            addEventListener: (name, fn) => listeners.set(name, fn),
            appendChild(child) {
                this.children.push(child);
            },
            listeners,
        };
    };
    const elements = new Map();
    let watch;
    let stopped = false;
    const sent = [];
    const document = {
        URL: `chrome-extension://test/warning-page.html?url=${encodeURIComponent(blockedUrl)}&or=provider&rs=malicious`,
        readyState: 'loading', visibilityState: 'hidden',
        documentElement: {style: {}},
        getElementById: id => {
            if (!elements.has(id)) elements.set(id, createElement());
            return elements.get(id);
        },
        querySelector: () => createElement(),
        createElement,
        createTextNode: text => ({textContent: text}),
        addEventListener() {
        },
    };
    const lang = new Proxy({
        applyLogoAlt() {
        }, setWarningMessageOverride() {
        },
        getWarningMessage: () => 'Warning', format: () => 'Provider',
    }, {get: (target, key) => target[key] ?? String(key)});
    const messages = {RECHECK_BLOCKED_URL: 'recheck', CONTINUE_TO_WEBSITE: 'continue'};
    const context = vm.createContext({
        URL, URLSearchParams, document, LangUtil: lang,
        console: {
            warn() {
            }
        }, setTimeout: () => 1,
        setInterval: fn => {
            watch = fn;
            return 1;
        },
        clearInterval: () => {
            stopped = true;
        },
        addEventListener() {
        },
        OspreyBrowserAPI: {
            runtimeSendMessage: async message => {
                sent.push(message);
                return message.messageType === 'recheck' ? {ok: true, allowed: true} : {ok: true, navigated: true};
            }
        },
        OspreyMessageBus: {Messages: messages, Ports: {}},
        OspreyProtectionResult: {
            Origin: {UNKNOWN: 'unknown'}, resultTypes: {FAILED: 'failed'},
            normalize: value => value, messageKeys: {malicious: 'malicious', failed: 'failed'},
        },
        OspreyProviderCatalog: {getDefinition: () => null},
        OspreyProviderStateStore: {getState: async () => ({})},
        OspreyPolicyService: {
            ensureCustomProviders: async () => {
            },
            applyToAppState: async () => ({
                effectiveApp: {
                    hideWarningProceedButton: true,
                    supportUrl: 'http://support.example/ask?topic=unblock',
                    userEmail: 'person@example.com',
                }
            }),
        },
        OspreyReportLinkBuilder: {},
    });
    load(context, 'pages/warning/warning-page.js');
    context.WarningSingleton.initialize();
    await tick();
    const link = elements.get('supportContact').children.find(child => child.listeners?.has('click'));
    assert.equal(link.getAttribute('href'), 'http://support.example/ask?topic=unblock');
    link.listeners.get('click')();
    await watch();
    assert.deepEqual(sent.map(message => message.messageType), ['recheck', 'continue']);
    assert.equal(sent[1].blockedUrl, blockedUrl);
    assert.equal(stopped, true);
});

test('unsafe regex rules are rejected at validation and evaluation boundaries', () => {
    const context = vm.createContext({
        URL, console: {
            warn() {
            }
        }, OspreyProviderGroups: {feeds: {}}
    });
    load(context, 'catalog/catalog-validator.js');
    load(context, 'platform/response-rule-engine.js');
    const safe = context.OspreyCatalogValidator.isSafeRegexPattern;
    const definition = {
        id: 'test-feed', kind: 'direct_static', group: 'feeds', displayName: 'Test Feed',
        enabledByDefault: true, lookupTarget: 'url', icon: 'icon.svg', tags: [],
        report: {type: 'none'}, request: {urlTemplate: 'https://feed.example/check', headers: []},
        responseRules: [{path: 'value', operator: 'regex', value: '^bad[a-z]+$', result: 'BLOCKED'}],
    };
    assert.equal(context.OspreyCatalogValidator.validateCustom([definition], []).valid.length, 1);
    assert.equal(safe('^bad[a-z]+$'), true);
    for (const pattern of ['(a+)+$', '(a|aa)+$', 'a*a*$', '(a)\\1', 'a{1,100}b']) {
        assert.equal(safe(pattern), false, pattern);
        definition.responseRules[0].value = pattern;
        assert.equal(context.OspreyCatalogValidator.validateCustom([definition], []).valid.length, 0);
        assert.equal(context.OspreyResponseRuleEngine.evaluateRules({value: 'a'.repeat(32) + '!'},
            [{path: 'value', operator: 'regex', value: pattern, result: 'BLOCKED'}]), 'ALLOWED');
    }
    const rule = [{path: 'value', operator: 'regex', value: '^bad[a-z]+$', result: 'BLOCKED'}];
    assert.equal(context.OspreyResponseRuleEngine.evaluateRules({value: 'badsite'}, rule), 'BLOCKED');
    assert.equal(context.OspreyResponseRuleEngine.evaluateRules({value: 'a'.repeat(1025)}, rule), 'ALLOWED');
});

test('concurrent reporting flushes and heartbeats share one request per operation', async () => {
    const pendingPosts = [];
    const context = vm.createContext({
        console, AbortController, setTimeout, clearTimeout,
        fetch: async (_, options) => {
            const request = deferred();
            pendingPosts.push({body: JSON.parse(options.body), request});
            return request.promise;
        },
        OspreyBrowserAPI: {api: {runtime: {getManifest: () => ({version: 'test'})}}},
        OspreyPolicyService: {
            getEndpointIdentity: async () => ({deviceTag: '', siteId: ''}),
            getReportingConfig: async () => ({endpoint: 'https://report.example/', authToken: ''}),
            getProxyOrigin: async () => '',
        },
    });
    const saved = new Map();
    context.indexedDB = {
        open: () => {
            const request = {};
            const db = {
                objectStoreNames: {contains: () => false}, createObjectStore() {
                },
                transaction: () => {
                    const tx = {
                        objectStore: () => ({
                            get: key => {
                                const operation = {result: saved.get(key)};
                                queueMicrotask(() => {
                                    operation.onsuccess();
                                    tx.oncomplete();
                                });
                                return operation;
                            },
                            put: (value, key) => {
                                saved.set(key, value);
                                queueMicrotask(() => tx.oncomplete());
                            },
                        })
                    };
                    return tx;
                },
            };
            queueMicrotask(() => {
                request.result = db;
                request.onupgradeneeded();
                request.onsuccess();
            });
            return request;
        }
    };
    load(context, 'state/event-log-service.js');
    context.OspreyProviderRuntimeFactory = {
        createRuntime: async () => ({
            effectiveState: {app: {}}, providers: [{state: {enabled: true}}],
        })
    };
    const log = context.OspreyEventLogService;
    await log.recordDetection({url: 'https://blocked.example/', providerId: 'provider'});
    const flushes = [log.flushToReporting(), log.flushToReporting()];
    const heartbeats = [log.sendHeartbeat(), log.sendHeartbeat()];
    await tick();
    assert.equal(pendingPosts.length, 2);
    assert.deepEqual(pendingPosts.map(item => item.body.kind).sort(), ['events', 'heartbeat']);
    for (const post of pendingPosts) post.request.resolve({ok: true});
    assert.deepEqual((await Promise.all(flushes)).map(result => result.sent), [1, 1]);
    assert.deepEqual((await Promise.all(heartbeats)).map(result => result.ok), [true, true]);
    assert.equal(pendingPosts.length, 2);
    const next = log.flushToReporting();
    assert.equal((await next).sent, 0);
});

test('managed blocks cannot be continued, even for lookalike origins', async () => {
    const fixture = blockingFixture();
    fixture.context.OspreyCacheService.getManagedListDecision = async () => ({allowed: true, blocked: true});
    fixture.contextByTab.set(4, {
        url: 'https://blocked.example/', origins: ['osprey'],
        primaryOrigin: 'osprey', primaryResult: 'lookalike',
    });
    assert.equal((await fixture.service.continueToWebsite(4, 'https://blocked.example/', 'osprey')).ok, false);
    assert.equal(fixture.navigated.length, 0);
});

test('heartbeat reflects effective global disable and provider availability', async () => {
    const bodies = [];
    const runtime = {
        effectiveState: {app: {disableAllProviders: false}},
        providers: [{state: {enabled: true}}]
    };
    const context = vm.createContext({
        AbortController, setTimeout, clearTimeout,
        console, fetch: async (_, options) => {
            bodies.push(JSON.parse(options.body));
            return {ok: true};
        },
        OspreyBrowserAPI: {api: {runtime: {getManifest: () => ({version: '1.0'})}}},
        OspreyPolicyService: {
            getReportingConfig: async () => ({endpoint: 'https://report.example/', authToken: ''}),
            getEndpointIdentity: async () => ({deviceTag: '', siteId: ''}),
            getProxyOrigin: async () => '',
        },
    });
    load(context, 'state/event-log-service.js');
    context.OspreyProviderRuntimeFactory = {createRuntime: async () => runtime};
    const send = context.OspreyEventLogService.sendHeartbeat;
    await send();
    runtime.effectiveState.app.disableAllProviders = true;
    await send();
    runtime.effectiveState.app.disableAllProviders = false;
    runtime.providers[0].state.enabled = false;
    await send();
    assert.deepEqual(bodies.map(body => body.enabled), [true, false, false]);
    assert.equal(bodies.every(body => body.installed === true), true);
});
