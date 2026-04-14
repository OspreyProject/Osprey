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

globalThis.OspreyDirectIntegrations = (() => {
    // Global variables
    const providerGroups = globalThis.OspreyProviderGroups;

    const metaDefenderApiRequest = Object.freeze({
        urlTemplate: 'https://api.metadefender.com/v4/url/',
        method: 'POST',
        headers: Object.freeze([
            Object.freeze({
                name: 'apikey',
                value: '{api_key}'
            }),
        ]),
        bodyTemplate: '{"url": ["{url}"]}',
        contentType: 'application/json',
        timeoutMs: 7000,
    });


    const apiVoidDomainReputationRequest = Object.freeze({
        urlTemplate: 'https://api.apivoid.com/v2/domain-reputation',
        method: 'POST',
        headers: Object.freeze([
            Object.freeze({
                name: 'X-API-Key',
                value: '{api_key}'
            }),
        ]),
        bodyTemplate: '{"host": "{lookupValue}"}',
        contentType: 'application/json',
        timeoutMs: 7000,
    });

    const integration = definition => Object.freeze({
        kind: 'direct_static',
        enabledByDefault: false,
        aliases: [],
        tags: [],
        icon: '',
        ...definition,
    });

    const metadefenderIntegration = ({id, displayName, aliases = [], providerNames, responseRules}) => integration({
        id,
        aliases,
        displayName,
        group: providerGroups.direct_integrations.id,
        icon: 'assets/providers/metadefender.png',
        enabledByDefault: false,
        lookupTarget: 'url',
        tags: ['api_key_required'],
        apiKeyUrl: 'https://metadefender.com/',
        request: metaDefenderApiRequest,
        sharedApiKeyGroup: 'metadefender',
        sharedRequestGroup: 'metadefender-url-reputation',
        responseRuleScope: 'metadefender_provider_block',
        metaDefenderProviderNames: Object.freeze([].concat(providerNames || []).map(value => String(value || '')).filter(Boolean)),
        responseRules: Object.freeze((Array.isArray(responseRules) && responseRules.length > 0 ? responseRules : [
            Object.freeze({
                path: 'provider',
                operator: 'exists',
                result: 'ALLOWED'
            }),
        ]).map(rule => Object.freeze({...rule}))),
        report: Object.freeze({
            type: 'none'
        }),
    });


    const apivoidIntegration = ({id, displayName, aliases = [], engineNames, responseRules}) => integration({
        id,
        aliases,
        displayName,
        group: providerGroups.direct_integrations.id,
        icon: 'assets/providers/apivoid.avif',
        enabledByDefault: false,
        lookupTarget: 'hostname',
        tags: ['api_key_required', 'hostname_only'],
        apiKeyUrl: 'https://dash.apivoid.com/api-keys',
        request: apiVoidDomainReputationRequest,
        sharedApiKeyGroup: 'apivoid',
        sharedRequestGroup: 'apivoid-domain-reputation',
        responseRuleScope: 'apivoid_provider_block',
        apiVoidEngineNames: Object.freeze([].concat(engineNames || []).map(value => String(value || '')).filter(Boolean)),
        responseRules: Object.freeze((Array.isArray(responseRules) && responseRules.length > 0 ? responseRules : [
            Object.freeze({
                path: 'detected',
                operator: 'equals',
                value: true,
                result: 'MALICIOUS'
            }),
            Object.freeze({
                path: 'name',
                operator: 'exists',
                result: 'ALLOWED'
            }),
        ]).map(rule => Object.freeze({...rule}))),
        report: Object.freeze({
            type: 'none'
        }),
    });

    return Object.freeze([
        integration({
            id: 'abusix',
            aliases: ['abusix'],
            displayName: 'Abusix Guardian Intel',
            group: providerGroups.direct_integrations.id,
            icon: 'assets/providers/abusix.avif',
            enabledByDefault: false,
            lookupTarget: 'hostname',
            tags: ['api_key_required', 'hostname_only'],
            apiKeyUrl: 'https://app.abusix.com/guardian/intel',

            request: Object.freeze({
                urlTemplate: 'https://threat-intel-api.abusix.com/beta/query/{lookupValue}',
                method: 'GET',
                headers: Object.freeze([
                    Object.freeze({
                        name: 'x-api-key',
                        value: '{api_key}'
                    }),
                ]),
                bodyTemplate: '',
                contentType: 'application/json',
                timeoutMs: 7000,
            }),

            responseRules: Object.freeze([
                Object.freeze({
                    path: 'result.intent',
                    operator: 'equals',
                    value: "malicious",
                    result: 'MALICIOUS'
                }),

                Object.freeze({
                    path: 'result.intent',
                    operator: 'not_equals',
                    value: "unknown",
                    result: 'MALICIOUS'
                }),
            ]),

            report: Object.freeze({
                type: 'external_url',
                url: 'https://app.abusix.com/lookup-and-delist?q={lookupValue}',
            }),
        }),

        integration({
            id: 'lumu',
            aliases: ['maltiverse'],
            displayName: 'Lumu Maltiverse',
            group: providerGroups.direct_integrations.id,
            icon: 'assets/providers/maltiverse.png',
            enabledByDefault: false,
            lookupTarget: 'hostname',
            tags: ['api_key_required', 'hostname_only'],
            apiKeyUrl: 'https://maltiverse.com/profile/user',

            request: Object.freeze({
                urlTemplate: 'https://api.maltiverse.com/hostname/{lookupValue}',
                method: 'GET',
                headers: Object.freeze([
                    Object.freeze({
                        name: 'Authorization',
                        value: 'Bearer: {api_key}'
                    }),
                ]),
                bodyTemplate: '',
                contentType: 'application/json',
                timeoutMs: 7000,
            }),

            responseRules: Object.freeze([
                Object.freeze({
                    path: 'is_phishing',
                    operator: 'equals',
                    value: true,
                    result: 'PHISHING'
                }),
            ]),

            report: Object.freeze({
                type: 'mailto_false_positive',
                email: 'info@lumu.io',
                productName: 'Lumu Maltiverse API'
            }),
        }),

        integration({
            id: 'seclookup',
            aliases: ['secLookup'],
            displayName: 'SecLookup',
            group: providerGroups.direct_integrations.id,
            icon: 'assets/providers/seclookup.avif',
            enabledByDefault: false,
            lookupTarget: 'hostname',
            tags: ['api_key_required', 'hostname_only'],
            apiKeyUrl: 'https://seclookup.com/',

            request: Object.freeze({
                urlTemplate: 'https://api.seclookup.com/api/v1/scan/api?api_key={api_key}&domain={lookupValue}',
                method: 'GET',
                headers: [],
                bodyTemplate: '',
                contentType: 'application/json',
                timeoutMs: 7000,
            }),

            responseRules: Object.freeze([
                Object.freeze({
                    path: 'data.is_malicious',
                    operator: 'equals',
                    value: true,
                    result: 'MALICIOUS'
                }),
            ]),

            report: Object.freeze({
                type: 'mailto_false_positive',
                email: 'info@seclookup.com',
                productName: 'SecLookup API'
            }),
        }),

        integration({
            id: 'xcitium',
            aliases: ['xcitium'],
            displayName: 'Xcitium Verdict Cloud',
            group: providerGroups.direct_integrations.id,
            icon: 'assets/providers/xcitium.avif',
            enabledByDefault: false,
            lookupTarget: 'hostname',
            tags: ['api_key_required', 'hostname_only'],
            apiKeyUrl: 'https://lookup.verdict.xcitium.com/auth/profile',

            request: Object.freeze({
                urlTemplate: 'https://lookup.verdict.xcitium.com/api/v1/url/category/query?url={lookupValue}',
                method: 'GET',
                headers: Object.freeze([
                    Object.freeze({
                        name: 'X-Api-Key',
                        value: '{api_key}'
                    }),
                ]),
                bodyTemplate: '',
                contentType: 'application/json',
                timeoutMs: 7000,
            }),

            responseRules: Object.freeze([
                Object.freeze({
                    path: 'categories[*].category_id',
                    operator: 'contains',
                    value: 72,
                    result: 'MALICIOUS'
                }),

                Object.freeze({
                    path: 'categories[*].category_id',
                    operator: 'contains',
                    value: 6,
                    result: 'MALICIOUS'
                }),
            ]),

            report: Object.freeze({
                type: 'mailto_false_positive',
                email: 'support@xcitium.com',
                productName: 'Xcitium Verdict Cloud'
            }),
        }),

        metadefenderIntegration({
            id: 'metadefender-reputation',
            aliases: ['metadefender'],
            displayName: 'MetaDefender Reputation',
            providerNames: ['Offline Reputation'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'equals',
                    value: 'benign',
                    result: 'ALLOWED'
                }),

                Object.freeze({
                    path: 'assessment',
                    operator: 'equals',
                    value: 'unknown',
                    result: 'ALLOWED'
                }),

                Object.freeze({
                    path: 'assessment',
                    operator: 'equals',
                    value: 'suspicious',
                    result: 'ALLOWED'
                }),

                Object.freeze({
                    path: 'assessment',
                    operator: 'not_equals',
                    value: '',
                    result: 'MALICIOUS'
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-webroot',
            displayName: 'Webroot (MetaDefender)',
            providerNames: ['webroot.com'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'category',
                    operator: 'equals',
                    value: 'Phishing and Other Frauds',
                    result: 'PHISHING'
                }),

                Object.freeze({
                    path: 'category',
                    operator: 'equals',
                    value: 'Malware Sites',
                    result: 'MALICIOUS'
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-openphish',
            displayName: 'OpenPhish (MetaDefender)',
            providerNames: ['openphish.com'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'equals',
                    value: 'phishing',
                    result: 'PHISHING'
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-usom',
            displayName: 'USOM (MetaDefender)',
            providerNames: ['www.usom.gov.tr'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'not_equals',
                    value: '',
                    result: 'MALICIOUS'
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-team-cymru',
            displayName: 'Team Cymru (MetaDefender)',
            providerNames: ['www.team-cymru.org'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'not_equals',
                    value: '',
                    result: 'MALICIOUS'
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-abuse-ch',
            displayName: 'Abuse.ch (MetaDefender)',
            providerNames: ['urlhaus.abuse.ch'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'not_equals',
                    value: '',
                    result: 'MALICIOUS'
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-normshield',
            displayName: 'NormShield (MetaDefender)',
            providerNames: ['normshield.com'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'not_equals',
                    value: '',
                    result: 'MALICIOUS'
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-viriback',
            displayName: 'Viriback (MetaDefender)',
            providerNames: ['tracker.viriback.com'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'not_equals',
                    value: '',
                    result: 'MALICIOUS'
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-otx-alienvault',
            displayName: 'OTX AlienVault (MetaDefender)',
            providerNames: ['reputation.alienvault.com'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'not_equals',
                    value: '',
                    result: 'MALICIOUS'
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-vxvault',
            displayName: 'VXVault (MetaDefender)',
            providerNames: ['vxvault.net'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'not_equals',
                    value: '',
                    result: 'MALICIOUS'
                }),
            ]),
        }),

        apivoidIntegration({
            id: 'apivoid-apva',
            displayName: 'APVA (APIVoid)',
            engineNames: ['APVA'],
            report: Object.freeze({
                type: 'external_url',
                url: 'https://www.antiphish.org/false-positive',
            }),
        }),

        apivoidIntegration({
            id: 'apivoid-artists-against-419',
            displayName: 'Artists Against 419 (APIVoid)',
            engineNames: ['Artists Against 419'],
        }),

        apivoidIntegration({
            id: 'apivoid-bambenek-consulting',
            displayName: 'Bambenek Consulting (APIVoid)',
            engineNames: ['Bambenek Consulting'],
        }),

        apivoidIntegration({
            id: 'apivoid-cert-polska',
            displayName: 'CERT Polska (APIVoid)',
            engineNames: ['CERT Polska'],
        }),

        apivoidIntegration({
            id: 'apivoid-chongluadao',
            displayName: 'ChongLuaDao (APIVoid)',
            engineNames: ['ChongLuaDao'],
        }),

        apivoidIntegration({
            id: 'apivoid-codeesura',
            displayName: 'Codeesura (APIVoid)',
            engineNames: ['Codeesura'],
        }),

        apivoidIntegration({
            id: 'apivoid-coi-cz',
            displayName: 'COI CZ (APIVoid)',
            engineNames: ['COI CZ'],
        }),

        apivoidIntegration({
            id: 'apivoid-cryptoscamdb',
            displayName: 'CryptoScamDB (APIVoid)',
            engineNames: ['CryptoScamDB'],
        }),

        apivoidIntegration({
            id: 'apivoid-durablenapkin-scam-blocklist',
            displayName: 'DurableNapkin Scam Blocklist (APIVoid)',
            engineNames: ['DurableNapkin Scam Blocklist'],
        }),

        apivoidIntegration({
            id: 'apivoid-enkryptcom',
            displayName: 'Enkrypt.com (APIVoid)',
            engineNames: ['Enkryptcom'],
        }),

        apivoidIntegration({
            id: 'apivoid-fr-fma-blocklist',
            displayName: 'FR FMA Blocklist (APIVoid)',
            engineNames: ['FR FMA Blocklist'],
        }),

        apivoidIntegration({
            id: 'apivoid-nabp-not-recommended-sites',
            displayName: 'NABP Not Recommended Sites (APIVoid)',
            engineNames: ['NABP Not Recommended Sites'],
        }),

        apivoidIntegration({
            id: 'apivoid-petscams',
            displayName: 'PetScams (APIVoid)',
            engineNames: ['PetScams'],
        }),

        apivoidIntegration({
            id: 'apivoid-phishfort',
            displayName: 'PhishFort (APIVoid)',
            engineNames: ['PhishFort'],
        }),

        apivoidIntegration({
            id: 'apivoid-phishing-test',
            displayName: 'Phishing Test (APIVoid)',
            engineNames: ['Phishing Test'],
        }),

        apivoidIntegration({
            id: 'apivoid-phishstats',
            displayName: 'PhishStats (APIVoid)',
            engineNames: ['PhishStats'],
        }),

        apivoidIntegration({
            id: 'apivoid-phishtank',
            displayName: 'PhishTank (APIVoid)',
            engineNames: ['PhishTank'],
        }),

        apivoidIntegration({
            id: 'apivoid-phishunt',
            displayName: 'Phishunt (APIVoid)',
            engineNames: ['Phishunt'],
        }),

        apivoidIntegration({
            id: 'apivoid-polkadot',
            displayName: 'Polkadot (APIVoid)',
            engineNames: ['Polkadot'],
        }),

        apivoidIntegration({
            id: 'apivoid-rpilist-not-serious',
            displayName: 'RPiList Not Serious (APIVoid)',
            engineNames: ['RPiList Not Serious'],
        }),

        apivoidIntegration({
            id: 'apivoid-scam-test',
            displayName: 'Scam Test (APIVoid)',
            engineNames: ['Scam Test'],
        }),

        apivoidIntegration({
            id: 'apivoid-scam-directory',
            displayName: 'Scam.Directory (APIVoid)',
            engineNames: ['Scam.Directory'],
        }),

        apivoidIntegration({
            id: 'apivoid-seal',
            displayName: 'SEAL (APIVoid)',
            engineNames: ['SEAL'],
        }),

        apivoidIntegration({
            id: 'apivoid-sinkholed-domain',
            displayName: 'Sinkholed Domain (APIVoid)',
            engineNames: ['Sinkholed Domain'],
        }),

        apivoidIntegration({
            id: 'apivoid-sinkingyachts-phishing',
            displayName: 'SinkingYachts Phishing (APIVoid)',
            engineNames: ['SinkingYachts Phishing'],
        }),

        apivoidIntegration({
            id: 'apivoid-spam404',
            displayName: 'Spam404 (APIVoid)',
            engineNames: ['Spam404'],
        }),

        apivoidIntegration({
            id: 'apivoid-suspicious-hosting-ip',
            displayName: 'Suspicious Hosting IP (APIVoid)',
            engineNames: ['Suspicious Hosting IP'],
        }),

        apivoidIntegration({
            id: 'apivoid-threat-sourcing',
            displayName: 'Threat Sourcing (APIVoid)',
            engineNames: ['Threat Sourcing'],
        }),

        apivoidIntegration({
            id: 'apivoid-threatfox',
            displayName: 'ThreatFox (APIVoid)',
            engineNames: ['ThreatFox'],
        }),

        apivoidIntegration({
            id: 'apivoid-threatlog',
            displayName: 'ThreatLog (APIVoid)',
            engineNames: ['ThreatLog'],
        }),

        apivoidIntegration({
            id: 'apivoid-tweetfeed',
            displayName: 'TweetFeed (APIVoid)',
            engineNames: ['TweetFeed'],
        }),

        apivoidIntegration({
            id: 'apivoid-urlabuse',
            displayName: 'URLAbuse (APIVoid)',
            engineNames: ['URLAbuse'],
        }),

        apivoidIntegration({
            id: 'apivoid-urlquery',
            displayName: 'UrlQuery (APIVoid)',
            engineNames: ['UrlQuery'],
        }),
    ]);
})();
