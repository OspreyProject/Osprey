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

(() => {
    Object.defineProperty(globalThis, 'OspreyProxyBuiltins', {
        configurable: true,
        enumerable: true,

        get() {
            const providerGroups = globalThis.OspreyProviderGroups;
            const emptyBlockCategories = Object.freeze([]);

            const blockCategory = (key, label, tooltip, defaultEnabled) => Object.freeze({
                key,
                label,
                tooltip,
                defaultEnabled: Boolean(defaultEnabled),
            });

            const alphaMountainBlockCategories = Object.freeze([
                blockCategory('suspicious', 'blockSuspicious', 'blockSuspiciousTooltip', false),
                blockCategory('newly_registered', 'blockNewlyRegistered', 'blockNewlyRegisteredTooltip', false),
                blockCategory('dynamic_dns', 'blockDynamicDns', 'blockDynamicDnsTooltip', false),
            ]);

            const buildMonomorphicShape = def => Object.freeze({
                kind: 'proxy_builtin',
                proxyBaseUrl: 'https://api.osprey.ac',
                id: def.id,
                aliases: def.aliases || [],
                displayName: def.displayName,
                group: def.group,
                icon: def.icon || '',
                enabledByDefault: def.enabledByDefault || false,
                bypassBlockingThreshold: def.bypassBlockingThreshold || false,
                blockCategories: def.blockCategories || emptyBlockCategories,
                endpoint: def.endpoint,
                tags: def.tags || ['proxy'],
                policyKey: def.policyKey,
                report: def.report,
                lookupTarget: def.lookupTarget || 'url',
                website: def.website || '',
            });

            const builtin = def => buildMonomorphicShape(def);

            const hostnameBuiltin = def => {
                def.lookupTarget = 'hostname';
                def.tags = def.tags || ['proxy', 'hostname_only'];
                return buildMonomorphicShape(def);
            };

            const cloudflareReport = Object.freeze({
                type: 'url_template',
                template: 'https://radar.cloudflare.com/domains/feedback/{url}',
            });

            const spamhausReport = Object.freeze({
                type: 'external_url',
                url: 'https://www.spamhaus.com/abuse-ch/#contact-us',
            });

            const mailtoReport = (email, productName) => Object.freeze({
                type: 'mailto_false_positive',
                email,
                productName,
            });

            const externalUrlReport = url => Object.freeze({type: 'external_url', url});

            const builtins = Object.freeze([
                builtin({
                    id: 'alphamountain',
                    website: 'https://alphamountain.ai/?utm_source=osprey',
                    aliases: ['alphaMountain'],
                    displayName: 'AlphaMountain',
                    group: providerGroups.official_partners.id,
                    icon: 'assets/providers/alphamountain.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    blockCategories: alphaMountainBlockCategories,
                    endpoint: 'alphamountain',
                    tags: ['proxy', 'partner'],
                    policyKey: 'AlphaMountainEnabled',
                    report: externalUrlReport('https://alphamountain.freshdesk.com/support/tickets/new'),
                }),

                builtin({
                    id: 'bforeai',
                    website: 'https://bfore.ai/?utm_source=osprey',
                    aliases: ['bforeAI'],
                    displayName: 'BforeAI PreCrime',
                    group: providerGroups.official_partners.id,
                    icon: 'assets/providers/bforeai.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'bforeai',
                    tags: ['proxy', 'partner'],
                    policyKey: 'BforeAIEnabled',
                    report: externalUrlReport('https://bfore.ai/support'),
                }),

                builtin({
                    id: 'chainpatrol',
                    website: 'https://chainpatrol.io/?utm_source=osprey',
                    aliases: ['chainPatrol'],
                    displayName: 'ChainPatrol',
                    group: providerGroups.official_partners.id,
                    icon: 'assets/providers/chainpatrol.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'chainpatrol',
                    tags: ['proxy', 'partner'],
                    policyKey: 'ChainPatrolEnabled',
                    report: externalUrlReport('https://app.chainpatrol.io/dispute'),
                }),

                builtin({
                    id: 'izoologic',
                    website: 'https://izoologic.com/?utm_source=osprey',
                    aliases: ['izoologic'],
                    displayName: 'iZOOlogic',
                    group: providerGroups.official_partners.id,
                    icon: 'assets/providers/izoologic.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'izoologic',
                    tags: ['proxy', 'partner'],
                    policyKey: 'iZOOlogicEnabled',
                    report: mailtoReport('reporting.cti@izoologic.com', 'iZOOlogic GetUrlVerdict API'),
                }),

                builtin({
                    id: 'precisionsec',
                    website: 'https://precisionsec.com/?utm_source=osprey',
                    aliases: ['precisionSec'],
                    displayName: 'PrecisionSec',
                    group: providerGroups.official_partners.id,
                    icon: 'assets/providers/precisionsec.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'precisionsec',
                    tags: ['proxy', 'hostname_only', 'partner'],
                    policyKey: 'PrecisionSecEnabled',
                    report: mailtoReport('info@precisionsec.com', 'PrecisionSec Check Domain API'),
                }),

                builtin({
                    id: 'adguard-dns',
                    website: 'https://adguard-dns.io/?utm_source=osprey',
                    aliases: ['adGuardDNS'],
                    displayName: 'AdGuard DNS',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/adguard.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'adguard-dns',
                    lookupTarget: 'hostname',
                    tags: ['proxy', 'hostname_only'],
                    policyKey: 'AdGuardDNSEnabled',
                    report: mailtoReport('support@adguard.com', 'AdGuard Public DNS'),
                }),

                hostnameBuiltin({
                    id: 'aa419',
                    website: 'https://db.aa419.org/?utm_source=osprey',
                    aliases: ['aa419'],
                    displayName: 'Artists Against 419',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/aa419.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'aa419',
                    policyKey: 'AA419Enabled',
                    report: externalUrlReport('https://wiki.aa419.org/index.php/Contact_Us'),
                }),

                hostnameBuiltin({
                    id: 'cloudflare',
                    website: 'https://one.one.one.one/?utm_source=osprey',
                    aliases: ['cloudflare'],
                    displayName: 'Cloudflare',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/cloudflare.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'cloudflare',
                    policyKey: 'CloudflareEnabled',
                    report: cloudflareReport,
                }),

                hostnameBuiltin({
                    id: 'control-d',
                    website: 'https://controld.com/?utm_source=osprey',
                    aliases: ['controlD'],
                    displayName: 'Control D',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/controld.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'control-d',
                    policyKey: 'ControlDEnabled',
                    report: mailtoReport('help@controld.com', 'Control D \'no-malware-typo\' DNS'),
                }),

                hostnameBuiltin({
                    id: 'openphish',
                    website: 'https://openphish.com/?utm_source=osprey',
                    aliases: ['openPhish'],
                    displayName: 'OpenPhish',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/openphish.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'openphish',
                    policyKey: 'OpenPhishEnabled',
                    report: mailtoReport('support@openphish.com', 'OpenPhish Public List'),
                }),

                hostnameBuiltin({
                    id: 'phishdestroy',
                    website: 'https://phishdestroy.io/?utm_source=osprey',
                    aliases: ['phishDestroy'],
                    displayName: 'PhishDestroy',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/phishdestroy.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'phishdestroy',
                    policyKey: 'PhishDestroyEnabled',
                    report: externalUrlReport('https://phishdestroy.io/appeals'),
                }),

                hostnameBuiltin({
                    id: 'phishunt-io',
                    website: 'https://phishunt.io/?utm_source=osprey',
                    aliases: ['phishuntIO'],
                    displayName: 'Phishunt.io',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/phishuntio.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'phishunt-io',
                    policyKey: 'PhishuntIOEnabled',
                    report: mailtoReport('info@phishunt.io', 'Phishunt.io Feed'),
                }),

                hostnameBuiltin({
                    id: 'quad9',
                    website: 'https://quad9.net/?utm_source=osprey',
                    aliases: ['quad9'],
                    displayName: 'Quad9',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/quad9.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'quad9',
                    policyKey: 'Quad9Enabled',
                    report: externalUrlReport('https://quad9.net/support/contact'),
                }),

                hostnameBuiltin({
                    id: 'red-flag-domains',
                    website: 'https://red.flag.domains/?utm_source=osprey',
                    aliases: ['red-flag-domains'],
                    displayName: 'Red Flag Domains',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/red-flag-domains.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'red-flag-domains',
                    policyKey: 'RedFlagDomainsEnabled',
                    report: mailtoReport('hello@red.flag.domains', 'Red Flag Domains List'),
                }),

                hostnameBuiltin({
                    id: 'sinking-yachts',
                    website: 'https://sinking.yachts/?utm_source=osprey',
                    aliases: ['sinking-yachts'],
                    displayName: 'SinkingYachts',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/sinking-yachts.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'sinking-yachts',
                    policyKey: 'SinkingYachtsEnabled',
                    report: mailtoReport('sinkingyachts@gmail.com', 'SinkingYachts List'),
                }),

                hostnameBuiltin({
                    id: 'switch-ch',
                    website: 'https://www.switch.ch/en/dns-firewall/?utm_source=osprey',
                    aliases: ['switchCH'],
                    displayName: 'Switch.ch',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/switchch.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'switch-ch',
                    policyKey: 'SwitchCHEnabled',
                    report: mailtoReport('dnsfirewall@switch.ch', 'Switch.ch Public DNS'),
                }),

                hostnameBuiltin({
                    id: 'threatfox',
                    website: 'https://threatfox.abuse.ch/?utm_source=osprey',
                    aliases: ['threatfox'],
                    displayName: 'THREATfox',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/urlhaus.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'threatfox',
                    policyKey: 'THREATfoxEnabled',
                    report: spamhausReport,
                }),

                hostnameBuiltin({
                    id: 'urlhaus',
                    website: 'https://urlhaus.abuse.ch/?utm_source=osprey',
                    aliases: ['urlhaus'],
                    displayName: 'URLhaus',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/urlhaus.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'urlhaus',
                    policyKey: 'URLhausEnabled',
                    report: spamhausReport,
                }),

                hostnameBuiltin({
                    id: 'urlabuse',
                    website: 'https://urlabuse.com/?utm_source=osprey',
                    aliases: ['urlabuse'],
                    displayName: 'URLAbuse',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/urlabuse.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'urlabuse',
                    policyKey: 'URLAbuseEnabled',
                    report: mailtoReport('info@urlabuse.com', 'URLAbuse Lookup API'),
                }),

                hostnameBuiltin({
                    id: 'validin',
                    website: 'https://validin.com/?utm_source=osprey',
                    aliases: ['validin'],
                    displayName: 'Validin',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/validin.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'validin',
                    policyKey: 'ValidinEnabled',
                    report: mailtoReport('lets.talk@validin.com', 'Validin Public Phish Feeds'),
                }),
            ]);

            Object.defineProperty(globalThis, 'OspreyProxyBuiltins', {
                value: builtins,
                configurable: false,
                writable: false,
                enumerable: true,
            });
            return builtins;
        },
    });
})();
