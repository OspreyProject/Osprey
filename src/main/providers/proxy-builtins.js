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

            const openDnsReport = Object.freeze({
                type: 'external_url',
                url: 'https://talosintelligence.com/reputation_center/web_reputation',
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
                    displayName: 'AlphaMountain Web Protection',
                    group: providerGroups.official_partners.id,
                    icon: 'assets/providers/alphamountain.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'alphamountain',
                    tags: ['proxy', 'partner'],
                    policyKey: 'AlphaMountainEnabled',
                    report: externalUrlReport('https://alphamountain.freshdesk.com/support/tickets/new'),
                }),

                builtin({
                    id: 'chainpatrol',
                    website: 'https://chainpatrol.io/?utm_source=osprey',
                    aliases: ['chainPatrol'],
                    displayName: 'ChainPatrol Web Protection',
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
                    id: 'precisionsec',
                    website: 'https://precisionsec.com/?utm_source=osprey',
                    aliases: ['precisionSec'],
                    displayName: 'PrecisionSec Web Protection',
                    group: providerGroups.official_partners.id,
                    icon: 'assets/providers/precisionsec.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'precisionsec',
                    tags: ['proxy', 'hostname_only', 'partner'],
                    policyKey: 'PrecisionSecEnabled',
                    report: mailtoReport('info@precisionsec.com', 'PrecisionSec Web Protection'),
                }),

                builtin({
                    id: 'adguard-security',
                    website: 'https://adguard-dns.io/?utm_source=osprey',
                    aliases: ['adGuardSecurity'],
                    displayName: 'AdGuard Security DNS',
                    group: providerGroups.official_partners.id,
                    icon: 'assets/providers/adguard.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'adguard-security',
                    lookupTarget: 'hostname',
                    tags: ['proxy', 'hostname_only'],
                    policyKey: 'AdGuardSecurityEnabled',
                    report: mailtoReport('support@adguard.com', 'AdGuard Public DNS'),
                }),

                hostnameBuiltin({
                    id: 'cleanbrowsing-security',
                    website: 'https://cleanbrowsing.org/?utm_source=osprey',
                    aliases: ['cleanBrowsingSecurity'],
                    displayName: 'CleanBrowsing Security DNS',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/cleanbrowsing.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'cleanbrowsing-security',
                    policyKey: 'CleanBrowsingSecurityEnabled',
                    report: mailtoReport('support@cleanbrowsing.org', 'CleanBrowsing Security Filter'),
                }),

                hostnameBuiltin({
                    id: 'cloudflare-security',
                    website: 'https://one.one.one.one/?utm_source=osprey',
                    aliases: ['cloudflareSecurity'],
                    displayName: 'Cloudflare Security DNS',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/cloudflare.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'cloudflare-security',
                    policyKey: 'CloudflareSecurityEnabled',
                    report: cloudflareReport,
                }),

                hostnameBuiltin({
                    id: 'controld-security',
                    website: 'https://controld.com/?utm_source=osprey',
                    aliases: ['controlDSecurity'],
                    displayName: 'Control D Security DNS',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/controld.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'controld-security',
                    policyKey: 'ControlDSecurityEnabled',
                    report: mailtoReport('help@controld.com', 'Control D Security DNS'),
                }),

                hostnameBuiltin({
                    id: 'opendns-security',
                    website: 'https://www.opendns.com/?utm_source=osprey',
                    aliases: ['openDNSSecurity'],
                    displayName: 'OpenDNS Security DNS',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/opendns.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'opendns-security',
                    policyKey: 'OpenDNSSecurityEnabled',
                    report: openDnsReport,
                }),

                hostnameBuiltin({
                    id: 'quad9',
                    website: 'https://quad9.net/?utm_source=osprey',
                    aliases: ['quad9'],
                    displayName: 'Quad9 Security DNS',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/quad9.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'quad9',
                    policyKey: 'Quad9Enabled',
                    report: externalUrlReport('https://quad9.net/support/contact'),
                }),

                hostnameBuiltin({
                    id: 'switch-ch',
                    website: 'https://www.switch.ch/?utm_source=osprey',
                    aliases: ['switchCH'],
                    displayName: 'Switch.ch Security DNS',
                    group: providerGroups.security_filters.id,
                    icon: 'assets/providers/switchch.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'switch-ch',
                    policyKey: 'SwitchCHEnabled',
                    report: mailtoReport('dnsfirewall@switch.ch', 'Switch.ch Public DNS'),
                }),

                hostnameBuiltin({
                    id: 'openphish',
                    website: 'https://openphish.com/?utm_source=osprey',
                    aliases: ['openPhish'],
                    displayName: 'OpenPhish List',
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
                    displayName: 'PhishDestroy List',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/phishdestroy.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: false, // keep this 'false'
                    endpoint: 'phishdestroy',
                    policyKey: 'PhishDestroyEnabled',
                    report: externalUrlReport('https://phishdestroy.io/appeals'),
                }),

                hostnameBuiltin({
                    id: 'phishing-database',
                    website: 'https://github.com/Phishing-Database/Phishing.Database/?utm_source=osprey',
                    aliases: ['phishingDatabase'],
                    displayName: 'Phishing.Database List',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/phishingdatabase.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'phishing-database',
                    policyKey: 'PhishingDatabaseEnabled',
                    report: mailtoReport('support@phish.co.za', 'Phishing.Database (ACTIVE list)'),
                }),

                hostnameBuiltin({
                    id: 'phishunt-io',
                    website: 'https://phishunt.io/?utm_source=osprey',
                    aliases: ['phishuntIO'],
                    displayName: 'Phishunt.io List',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/phishuntio.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'phishunt-io',
                    policyKey: 'PhishuntIOEnabled',
                    report: mailtoReport('info@phishunt.io', 'Phishunt.io Feed'),
                }),

                hostnameBuiltin({
                    id: 'red-flag-domains',
                    website: 'https://red.flag.domains/?utm_source=osprey',
                    aliases: ['red-flag-domains'],
                    displayName: 'Red Flag Domains List',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/red-flag-domains.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'red-flag-domains',
                    policyKey: 'RedFlagDomainsEnabled',
                    report: mailtoReport('hello@red.flag.domains', 'Red Flag Domains List'),
                }),

                hostnameBuiltin({
                    id: 'sinking-yachts',
                    website: 'https://red.flag.domains/?utm_source=osprey',
                    aliases: ['sinking-yachts'],
                    displayName: 'SinkingYachts List',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/sinking-yachts.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'sinking-yachts',
                    policyKey: 'SinkingYachtsEnabled',
                    report: mailtoReport('sinkingyachts@gmail.com', 'SinkingYachts List'),
                }),

                hostnameBuiltin({
                    id: 'threatfox',
                    website: 'https://threatfox.abuse.ch/?utm_source=osprey',
                    aliases: ['threatfox'],
                    displayName: 'THREATfox List',
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
                    displayName: 'URLhaus List',
                    group: providerGroups.feeds.id,
                    icon: 'assets/providers/urlhaus.avif',
                    enabledByDefault: true,
                    bypassBlockingThreshold: true,
                    endpoint: 'urlhaus',
                    policyKey: 'URLhausEnabled',
                    report: spamhausReport,
                }),

                hostnameBuiltin({
                    id: 'validin',
                    website: 'https://validin.com/?utm_source=osprey',
                    aliases: ['validin'],
                    displayName: 'Validin List',
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
