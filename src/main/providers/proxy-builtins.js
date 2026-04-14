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

globalThis.OspreyProxyBuiltins = (() => {
    // Global variables
    const providerGroups = globalThis.OspreyProviderGroups;

    const builtin = definition => Object.freeze({
        kind: 'proxy_builtin',
        proxyBaseUrl: 'https://api.osprey.ac',
        enabledByDefault: false,
        aliases: [],
        tags: ['proxy'],
        lookupTarget: 'url',
        icon: '',
        ...definition,
    });

    const hostnameBuiltin = definition => builtin({
        lookupTarget: 'hostname',
        tags: ['proxy', 'hostname_only'],
        ...definition,
    });

    const adultFilterHostnameBuiltin = definition => hostnameBuiltin({
        tags: ['proxy', 'hostname_only', 'adult_filter'],
        ...definition,
    });

    const mailtoFalsePositiveReport = (email, productName) => Object.freeze({
        type: 'mailto_false_positive',
        email,
        productName,
    });

    const externalUrlReport = url => Object.freeze({type: 'external_url', url});
    const urlTemplateReport = template => Object.freeze({type: 'url_template', template});

    return Object.freeze([
        builtin({
            id: 'adguard-security',
            aliases: ['adGuardSecurity'],
            displayName: 'AdGuard Security DNS',
            group: providerGroups.official_partners.id,
            icon: 'assets/providers/adguard.avif',
            enabledByDefault: true,
            endpoint: 'adguard-security',
            lookupTarget: 'hostname',
            tags: ['proxy', 'partner', 'hostname_only'],
            policyKey: 'AdGuardSecurityEnabled',
            report: mailtoFalsePositiveReport('support@adguard.com', 'AdGuard Public DNS'),
        }),

        builtin({
            id: 'adguard-family',
            aliases: ['adGuardFamily'],
            displayName: 'AdGuard Family DNS',
            group: providerGroups.adult_content_filters.id,
            icon: 'assets/providers/adguard.avif',
            endpoint: 'adguard-family',
            lookupTarget: 'hostname',
            tags: ['proxy', 'partner', 'hostname_only', 'adult_filter'],
            policyKey: 'AdGuardFamilyEnabled',
            report: mailtoFalsePositiveReport('support@adguard.com', 'AdGuard Family DNS'),
        }),

        builtin({
            id: 'alphamountain',
            aliases: ['alphaMountain'],
            displayName: 'AlphaMountain Web Protection',
            group: providerGroups.official_partners.id,
            icon: 'assets/providers/alphamountain.avif',
            enabledByDefault: true,
            bypassBlockingThreshold: true,
            endpoint: 'alphamountain',
            tags: ['proxy', 'partner'],
            policyKey: 'AlphaMountainEnabled',
            report: externalUrlReport('https://alphamountain.freshdesk.com/support/tickets/new'),
        }),

        builtin({
            id: 'chainpatrol',
            aliases: ['chainPatrol'],
            displayName: 'ChainPatrol Web Protection',
            group: providerGroups.official_partners.id,
            icon: 'assets/providers/chainpatrol.avif',
            enabledByDefault: true,
            endpoint: 'chainpatrol',
            tags: ['proxy', 'partner'],
            policyKey: 'ChainPatrolEnabled',
            report: externalUrlReport('https://app.chainpatrol.io/dispute'),
        }),

        builtin({
            id: 'precisionsec',
            aliases: ['precisionSec'],
            displayName: 'PrecisionSec Web Protection',
            group: providerGroups.official_partners.id,
            icon: 'assets/providers/precisionsec.avif',
            enabledByDefault: true,
            endpoint: 'precisionsec',
            tags: ['proxy', 'hostname_only', 'partner'],
            policyKey: 'PrecisionSecEnabled',
            report: mailtoFalsePositiveReport('info@precisionsec.com', 'PrecisionSec Web Protection'),
        }),

        hostnameBuiltin({
            id: 'certee-security',
            aliases: ['certEESecurity'],
            displayName: 'CERT-EE Security DNS',
            group: providerGroups.security_filters.id,
            icon: 'assets/providers/cert-ee.avif',
            enabledByDefault: true,
            endpoint: 'cert-ee',
            policyKey: 'CERTEEEnabled',
            report: mailtoFalsePositiveReport('ria@ria.ee', 'CERT-EE DNS'),
        }),

        hostnameBuiltin({
            id: 'cleanbrowsing-security',
            aliases: ['cleanBrowsingSecurity'],
            displayName: 'CleanBrowsing Security DNS',
            group: providerGroups.security_filters.id,
            icon: 'assets/providers/cleanbrowsing.avif',
            enabledByDefault: true,
            endpoint: 'cleanbrowsing-security',
            policyKey: 'CleanBrowsingSecurityEnabled',
            report: mailtoFalsePositiveReport('support@cleanbrowsing.org', 'CleanBrowsing Security Filter'),
        }),

        adultFilterHostnameBuiltin({
            id: 'cleanbrowsing-family',
            aliases: ['cleanBrowsingFamily'],
            displayName: 'CleanBrowsing Family DNS',
            group: providerGroups.adult_content_filters.id,
            icon: 'assets/providers/cleanbrowsing.avif',
            endpoint: 'cleanbrowsing-family',
            policyKey: 'CleanBrowsingFamilyEnabled',
            report: mailtoFalsePositiveReport('support@cleanbrowsing.org', 'CleanBrowsing Adult Filter'),
        }),

        hostnameBuiltin({
            id: 'cloudflare-security',
            aliases: ['cloudflareSecurity'],
            displayName: 'Cloudflare Security DNS',
            group: providerGroups.security_filters.id,
            icon: 'assets/providers/cloudflare.avif',
            enabledByDefault: true,
            endpoint: 'cloudflare-security',
            policyKey: 'CloudflareSecurityEnabled',
            report: urlTemplateReport('https://radar.cloudflare.com/domains/feedback/{url}'),
        }),

        adultFilterHostnameBuiltin({
            id: 'cloudflare-family',
            aliases: ['cloudflareFamily'],
            displayName: 'Cloudflare Family DNS',
            group: providerGroups.adult_content_filters.id,
            icon: 'assets/providers/cloudflare.avif',
            endpoint: 'cloudflare-family',
            policyKey: 'CloudflareFamilyEnabled',
            report: urlTemplateReport('https://radar.cloudflare.com/domains/feedback/{url}'),
        }),

        hostnameBuiltin({
            id: 'controld-security',
            aliases: ['controlDSecurity'],
            displayName: 'Control D Security DNS',
            group: providerGroups.security_filters.id,
            icon: 'assets/providers/controld.avif',
            enabledByDefault: true,
            endpoint: 'controld-security',
            policyKey: 'ControlDSecurityEnabled',
            report: mailtoFalsePositiveReport('help@controld.com', 'Control D Security DNS'),
        }),

        adultFilterHostnameBuiltin({
            id: 'controld-family',
            aliases: ['controlDFamily'],
            displayName: 'Control D Family DNS',
            group: providerGroups.adult_content_filters.id,
            icon: 'assets/providers/controld.avif',
            endpoint: 'controld-family',
            policyKey: 'ControlDFamilyEnabled',
            report: mailtoFalsePositiveReport('help@controld.com', 'Control D Family DNS'),
        }),

        hostnameBuiltin({
            id: 'opendns-security',
            aliases: ['openDNSSecurity'],
            displayName: 'OpenDNS Security DNS',
            group: providerGroups.security_filters.id,
            icon: 'assets/providers/opendns.avif',
            enabledByDefault: true,
            endpoint: 'opendns-security',
            policyKey: 'OpenDNSSecurityEnabled',
            report: externalUrlReport('https://talosintelligence.com/reputation_center/web_reputation'),
        }),

        adultFilterHostnameBuiltin({
            id: 'opendns-family',
            aliases: ['openDNSFamily'],
            displayName: 'OpenDNS Family DNS',
            group: providerGroups.adult_content_filters.id,
            icon: 'assets/providers/opendns.avif',
            endpoint: 'opendns-family',
            policyKey: 'OpenDNSFamilyEnabled',
            report: externalUrlReport('https://talosintelligence.com/reputation_center/web_reputation'),
        }),

        hostnameBuiltin({
            id: 'phishdestroy',
            aliases: ['phishDestroy'],
            displayName: 'PhishDestroy Feed',
            group: providerGroups.feeds.id,
            icon: 'assets/providers/phishdestroy.avif',
            enabledByDefault: true,
            endpoint: 'phishdestroy',
            policyKey: 'PhishDestroyEnabled',
            report: externalUrlReport('https://phishdestroy.io/appeals'),
        }),

        hostnameBuiltin({
            id: 'phishing-database',
            aliases: ['phishingDatabase'],
            displayName: 'Phishing.Database Feed',
            group: providerGroups.feeds.id,
            icon: 'assets/providers/phishingdatabase.avif',
            enabledByDefault: true,
            endpoint: 'phishing-database',
            policyKey: 'PhishingDatabaseEnabled',
            report: mailtoFalsePositiveReport('support@phish.co.za', 'Phishing.Database'),
        }),

        hostnameBuiltin({
            id: 'quad9',
            aliases: ['quad9'],
            displayName: 'Quad9 Security DNS',
            group: providerGroups.security_filters.id,
            icon: 'assets/providers/quad9.avif',
            enabledByDefault: true,
            endpoint: 'quad9',
            policyKey: 'Quad9Enabled',
            report: externalUrlReport('https://quad9.net/support/contact'),
        }),

        hostnameBuiltin({
            id: 'switch-ch',
            aliases: ['switchCH'],
            displayName: 'Switch.ch Security DNS',
            group: providerGroups.security_filters.id,
            icon: 'assets/providers/switchch.avif',
            enabledByDefault: true,
            endpoint: 'switch-ch',
            policyKey: 'SwitchCHEnabled',
            report: mailtoFalsePositiveReport('dnsfirewall@switch.ch', 'Switch.ch Public DNS'),
        }),
    ]);
})();
