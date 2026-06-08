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

globalThis.OspreyDirectIntegrations = (() => {
    const providerGroups = globalThis.OspreyProviderGroups;

    const metaDefenderApiRequest = Object.freeze({
        urlTemplate: 'https://api.metadefender.com/v4/url',
        method: 'POST',
        headers: Object.freeze([
            Object.freeze({
                name: 'apikey',
                value: '{api_key}',
            }),
        ]),
        bodyTemplate: '{"url": ["{url}"]}',
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

    const metadefenderIntegration = ({
                                         id,
                                         displayName,
                                         aliases = [],
                                         providerNames,
                                         responseRules,
                                         website = 'https://www.metadefender.com/?utm_source=osprey',
                                     }) => integration({
        id,
        aliases,
        displayName,
        group: providerGroups.direct_integrations.id,
        icon: 'assets/providers/metadefender.png',
        enabledByDefault: false,
        lookupTarget: 'url',
        tags: ['api_key_required'],
        apiKeyUrl: 'https://metadefender.com/',
        website,
        request: metaDefenderApiRequest,
        sharedApiKeyGroup: 'metadefender',
        sharedRequestGroup: 'metadefender-url-reputation',
        responseRuleScope: 'metadefender_provider_block',
        metaDefenderProviderNames: Object.freeze([providerNames || []].flat().map(value => String(value || '')).filter(Boolean)),
        responseRules: Object.freeze((Array.isArray(responseRules) && responseRules.length > 0 ? responseRules : [
            Object.freeze({
                path: 'provider',
                operator: 'exists',
                result: 'ALLOWED',
            }),
        ]).map(rule => Object.freeze({...rule}))),

        report: Object.freeze({
            type: 'none',
        }),
    });

    return Object.freeze([
        metadefenderIntegration({
            id: 'metadefender-reputation',
            website: 'https://www.metadefender.com/?utm_source=osprey',
            aliases: ['metadefender'],
            displayName: 'MetaDefender Reputation',
            providerNames: ['Offline Reputation'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'assessment',
                    operator: 'equals',
                    value: 'benign',
                    result: 'ALLOWED',
                }),

                Object.freeze({
                    path: 'assessment',
                    operator: 'equals',
                    value: 'unknown',
                    result: 'ALLOWED',
                }),

                Object.freeze({
                    path: 'assessment',
                    operator: 'equals',
                    value: 'suspicious',
                    result: 'ALLOWED',
                }),

                Object.freeze({
                    path: 'assessment',
                    operator: 'not_equals',
                    value: '',
                    result: 'MALICIOUS',
                }),
            ]),
        }),

        metadefenderIntegration({
            id: 'metadefender-webroot',
            website: 'https://www.metadefender.com/?utm_source=osprey',
            displayName: 'Webroot (MetaDefender)',
            providerNames: ['Webroot'],
            responseRules: Object.freeze([
                Object.freeze({
                    path: 'category',
                    operator: 'equals',
                    value: 'Phishing and Other Frauds',
                    result: 'PHISHING',
                }),

                Object.freeze({
                    path: 'category',
                    operator: 'equals',
                    value: 'Malware Sites',
                    result: 'MALICIOUS',
                }),
            ]),
        }),
    ]);
})();
