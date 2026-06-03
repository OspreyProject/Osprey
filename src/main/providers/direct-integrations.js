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
        urlTemplate: 'https://api.metadefender.com/v4/url',
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
        metaDefenderProviderNames: Object.freeze([providerNames || []].flat().map(value => String(value || '')).filter(Boolean)),
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

    return Object.freeze([
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
    ]);
})();
