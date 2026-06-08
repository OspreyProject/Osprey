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

globalThis.OspreyRequestBuilder = (() => {
    const urlService = globalThis.OspreyUrlService;

    const templateRegex = /\{(url|hostname|lookupValue|lookup_value|apiKey|api_key)}/g;

    const proxyHeaders = Object.freeze({
        'Content-Type': 'application/json'
    });

    const replaceTemplate = (template, urlVal, hostnameVal, lookupVal, apiKeyVal, encoded = false) => {
        if (!template) {
            return '';
        }

        const strTemp = String(template);

        if (strTemp.indexOf('{') === -1) {
            return strTemp;
        }

        return strTemp.replace(templateRegex, (_, key) => {
            let val;

            switch (key) {
                case 'url':
                    val = urlVal;
                    break;

                case 'hostname':
                    val = hostnameVal;
                    break;

                case 'lookupValue':
                case 'lookup_value':
                    val = lookupVal;
                    break;

                case 'apiKey':
                case 'api_key':
                    val = apiKeyVal;
                    break;
            }
            return encoded ? encodeURIComponent(val) : String(val);
        });
    };

    const buildProxyRequest = (provider, url) => {
        const base = String(provider.proxyBaseUrl || '');
        const end = String(provider.endpoint || '');

        let baseLen = base.length;

        while (baseLen > 0 && base.codePointAt(baseLen - 1) === 47) {
            baseLen--;
        }

        let endStart = 0;
        const endLen = end.length;

        while (endStart < endLen && end.codePointAt(endStart) === 47) {
            endStart++;
        }

        const proxyUrl = (baseLen === base.length ? base : base.slice(0, baseLen)) + '/' +
            (endStart === 0 ? end : end.slice(endStart));

        return {
            url: proxyUrl,
            options: {
                method: 'POST',
                headers: proxyHeaders,
                body: JSON.stringify({
                    url: urlService.normalizeUrl(url)
                }),
            },
            timeoutMs: 7000,
            lookupKey: urlService.lookupValueForTarget(url, provider.lookupTarget),
        };
    };

    const buildDirectRequest = (provider, url, apiKey = '') => {
        const parsed = urlService.parseHttpUrl(url);

        if (!parsed) {
            console.warn(`OspreyRequestBuilder rejected an invalid direct request URL for provider '${provider?.id || 'unknown'}'`);
            throw new Error('Invalid URL for direct request');
        }

        const request = provider.request || {};
        const normUrl = urlService.normalizeUrl(parsed);
        const hostname = parsed.hostname;
        const lookupValue = urlService.lookupValueForTarget(parsed, provider.lookupTarget || 'url');

        const reqHeaders = request.headers;
        const headers = {};

        if (reqHeaders) {
            for (const element of reqHeaders) {
                const header = element;

                if (header?.name) {
                    headers[header.name] = replaceTemplate(header.value, normUrl, hostname, lookupValue, apiKey, false);
                }
            }
        }

        let method = 'GET';

        if (request.method) {
            const m = String(request.method);

            if (m === 'POST' || m === 'post' || m.toUpperCase() === 'POST') {
                method = 'POST';
            }
        }

        if (method === 'POST' && !headers['Content-Type']) {
            headers['Content-Type'] = request.contentType || 'application/json';
        }

        let timeoutMs = Number(request.timeoutMs);

        if (!(timeoutMs > 0)) {
            timeoutMs = 7000;
        }

        return {
            url: replaceTemplate(request.urlTemplate, normUrl, hostname, lookupValue, apiKey, true),
            options: {
                method,
                headers,
                body: method === 'POST' ? replaceTemplate(request.bodyTemplate, normUrl, hostname, lookupValue, apiKey, false) : undefined,
            },
            timeoutMs,
            lookupKey: lookupValue,
        };
    };

    const buildRequest = (provider, url, providerState = {}) =>
        provider.kind === 'proxy_builtin' ?
            buildProxyRequest(provider, url) :
            buildDirectRequest(provider, url, providerState.apiKey || '');

    return Object.freeze({
        buildRequest,
    });
})();
