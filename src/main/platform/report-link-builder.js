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

globalThis.OspreyReportLinkBuilder = (() => {
    const mailtoPrefix = 'mailto:';
    const mailtoSubject = '?subject=False%20Positive&body=Hello%2C%0A%0AI%20would%20like%20to%20report%20a%20false%20positive.%0A%0AProduct%3A%20';
    const mailtoURL = '%0AURL%3A%20';
    const mailtoSuffix = '%20%28or%20the%20hostname%20itself%29%0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0ASent%20with%20Osprey%20Browser%20Protection%0AWebsite%3A%20https%3A%2F%2Fosprey.ac';
    const defaultProviderName = 'Osprey%20Provider';

    let cachedRawUrl = '';
    let cachedEncodedUrl = '';

    const getEncodedUrl = rawUrl => {
        if (!rawUrl) {
            return '';
        }

        if (rawUrl === cachedRawUrl) {
            return cachedEncodedUrl;
        }

        cachedRawUrl = rawUrl;
        cachedEncodedUrl = encodeURIComponent(rawUrl);
        return cachedEncodedUrl;
    };

    const build = (template, context) => {
        if (!template || typeof template !== 'object' || !template.type) {
            console.warn('OspreyReportLinkBuilder.build received an invalid report template');
            return null;
        }

        switch (template.type) {
            case 'external_url':
                return template.url || null;

            case 'url_template':
                const tmpl = template.template || '';

                if (!tmpl) {
                    return '';
                }

                if (!tmpl.includes('{url}')) {
                    return tmpl;
                }
                return tmpl.replaceAll('{url}', getEncodedUrl(context?.blockedUrl || ''));

            case 'mailto_false_positive':
                const encodedUrl = getEncodedUrl(context?.blockedUrl || '');
                let prodName = defaultProviderName;

                if (template.productName && template.productName !== 'Osprey Provider') {
                    prodName = encodeURIComponent(template.productName);
                }
                return mailtoPrefix + (template.email || '') + mailtoSubject + prodName + mailtoURL + encodedUrl + mailtoSuffix;

            default:
                console.warn(`OspreyReportLinkBuilder encountered unsupported template type '${template.type}'`);
                return null;
        }
    };

    return Object.freeze({
        build,
    });
})();
