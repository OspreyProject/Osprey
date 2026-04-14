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

globalThis.OspreyReportLinkBuilder = (() => {
    const build = (template, context) => {
        if (!template || typeof template !== 'object') {
            console.warn('OspreyReportLinkBuilder.build received an invalid report template');
            return null;
        }

        const blockedUrl = context?.blockedUrl || '';
        const encodedUrl = encodeURIComponent(blockedUrl);
        const encodedResult = encodeURIComponent(context?.resultLabelEnglish || '');

        switch (template.type) {
            case 'none':
            case '':
            case null:
            case undefined:
                return null;

            case 'external_url':
                return template.url || null;

            case 'url_template':
                return String(template.template || '')
                    .replaceAll('{url}', encodedUrl)
                    .replaceAll('{result}', encodedResult);

            case 'mailto_false_positive':
                return `mailto:${template.email}?subject=False%20Positive
                &body=Hello%2C%0A%0AI%20would%20like%20to%20report%20a%20false%20positive.
                %0A%0AProduct%3A%20${encodeURIComponent(template.productName || 'Osprey Provider')}
                %0AURL%3A%20${encodedUrl}%20%28or%20the%20hostname%20itself%29%0ADetected%20as%3A%20${encodedResult}
                %0A%0AI%20believe%20this%20website%20is%20legitimate.%0A%0ASent%20with%20Osprey%20Browser%20Protection
                %0AWebsite%3A%20https%3A%2F%2Fosprey.ac`;

            default:
                console.warn(`OspreyReportLinkBuilder encountered unsupported template type '${template.type}'`);
                return null;
        }
    };

    // Public API
    return Object.freeze({
        build
    });
})();
