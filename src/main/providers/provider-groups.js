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

globalThis.OspreyProviderGroups = Object.freeze({
    official_partners: Object.freeze({
        id: 'official_partners',
        title: 'Official Partners',
        order: 10
    }),

    security_filters: Object.freeze({
        id: 'security_filters',
        title: 'Security Filters',
        order: 20
    }),

    adult_content_filters: Object.freeze({
        id: 'adult_content_filters',
        title: 'Adult Content Filters',
        order: 30
    }),

    feeds: Object.freeze({
        id: 'feeds',
        title: 'Feeds',
        order: 40
    }),

    direct_integrations: Object.freeze({
        id: 'direct_integrations',
        title: 'Direct Integrations',
        order: 50
    }),

    custom_providers: Object.freeze({
        id: 'custom_providers',
        title: 'Custom Providers',
        order: 60
    }),
});
