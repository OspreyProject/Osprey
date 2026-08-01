/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
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

globalThis.OspreyAboutPage = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const formHelpers = globalThis.OspreyFormHelpers;

    const links = Object.freeze([
        {
            labelKey: 'aboutChangelog',
            url: 'https://github.com/OspreyProject/Osprey/releases',
        },
        {
            labelKey: 'aboutGithub',
            url: 'https://github.com/OspreyProject/Osprey',
        },
        {
            labelKey: 'aboutWebsite',
            url: 'https://osprey.ac',
        },
        {
            labelKey: 'aboutPrivacy',
            url: 'https://osprey.ac/privacy',
        },
        {
            labelKey: 'aboutTerms',
            url: 'https://osprey.ac/terms',
        },
    ]);

    let cachedContainer = null;

    const resolveContainer = () => {
        if (!cachedContainer?.isConnected) {
            cachedContainer = document.getElementById('aboutList');
        }
        return cachedContainer;
    };

    const getVersion = () => {
        try {
            return browserAPI.api?.runtime.getManifest().version || '';
        } catch (error) {
            console.error('AboutPage failed to read the extension version', error);
            return '';
        }
    };

    const buildInfo = () => formHelpers.createElement('div', {
            className: 'about-info',
        },

        formHelpers.createElement('p', {
            className: 'about-app-name',
            textContent: LangUtil.TITLE,
        }),

        formHelpers.createElement('p', {
            className: 'about-meta',
            textContent: LangUtil.format('aboutVersion', [getVersion()]),
        }),

        formHelpers.createElement('br'),

        formHelpers.createElement('p', {
            className: 'about-meta',
            textContent: LangUtil.ABOUT_COPYRIGHT,
        }),

        formHelpers.createElement('p', {
            className: 'about-meta',
            textContent: LangUtil.ABOUT_RIGHTS,
        }),

        formHelpers.createElement('p', {
            className: 'about-meta',
            textContent: LangUtil.ABOUT_LICENSE,
        }),
    );

    const buildLinks = () => {
        const wrap = formHelpers.createElement('div', {
            className: 'about-links'
        });

        for (let i = 0, len = links.length; i < len; i++) {
            const link = links[i];

            wrap.appendChild(formHelpers.createElement('a', {
                className: 'about-link',
                href: link.url,
                target: '_blank',
                rel: 'noopener noreferrer',
                textContent: LangUtil.format(link.labelKey),
            }));
        }
        return wrap;
    };

    const render = () => {
        const container = resolveContainer();

        if (!container) {
            console.warn("'aboutList' not found in SettingsPage DOM.");
            return;
        }

        const wrapper = formHelpers.createElement('div', {
                className: 'about'
            },

            buildInfo(),
            buildLinks());

        container.replaceChildren(wrapper);
    };

    return Object.freeze({
        render,
    });
})();
