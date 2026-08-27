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

(() => {
    const browserAPI = globalThis.OspreyBrowserAPI;

    const setText = (id, value) => {
        const element = document.getElementById(id);

        if (element !== null) {
            element.textContent = value;
        }
    };

    const closeTab = () => {
        const tabs = browserAPI?.api?.tabs;

        if (tabs && typeof tabs.getCurrent === 'function') {
            browserAPI.withCallback(tabs.getCurrent, tabs)
                .then(tab => {
                    if (tab && typeof tab.id === 'number') {
                        return browserAPI.withCallback(tabs.remove, tabs, [tab.id]);
                    }
                    globalThis.close();
                    return undefined;
                })
                .catch(error => {
                    console.error('WelcomePage failed to close its tab', error);
                    globalThis.close();
                });
            return;
        }

        globalThis.close();
    };

    const initialize = () => {
        document.title = LangUtil.translate('welcomeTitle');
        LangUtil.applyLogoAlt(document.getElementById('logo'));
        LangUtil.applyLogoAlt(document.getElementById('logoLight'));

        const translatedIds = [
            'welcomeTitle',
            'welcomeIntro',
            'welcomeWhyHeading',
            'welcomeWhyBody',
            'welcomeHowHeading',
            'welcomeHowStep1',
            'welcomeHowStep2',
            'welcomeHowStep3',
            'welcomeSafeHeading',
            'welcomeSafeBody',
            'welcomeIconHeading',
            'welcomeIconBody',
        ];

        for (const id of translatedIds) {
            setText(id, LangUtil.translate(id));
        }

        setText('previewTitle', LangUtil.WARNING_TITLE);
        setText('previewText', LangUtil.RECOMMENDATION);
        setText('previewBack', LangUtil.BACK_BUTTON);
        setText('doneButton', LangUtil.translate('welcomeDoneButton'));
        setText('learnMoreLink', LangUtil.translate('welcomeLearnMore'));

        const preview = document.getElementById('warningPreview');

        if (preview !== null) {
            preview.setAttribute('aria-label', LangUtil.translate('welcomeWarningPreviewAlt'));
        }

        const doneButton = document.getElementById('doneButton');

        if (doneButton !== null) {
            doneButton.onclick = closeTab;
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize, {once: true});
    } else {
        initialize();
    }
})();
