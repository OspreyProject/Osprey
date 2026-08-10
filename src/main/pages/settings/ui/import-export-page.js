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

globalThis.OspreyImportExportPage = (() => {
    const formHelpers = globalThis.OspreyFormHelpers;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const toast = globalThis.OspreyToast;

    const envelopeType = 'osprey-settings';
    const maxImportBytes = 1024 * 1024;

    let currentRuntime = null;
    let isBusy = false;

    const isLocked = () => {
        const app = currentRuntime?.effectiveState?.app;
        return Boolean(app?.lockSettings);
    };

    const buildFileName = () => {
        const now = new Date();
        const pad = value => String(value).padStart(2, '0');
        const stamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
        return `osprey-settings-${stamp}.json`;
    };

    const triggerDownload = (text, fileName) => {
        const blob = new Blob([text], {type: 'application/json'});
        const url = URL.createObjectURL(blob);

        const anchor = formHelpers.createElement('a', {
            href: url,
        });

        anchor.download = fileName;
        anchor.rel = 'noopener';
        anchor.style.display = 'none';

        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();

        globalThis.setTimeout(() => URL.revokeObjectURL(url), 1000);
    };

    const handleExport = async () => {
        if (isBusy) {
            return;
        }

        isBusy = true;

        try {
            const state = await providerStateStore.getState();

            const envelope = {
                type: envelopeType,
                version: state.version,
                exportedAt: new Date().toISOString(),

                state: {
                    version: state.version,
                    app: state.app,
                    providers: state.providers,
                },
            };

            triggerDownload(JSON.stringify(envelope, null, 2), buildFileName());
            toast.show(LangUtil.TOAST_SETTINGS_EXPORTED);
        } catch (error) {
            console.error('ImportExportPage failed to export settings', error);
            toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
        } finally {
            isBusy = false;
        }
    };

    const extractStatePayload = parsed => {
        if (!parsed || typeof parsed !== 'object') {
            return null;
        }

        if (parsed.state && typeof parsed.state === 'object') {
            return parsed.state;
        }

        if (parsed.app && typeof parsed.app === 'object' && parsed.providers && typeof parsed.providers === 'object') {
            return parsed;
        }
        return null;
    };

    const handleImportFile = async file => {
        if (isBusy || !file) {
            return;
        }

        if (isLocked()) {
            toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
            return;
        }

        if (file.size > maxImportBytes) {
            toast.show(LangUtil.TOAST_IMPORT_INVALID, true);
            return;
        }

        isBusy = true;

        try {
            const text = await file.text();
            let parsed;

            try {
                parsed = JSON.parse(text);
            } catch {
                toast.show(LangUtil.TOAST_IMPORT_INVALID, true);
                return;
            }

            const payload = extractStatePayload(parsed);

            if (!payload) {
                toast.show(LangUtil.TOAST_IMPORT_INVALID, true);
                return;
            }

            await providerStateStore.importState(payload);
            toast.show(LangUtil.TOAST_SETTINGS_IMPORTED);
            document.dispatchEvent(new CustomEvent('osprey:settings-changed'));
        } catch (error) {
            console.error('ImportExportPage failed to import settings', error);
            toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
        } finally {
            isBusy = false;
        }
    };

    const buildControls = (runtime = null) => {
        currentRuntime = runtime;

        const wrap = formHelpers.createElement('div', {
            className: 'import-export-actions',
        });

        const exportButton = formHelpers.createElement('button', {
            id: 'exportSettingsBtn',
            type: 'button',
            className: 'reset-btn import-export-btn',
            textContent: LangUtil.EXPORT_SETTINGS,
        });

        exportButton.addEventListener('click', handleExport);

        const importButton = formHelpers.createElement('button', {
            id: 'importSettingsBtn',
            type: 'button',
            className: 'reset-btn import-export-btn',
            textContent: LangUtil.IMPORT_SETTINGS,
            disabled: isLocked(),
        });

        const fileInput = formHelpers.createElement('input', {
            id: 'importSettingsInput',
            type: 'file',
            className: 'import-export-file',
            hidden: true,
        });

        fileInput.accept = 'application/json,.json';

        importButton.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', () => {
            const file = fileInput.files?.[0];
            fileInput.value = '';

            handleImportFile(file).then(() => {
                // ignored
            });
        });

        wrap.append(exportButton, importButton, fileInput);
        return wrap;
    };

    return Object.freeze({
        buildControls,
    });
})();
