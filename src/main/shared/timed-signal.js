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

globalThis.OspreyTimedSignal = (() => {
    const create = (parentSignal, timeoutMs) => {
        const controller = new AbortController();
        let timerId = null;

        const abort = reason => {
            try {
                controller.abort(reason);
            } catch {
                controller.abort();
            }
        };

        if (parentSignal?.aborted) {
            abort(parentSignal.reason || 'parent-aborted');
        } else {
            parentSignal?.addEventListener('abort', () => abort(parentSignal.reason || 'parent-aborted'), {once: true});
        }

        timerId = setTimeout(() => abort('timeout'), timeoutMs);

        return {
            signal: controller.signal,

            cleanup() {
                timerId && clearTimeout(timerId);
                timerId = null;
            },
        };
    };

    // Public API
    return Object.freeze({
        create
    });
})();
