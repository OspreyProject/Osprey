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

// Manages fetching, persisting, and querying local filtering lists
class LocalLists {

    /**
     * Returns the runtime state object for a given descriptor.
     *
     * @param {Object} descriptor A descriptor from LocalLists.descriptors.
     * @returns {{ domainSet: Set<string>|null, rawJson: string|null }}
     */
    static getState(descriptor) {
        return localListState.get(descriptor.storageKey);
    }

    /**
     * Fetches the raw JSON text for a local list descriptor.
     *
     * @param {Object} descriptor A descriptor from LocalLists.descriptors.
     * @returns {Promise<string>} Resolves with the raw JSON text.
     */
    static async fetchJson(descriptor) {
        const shortName = ProtectionResult.ShortName[descriptor.origin];
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort("Fetch timeout"), LocalLists.FETCH_TIMEOUT_MS);

        try {
            const response = await fetch(descriptor.url, {
                method: "GET",
                headers: {"Accept": "application/json, text/plain, */*"},
                signal: controller.signal,
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }

            const contentType = response.headers.get("Content-Type") ?? "";

            if (!contentType.includes("application/json") && !contentType.includes("text/")) {
                throw new Error(`Unexpected Content-Type: ${contentType}`);
            }
            return await response.text();
        } finally {
            clearTimeout(timeoutId);
            console.debug(`[${shortName}] Finished fetching list from ${descriptor.url}`);
        }
    }

    /**
     * Parses a raw JSON string into a Set of lower-cased, trimmed hostnames.
     * Non-string and empty entries are silently ignored.
     * Yields the thread before parsing so large lists do not block navigation events.
     *
     * @param {string} rawJson The raw JSON text from the list endpoint.
     * @returns {Promise<Set<string>>} Resolves with the parsed set of hostnames.
     */
    static async parseJson(rawJson) {
        await new Promise(resolve => setTimeout(resolve, 0));

        const parsed = JSON.parse(rawJson);

        if (!Array.isArray(parsed)) {
            throw new TypeError(`Expected a JSON array but got ${typeof parsed}`);
        }

        const set = new Set();

        for (const entry of parsed) {
            if (typeof entry === "string" && entry.length > 0) {
                set.add(entry.trim().toLowerCase());
            }
        }
        return set;
    }

    /**
     * Parses a plain-text string (one hostname per line) into a Set of lower-cased,
     * trimmed hostnames. Blank lines and lines beginning with '#' are silently ignored.
     * Yields the thread before parsing so large lists do not block navigation events.
     *
     * @param {string} rawText The raw plain-text content from the list endpoint.
     * @returns {Promise<Set<string>>} Resolves with the parsed set of hostnames.
     */
    static async parsePlainText(rawText) {
        if (typeof rawText !== "string") {
            throw new TypeError(`Expected a string but got ${typeof rawText}`);
        }

        await new Promise(resolve => setTimeout(resolve, 0));

        const set = new Set();

        for (const line of rawText.split("\n")) {
            const trimmed = line.trim();

            // Skip blank lines and comment lines
            if (trimmed.length === 0 || trimmed.startsWith("#")) {
                continue;
            }

            set.add(trimmed.toLowerCase());
        }

        return set;
    }

    /**
     * Applies a freshly fetched raw string to a descriptor's runtime state.
     * Compares against the currently loaded raw string and skips the rebuild if unchanged.
     * Always persists to local storage.
     *
     * @param {Object} descriptor A descriptor from LocalLists.descriptors.
     * @param {string} rawData The newly fetched raw string (JSON or plain-text).
     */
    static async applyJson(descriptor, rawData) {
        const shortName = ProtectionResult.ShortName[descriptor.origin];
        const state = LocalLists.getState(descriptor);

        if (rawData === state.rawJson) {
            console.debug(`[${shortName}] List is unchanged; skipping rebuild.`);
            return;
        }

        let newSet;

        try {
            if (descriptor.format === "text") {
                newSet = await LocalLists.parsePlainText(rawData);
            } else {
                newSet = await LocalLists.parseJson(rawData);
            }
        } catch (error) {
            console.warn(`[${shortName}] Failed to parse list; keeping current: ${error.message}`);
            return;
        }

        // Atomically swap in the new set
        state.domainSet = newSet;
        state.rawJson = rawData;

        StorageUtil.setToLocalStore(descriptor.storageKey, {json: rawData, ts: Date.now()}, () => {
            console.info(`[${shortName}] List updated with ${newSet.size.toLocaleString()} entries.`);
        });
    }

    /**
     * Fetches the latest list for a descriptor and applies it.
     * Errors are caught and logged without interrupting the update schedule.
     *
     * @param {Object} descriptor A descriptor from LocalLists.descriptors.
     */
    static async fetchAndUpdate(descriptor) {
        const shortName = ProtectionResult.ShortName[descriptor.origin];

        try {
            console.debug(`[${shortName}] Fetching list update from: ${descriptor.url}`);
            const rawJson = await LocalLists.fetchJson(descriptor);
            await LocalLists.applyJson(descriptor, rawJson);
        } catch (error) {
            console.warn(`[${shortName}] Failed to fetch list update: ${error.message}`);
        }
    }

    /**
     * Initializes a single local list descriptor.
     * Attempts to restore a previously persisted list from extension local storage
     * so lookups are available immediately on service-worker restart.
     * Always schedules a background fetch and starts the periodic update interval.
     *
     * @param {Object} descriptor A descriptor from LocalLists.descriptors.
     */
    static init(descriptor) {
        const shortName = ProtectionResult.ShortName[descriptor.origin];

        const startFetchAndSchedule = () => {
            LocalLists.fetchAndUpdate(descriptor);
            setInterval(() => LocalLists.fetchAndUpdate(descriptor), LocalLists.UPDATE_INTERVAL_MS);
        };

        StorageUtil.getFromLocalStore(descriptor.storageKey, async stored => {
            if (stored && typeof stored.json === "string" && stored.json.length > 0) {
                try {
                    const restoredSet = descriptor.format === "text" ?
                        await LocalLists.parsePlainText(stored.json) :
                        await LocalLists.parseJson(stored.json);

                    const state = LocalLists.getState(descriptor);
                    state.domainSet = restoredSet;
                    state.rawJson = stored.json;
                    console.info(`[${shortName}] Restored ${restoredSet.size.toLocaleString()} entries from local storage.`);
                } catch (error) {
                    console.warn(`[${shortName}] Stored list is corrupt; fetching a new one: ${error.message}`);
                }
            }

            startFetchAndSchedule();
        });
    }

    /**
     * Initializes all local list descriptors.
     * Called once from background.js after the extension starts up.
     */
    static initAll() {
        for (const descriptor of LocalLists.descriptors) {
            LocalLists.init(descriptor);
        }
    }
}

// How often to re-fetch each local list
LocalLists.UPDATE_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

// Fetch timeout for list requests, kept separate from per-URL request timeouts
LocalLists.FETCH_TIMEOUT_MS = 30000; // 30 seconds

// Descriptor array — add one object per list; no other code needs to change.
// Each descriptor contains all static config for one list:
//   url         — remote URL that returns the list data
//   format      — "json" for a JSON array of hostnames, "text" for one hostname per line
//   origin      — ProtectionResult.Origin value used for results and cache lookups
//   settingsKey — key in the settings object that enables/disables this list
//   resultType  — ProtectionResult.ResultType to report when a hostname matches
//   storageKey  — extension local storage key used for persisting data
LocalLists.descriptors = Object.freeze([
    {
        url: "https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.json",
        format: "json",
        origin: ProtectionResult.Origin.PHISH_DESTROY,
        settingsKey: "phishDestroyEnabled",
        resultType: ProtectionResult.ResultType.PHISHING,
        storageKey: "LocalList_PhishDestroy",
    },
    {
        url: "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt",
        format: "text",
        origin: ProtectionResult.Origin.PHISHING_DATABASE,
        settingsKey: "phishingDatabaseEnabled",
        resultType: ProtectionResult.ResultType.PHISHING,
        storageKey: "LocalList_PhishingDatabase",
    },
]);

// Mutable runtime state per list, keyed by storageKey.
// Each entry: { domainSet: Set<string> | null, rawJson: string | null }
//   domainSet — the loaded set of lower-cased hostnames; null until first load
//   rawJson   — canonical JSON string used for change-detection on updates
//
// Module-scoped rather than a class field for JSHint compatibility (E024).
// Accessed only through LocalLists.getState() — treated as private.
const localListState = new Map(
    LocalLists.descriptors.map(descriptor => [descriptor.storageKey, {domainSet: null, rawJson: null}])
);
